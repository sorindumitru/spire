//go:build windows

package cng

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/util"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	defaultKeyPrefix = "spire-agent-"
	pluginName       = "cng"
)

func BuiltIn() catalog.BuiltIn {
	return asBuiltIn(newKeyManager())
}

func newKeyManager() *KeyManager {
	return &KeyManager{entries: make(map[string]*keyEntry)}
}

func asBuiltIn(p *KeyManager) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configuration struct {
	KeyPrefix string `hcl:"key_prefix"`
}

type keyEntry struct {
	signer *cngKey
	pubKey *keymanagerv1.PublicKey // Id, Type, PkixData, Fingerprint
}

// KeyManager is the CNG key manager plugin for Windows.
type KeyManager struct {
	keymanagerv1.UnsafeKeyManagerServer
	configv1.UnimplementedConfigServer

	log hclog.Logger

	mu       sync.RWMutex
	config   *configuration
	provider uintptr // NCRYPT_PROV_HANDLE; 0 until configured
	entries  map[string]*keyEntry
}

func (m *KeyManager) SetLogger(log hclog.Logger) {
	m.log = log
}

func (m *KeyManager) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	var config configuration
	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.KeyPrefix == "" {
		config.KeyPrefix = defaultKeyPrefix
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Only open the provider once; reconfiguration only updates config fields.
	if m.provider == 0 {
		prov, err := ncryptOpenStorageProvider(msKeyStorageProvider)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to open CNG key storage provider: %v", err)
		}
		m.provider = prov

		entries, err := m.loadExistingKeys(prov, config.KeyPrefix)
		if err != nil {
			ncryptFreeObject(prov)
			m.provider = 0
			return nil, err
		}
		m.entries = entries
	}

	m.config = &config
	return &configv1.ConfigureResponse{}, nil
}

func (m *KeyManager) loadExistingKeys(provider uintptr, prefix string) (map[string]*keyEntry, error) {
	names, err := ncryptEnumKeys(provider, prefix)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to enumerate CNG keys: %v", err)
	}

	entries := make(map[string]*keyEntry)
	for _, name := range names {
		keyID := strings.TrimPrefix(name, prefix)
		e, err := buildEntryFromCNGKey(provider, name, keyID)
		if err != nil {
			if m.log != nil {
				m.log.Warn("Skipping CNG key that could not be loaded", "name", name, "error", err)
			}
			continue
		}
		entries[keyID] = e
	}
	return entries, nil
}

// GenerateKey implements the KeyManager gRPC method.
func (m *KeyManager) GenerateKey(_ context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.KeyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		return nil, status.Error(codes.InvalidArgument, "key type is required")
	}

	m.mu.RLock()
	config := m.config
	provider := m.provider
	m.mu.RUnlock()

	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}

	cngName := config.KeyPrefix + req.KeyId
	entry, err := createAndBuildEntry(provider, cngName, req.KeyId, req.KeyType)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	// If a key with this ID existed before, delete the old CNG key.
	old, hadOld := m.entries[req.KeyId]
	m.entries[req.KeyId] = entry

	// Build the current entry set for cleanup.
	allEntries := m.entriesSliceLocked()
	m.mu.Unlock()

	if hadOld {
		ncryptFreeObject(old.signer.handle)
	}

	// Clean up any orphaned keys from previous runs.
	m.cleanupOrphanedKeys(provider, config.KeyPrefix, allEntries)

	return &keymanagerv1.GenerateKeyResponse{
		PublicKey: clonePublicKey(entry.pubKey),
	}, nil
}

func (m *KeyManager) GetPublicKey(_ context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}

	m.mu.RLock()
	e := m.entries[req.KeyId]
	m.mu.RUnlock()

	resp := new(keymanagerv1.GetPublicKeyResponse)
	if e != nil {
		resp.PublicKey = clonePublicKey(e.pubKey)
	}
	return resp, nil
}

func (m *KeyManager) GetPublicKeys(_ context.Context, _ *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	m.mu.RLock()
	entries := m.entriesSliceLocked()
	m.mu.RUnlock()

	resp := new(keymanagerv1.GetPublicKeysResponse)
	for _, e := range entries {
		resp.PublicKeys = append(resp.PublicKeys, clonePublicKey(e.pubKey))
	}
	return resp, nil
}

func (m *KeyManager) SignData(_ context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	resp, err := m.signData(req)
	if err != nil {
		return nil, prefixStatus(err, "failed to sign data")
	}
	return resp, nil
}

func (m *KeyManager) signData(req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key id is required")
	}
	if req.SignerOpts == nil {
		return nil, status.Error(codes.InvalidArgument, "signer opts is required")
	}

	var signerOpts crypto.SignerOpts
	switch opts := req.SignerOpts.(type) {
	case *keymanagerv1.SignDataRequest_HashAlgorithm:
		if opts.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm is required")
		}
		signerOpts = util.MustCast[crypto.Hash](opts.HashAlgorithm)
	case *keymanagerv1.SignDataRequest_PssOptions:
		if opts.PssOptions == nil {
			return nil, status.Error(codes.InvalidArgument, "PSS options are nil")
		}
		if opts.PssOptions.HashAlgorithm == keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM {
			return nil, status.Error(codes.InvalidArgument, "hash algorithm in PSS options is required")
		}
		signerOpts = &rsa.PSSOptions{
			SaltLength: int(opts.PssOptions.SaltLength),
			Hash:       util.MustCast[crypto.Hash](opts.PssOptions.HashAlgorithm),
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported signer opts type %T", opts)
	}

	m.mu.RLock()
	e := m.entries[req.KeyId]
	m.mu.RUnlock()

	if e == nil {
		return nil, status.Errorf(codes.NotFound, "no such key %q", req.KeyId)
	}

	signature, err := e.signer.Sign(rand.Reader, req.Data, signerOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "keypair %q signing operation failed: %v", req.KeyId, err)
	}

	return &keymanagerv1.SignDataResponse{
		Signature:      signature,
		KeyFingerprint: e.pubKey.Fingerprint,
	}, nil
}

// createAndBuildEntry creates a new persisted CNG key named cngName and builds
// a keyEntry for it. Any existing key with the same name is deleted first;
// NCryptCreatePersistedKey returns NTE_EXISTS rather than overwriting.
func createAndBuildEntry(provider uintptr, cngName, keyID string, keyType keymanagerv1.KeyType) (*keyEntry, error) {
	algID, rsaBits, err := keyTypeToAlg(keyType)
	if err != nil {
		return nil, err
	}

	if existing, err := ncryptOpenKey(provider, cngName); err == nil {
		ncryptDeleteKey(existing)
	}

	handle, err := ncryptCreatePersistedKey(provider, algID, cngName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create CNG key: %v", err)
	}

	if rsaBits > 0 {
		if err := ncryptSetPropertyDWORD(handle, ncryptLengthProperty, rsaBits); err != nil {
			ncryptDeleteKey(handle)
			return nil, status.Errorf(codes.Internal, "set RSA key length: %v", err)
		}
	}

	if err := ncryptFinalizeKey(handle); err != nil {
		ncryptDeleteKey(handle)
		return nil, status.Errorf(codes.Internal, "finalize CNG key: %v", err)
	}

	pub, err := exportPublicKey(handle, keyType)
	if err != nil {
		ncryptDeleteKey(handle)
		return nil, status.Errorf(codes.Internal, "export public key: %v", err)
	}

	return buildEntry(&cngKey{handle: handle, pub: pub}, keyID, keyType, pub)
}

// buildEntryFromCNGKey opens an existing CNG key by name and builds a keyEntry.
func buildEntryFromCNGKey(provider uintptr, cngName, keyID string) (*keyEntry, error) {
	handle, err := ncryptOpenKey(provider, cngName)
	if err != nil {
		return nil, err
	}

	algName, err := ncryptGetPropertyString(handle, ncryptAlgorithmProperty)
	if err != nil {
		ncryptFreeObject(handle)
		return nil, fmt.Errorf("get algorithm: %w", err)
	}

	keyType, err := algToKeyType(handle, algName, keyID)
	if err != nil {
		ncryptFreeObject(handle)
		return nil, err
	}

	pub, err := exportPublicKey(handle, keyType)
	if err != nil {
		ncryptFreeObject(handle)
		return nil, fmt.Errorf("export public key: %w", err)
	}

	return buildEntry(&cngKey{handle: handle, pub: pub}, keyID, keyType, pub)
}

func buildEntry(key *cngKey, keyID string, keyType keymanagerv1.KeyType, pub crypto.PublicKey) (*keyEntry, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX public key: %w", err)
	}
	fp := sha256.Sum256(pkixData)
	return &keyEntry{
		signer: key,
		pubKey: &keymanagerv1.PublicKey{
			Id:          keyID,
			Type:        keyType,
			PkixData:    pkixData,
			Fingerprint: hex.EncodeToString(fp[:]),
		},
	}, nil
}

func exportPublicKey(handle uintptr, keyType keymanagerv1.KeyType) (crypto.PublicKey, error) {
	switch keyType {
	case keymanagerv1.KeyType_EC_P256, keymanagerv1.KeyType_EC_P384:
		return exportECPublicKey(handle)
	case keymanagerv1.KeyType_RSA_2048, keymanagerv1.KeyType_RSA_4096:
		return exportRSAPublicKey(handle)
	default:
		return nil, fmt.Errorf("unsupported key type %v", keyType)
	}
}

func exportECPublicKey(handle uintptr) (*ecdsa.PublicKey, error) {
	blob, err := ncryptExportKey(handle, bcryptECCPublicBlobType)
	if err != nil {
		return nil, err
	}
	magic, _, x, y, err := parseECCPublicBlob(blob)
	if err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch magic {
	case bcryptECDSAPublicP256Magic:
		curve = elliptic.P256()
	case bcryptECDSAPublicP384Magic:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unrecognized ECC blob magic 0x%08X", magic)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func exportRSAPublicKey(handle uintptr) (*rsa.PublicKey, error) {
	blob, err := ncryptExportKey(handle, bcryptRSAPublicBlobType)
	if err != nil {
		return nil, err
	}
	e, n, err := parseRSAPublicBlob(blob)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func keyTypeToAlg(keyType keymanagerv1.KeyType) (algID string, rsaBits uint32, err error) {
	switch keyType {
	case keymanagerv1.KeyType_EC_P256:
		return bcryptECDSAP256Algorithm, 0, nil
	case keymanagerv1.KeyType_EC_P384:
		return bcryptECDSAP384Algorithm, 0, nil
	case keymanagerv1.KeyType_RSA_2048:
		return bcryptRSAAlgorithm, 2048, nil
	case keymanagerv1.KeyType_RSA_4096:
		return bcryptRSAAlgorithm, 4096, nil
	default:
		return "", 0, status.Errorf(codes.InvalidArgument, "unsupported key type %v", keyType)
	}
}

func algToKeyType(handle uintptr, algName, keyID string) (keymanagerv1.KeyType, error) {
	switch algName {
	case bcryptECDSAP256Algorithm:
		return keymanagerv1.KeyType_EC_P256, nil
	case bcryptECDSAP384Algorithm:
		return keymanagerv1.KeyType_EC_P384, nil
	case bcryptRSAAlgorithm:
		bits, err := ncryptGetPropertyDWORD(handle, ncryptLengthProperty)
		if err != nil {
			return 0, fmt.Errorf("get RSA key length for %q: %w", keyID, err)
		}
		switch bits {
		case 2048:
			return keymanagerv1.KeyType_RSA_2048, nil
		case 4096:
			return keymanagerv1.KeyType_RSA_4096, nil
		default:
			return 0, fmt.Errorf("unsupported RSA key size %d for key %q", bits, keyID)
		}
	default:
		return 0, fmt.Errorf("unsupported algorithm %q for key %q", algName, keyID)
	}
}

func (m *KeyManager) cleanupOrphanedKeys(provider uintptr, prefix string, activeEntries []*keyEntry) {
	active := make(map[string]struct{}, len(activeEntries))
	for _, e := range activeEntries {
		active[prefix+e.pubKey.Id] = struct{}{}
	}

	names, err := ncryptEnumKeys(provider, prefix)
	if err != nil {
		if m.log != nil {
			m.log.Warn("Failed to enumerate CNG keys during cleanup", "error", err)
		}
		return
	}
	for _, name := range names {
		if _, ok := active[name]; ok {
			continue
		}
		handle, err := ncryptOpenKey(provider, name)
		if err != nil {
			if m.log != nil {
				m.log.Warn("Could not open CNG key for deletion", "name", name, "error", err)
			}
			continue
		}
		if err := ncryptDeleteKey(handle); err != nil {
			if m.log != nil {
				m.log.Warn("Could not delete orphaned CNG key", "name", name, "error", err)
			}
			ncryptFreeObject(handle)
		}
		// NCryptDeleteKey frees the handle on success.
	}
}

// entriesSliceLocked returns a sorted slice of entries. Must be called with m.mu held.
func (m *KeyManager) entriesSliceLocked() []*keyEntry {
	s := make([]*keyEntry, 0, len(m.entries))
	for _, e := range m.entries {
		s = append(s, e)
	}
	sort.Slice(s, func(i, j int) bool {
		return s[i].pubKey.Id < s[j].pubKey.Id
	})
	return s
}

// cngKey implements crypto.Signer backed by an NCRYPT_KEY_HANDLE.
type cngKey struct {
	handle uintptr
	pub    crypto.PublicKey
}

func (k *cngKey) Public() crypto.PublicKey {
	return k.pub
}

func (k *cngKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch k.pub.(type) {
	case *ecdsa.PublicKey:
		return k.signECDSA(digest)
	case *rsa.PublicKey:
		return k.signRSA(digest, opts)
	default:
		return nil, fmt.Errorf("unsupported key type %T", k.pub)
	}
}

func (k *cngKey) signECDSA(digest []byte) ([]byte, error) {
	// NCryptSignHash returns raw r||s; convert to DER ASN.1.
	raw, err := ncryptSignHash(k.handle, nil, digest, 0)
	if err != nil {
		return nil, err
	}
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("unexpected ECDSA signature length %d", len(raw))
	}
	half := len(raw) / 2
	return asn1.Marshal(ecdsaSig{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}

type ecdsaSig struct {
	R, S *big.Int
}

func (k *cngKey) signRSA(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		return k.signRSAPSS(digest, pss)
	}
	return k.signRSAPKCS1(digest, opts.HashFunc())
}

func (k *cngKey) signRSAPKCS1(digest []byte, hash crypto.Hash) ([]byte, error) {
	algName, err := hashAlgName(uint(hash))
	if err != nil {
		return nil, err
	}
	algPtr, err := windows.UTF16PtrFromString(algName)
	if err != nil {
		return nil, err
	}
	info := bcryptPKCS1PaddingInfo{pszAlgID: algPtr}
	return ncryptSignHash(k.handle, unsafe.Pointer(&info), digest, ncryptPadPKCS1Flag)
}

func (k *cngKey) signRSAPSS(digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	algName, err := hashAlgName(uint(opts.Hash))
	if err != nil {
		return nil, err
	}
	algPtr, err := windows.UTF16PtrFromString(algName)
	if err != nil {
		return nil, err
	}

	saltLen := opts.SaltLength
	switch saltLen {
	case rsa.PSSSaltLengthEqualsHash:
		saltLen = opts.Hash.Size()
	case rsa.PSSSaltLengthAuto:
		pub := k.pub.(*rsa.PublicKey)
		saltLen = pub.N.BitLen()/8 - opts.Hash.Size() - 2
	}

	info := bcryptPSSPaddingInfo{
		pszAlgID: algPtr,
		cbSalt:   uint32(saltLen),
	}
	return ncryptSignHash(k.handle, unsafe.Pointer(&info), digest, ncryptPadPSSFlag)
}

func clonePublicKey(pk *keymanagerv1.PublicKey) *keymanagerv1.PublicKey {
	if pk == nil {
		return nil
	}
	return proto.Clone(pk).(*keymanagerv1.PublicKey)
}

func prefixStatus(err error, prefix string) error {
	st := status.Convert(err)
	if st.Code() != codes.OK {
		return status.Error(st.Code(), prefix+": "+st.Message())
	}
	return err
}
