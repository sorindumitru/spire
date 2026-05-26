//go:build windows

package dpapi

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ncryptDLL = syscall.NewLazyDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	procNCryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	procNCryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncryptDLL.NewProc("NCryptGetProperty")
	procNCryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	procNCryptEnumKeys            = ncryptDLL.NewProc("NCryptEnumKeys")
	procNCryptDeleteKey           = ncryptDLL.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
	procNCryptFreeBuffer          = ncryptDLL.NewProc("NCryptFreeBuffer")
)

const (
	msKeyStorageProvider = "Microsoft Software Key Storage Provider"

	bcryptECDSAP256Algorithm = "ECDSA_P256"
	bcryptECDSAP384Algorithm = "ECDSA_P384"
	bcryptRSAAlgorithm       = "RSA"

	bcryptECCPublicBlobType = "ECCPUBLICBLOB"
	bcryptRSAPublicBlobType = "RSAPUBLICBLOB"

	// BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	bcryptECDSAPublicP256Magic uint32 = 0x31534345
	// BCRYPT_ECDSA_PUBLIC_P384_MAGIC
	bcryptECDSAPublicP384Magic uint32 = 0x33534345
	// BCRYPT_RSAPUBLIC_MAGIC
	bcryptRSAPublicMagic uint32 = 0x31415352

	ncryptAlgorithmProperty = "Algorithm Name"
	ncryptLengthProperty    = "Length"
	ncryptNameProperty      = "Name"

	// NCRYPT_PAD_PKCS1_FLAG
	ncryptPadPKCS1Flag uint32 = 0x00000002
	// NCRYPT_PAD_PSS_FLAG
	ncryptPadPSSFlag uint32 = 0x00000008

	nteNoKey uint32 = 0x8009000D
)

// bcryptPKCS1PaddingInfo maps to BCRYPT_PKCS1_PADDING_INFO
type bcryptPKCS1PaddingInfo struct {
	pszAlgID *uint16
}

// bcryptPSSPaddingInfo maps to BCRYPT_PSS_PADDING_INFO
type bcryptPSSPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint32
}

// ncryptKeyName maps to NCryptKeyName
type ncryptKeyName struct {
	pszName        *uint16
	pszAlgid       *uint16
	dwLegacyKeySpec uint32
	dwFlags        uint32
}

func ncryptOpenStorageProvider(providerName string) (uintptr, error) {
	name, err := windows.UTF16PtrFromString(providerName)
	if err != nil {
		return 0, err
	}
	var handle uintptr
	ret, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(name)),
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("NCryptOpenStorageProvider: 0x%08X", ret)
	}
	return handle, nil
}

func ncryptCreatePersistedKey(provider uintptr, algID, keyName string) (uintptr, error) {
	alg, err := windows.UTF16PtrFromString(algID)
	if err != nil {
		return 0, err
	}
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var handle uintptr
	ret, _, _ := procNCryptCreatePersistedKey.Call(
		provider,
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(alg)),
		uintptr(unsafe.Pointer(name)),
		0, // dwLegacyKeySpec
		0, // dwFlags (no NCRYPT_MACHINE_KEY_FLAG = user-level)
	)
	if ret != 0 {
		return 0, fmt.Errorf("NCryptCreatePersistedKey: 0x%08X", ret)
	}
	return handle, nil
}

func ncryptOpenKey(provider uintptr, keyName string) (uintptr, error) {
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var handle uintptr
	ret, _, _ := procNCryptOpenKey.Call(
		provider,
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(name)),
		0, // dwLegacyKeySpec
		0, // dwFlags
	)
	if ret != 0 {
		return 0, fmt.Errorf("NCryptOpenKey(%q): 0x%08X", keyName, ret)
	}
	return handle, nil
}

func ncryptFinalizeKey(key uintptr) error {
	ret, _, _ := procNCryptFinalizeKey.Call(key, 0)
	if ret != 0 {
		return fmt.Errorf("NCryptFinalizeKey: 0x%08X", ret)
	}
	return nil
}

func ncryptSetPropertyDWORD(key uintptr, property string, value uint32) error {
	prop, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return err
	}
	ret, _, _ := procNCryptSetProperty.Call(
		key,
		uintptr(unsafe.Pointer(prop)),
		uintptr(unsafe.Pointer(&value)),
		unsafe.Sizeof(value),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("NCryptSetProperty(%q): 0x%08X", property, ret)
	}
	return nil
}

func ncryptGetPropertyString(key uintptr, property string) (string, error) {
	prop, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return "", err
	}

	// First call to get required buffer size
	var needed uint32
	ret, _, _ := procNCryptGetProperty.Call(
		key,
		uintptr(unsafe.Pointer(prop)),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if ret != 0 {
		return "", fmt.Errorf("NCryptGetProperty(%q) size: 0x%08X", property, ret)
	}

	buf := make([]uint16, needed/2)
	ret, _, _ = procNCryptGetProperty.Call(
		key,
		uintptr(unsafe.Pointer(prop)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if ret != 0 {
		return "", fmt.Errorf("NCryptGetProperty(%q): 0x%08X", property, ret)
	}
	return windows.UTF16ToString(buf), nil
}

func ncryptGetPropertyDWORD(key uintptr, property string) (uint32, error) {
	prop, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return 0, err
	}
	var value uint32
	var needed uint32
	ret, _, _ := procNCryptGetProperty.Call(
		key,
		uintptr(unsafe.Pointer(prop)),
		uintptr(unsafe.Pointer(&value)),
		unsafe.Sizeof(value),
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if ret != 0 {
		return 0, fmt.Errorf("NCryptGetProperty(%q): 0x%08X", property, ret)
	}
	return value, nil
}

func ncryptExportKey(key uintptr, blobType string) ([]byte, error) {
	blobTyp, err := windows.UTF16PtrFromString(blobType)
	if err != nil {
		return nil, err
	}

	var needed uint32
	ret, _, _ := procNCryptExportKey.Call(
		key,
		0, // hExportKey
		uintptr(unsafe.Pointer(blobTyp)),
		0, // pParameterList
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptExportKey size: 0x%08X", ret)
	}

	buf := make([]byte, needed)
	ret, _, _ = procNCryptExportKey.Call(
		key,
		0,
		uintptr(unsafe.Pointer(blobTyp)),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptExportKey: 0x%08X", ret)
	}
	return buf[:needed], nil
}

func ncryptSignHash(key uintptr, paddingInfo unsafe.Pointer, hash []byte, flags uint32) ([]byte, error) {
	var needed uint32
	ret, _, _ := procNCryptSignHash.Call(
		key,
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&hash[0])),
		uintptr(len(hash)),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
		uintptr(flags),
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash size: 0x%08X", ret)
	}

	sig := make([]byte, needed)
	ret, _, _ = procNCryptSignHash.Call(
		key,
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&hash[0])),
		uintptr(len(hash)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
		uintptr(flags),
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptSignHash: 0x%08X", ret)
	}
	return sig[:needed], nil
}

// ncryptEnumKeys returns all key names in the store that start with prefix.
// pszScope must be NULL (the only supported value per the NCryptEnumKeys docs;
// non-NULL returns NTE_NOT_SUPPORTED), so prefix filtering is done in Go.
func ncryptEnumKeys(provider uintptr, prefix string) ([]string, error) {
	var names []string
	var enumState uintptr

	for {
		var keyName uintptr // pointer to NCryptKeyName
		ret, _, _ := procNCryptEnumKeys.Call(
			provider,
			0, // pszScope must be NULL
			uintptr(unsafe.Pointer(&keyName)),
			uintptr(unsafe.Pointer(&enumState)),
			0,
		)
		if ret == uintptr(0x8009002A) { // NTE_NO_MORE_ITEMS
			break
		}
		if ret != 0 {
			return nil, fmt.Errorf("NCryptEnumKeys: 0x%08X", ret)
		}

		entry := (*ncryptKeyName)(unsafe.Pointer(keyName))
		name := windows.UTF16PtrToString(entry.pszName)
		procNCryptFreeBuffer.Call(keyName)

		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}

	if enumState != 0 {
		procNCryptFreeBuffer.Call(enumState)
	}

	return names, nil
}

func ncryptDeleteKey(key uintptr) error {
	ret, _, _ := procNCryptDeleteKey.Call(key, 0)
	if ret != 0 {
		return fmt.Errorf("NCryptDeleteKey: 0x%08X", ret)
	}
	return nil
}

func ncryptFreeObject(handle uintptr) {
	procNCryptFreeObject.Call(handle)
}

// parseECCPublicBlob parses a BCRYPT_ECCPUBLIC_BLOB and returns the curve name
// and the uncompressed X and Y coordinates.
func parseECCPublicBlob(blob []byte) (magic uint32, keyBytes int, x, y []byte, err error) {
	if len(blob) < 8 {
		return 0, 0, nil, nil, fmt.Errorf("ECC public blob too short")
	}
	magic = binary.LittleEndian.Uint32(blob[0:4])
	cbKey := int(binary.LittleEndian.Uint32(blob[4:8]))
	if len(blob) < 8+2*cbKey {
		return 0, 0, nil, nil, fmt.Errorf("ECC public blob truncated")
	}
	x = blob[8 : 8+cbKey]
	y = blob[8+cbKey : 8+2*cbKey]
	return magic, cbKey, x, y, nil
}

// parseRSAPublicBlob parses a BCRYPT_RSAPUBLIC_BLOB and returns e and n.
func parseRSAPublicBlob(blob []byte) (e *big.Int, n *big.Int, err error) {
	if len(blob) < 20 {
		return nil, nil, fmt.Errorf("RSA public blob too short")
	}
	// magic := binary.LittleEndian.Uint32(blob[0:4])
	// bitLen := binary.LittleEndian.Uint32(blob[4:8])
	cbPublicExp := int(binary.LittleEndian.Uint32(blob[8:12]))
	cbModulus := int(binary.LittleEndian.Uint32(blob[12:16]))
	// cbPrime1 := int(binary.LittleEndian.Uint32(blob[16:20]))
	off := 20
	if len(blob) < off+cbPublicExp+cbModulus {
		return nil, nil, fmt.Errorf("RSA public blob truncated")
	}
	e = new(big.Int).SetBytes(blob[off : off+cbPublicExp])
	n = new(big.Int).SetBytes(blob[off+cbPublicExp : off+cbPublicExp+cbModulus])
	return e, n, nil
}

// hashAlgName returns the Windows hash algorithm name for use in padding info structs.
func hashAlgName(hashID uint) (string, error) {
	switch hashID {
	case 4: // crypto.SHA1
		return "SHA1", nil
	case 5: // crypto.SHA256
		return "SHA256", nil
	case 6: // crypto.SHA384
		return "SHA384", nil
	case 7: // crypto.SHA512
		return "SHA512", nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm %d", hashID)
	}
}
