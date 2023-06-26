package manager

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"sync"

	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/zeebo/errs"
	"google.golang.org/protobuf/proto"
)

const (
	// journalCap is the maximum number of entries per type that we'll
	// hold onto.
	journalCap = 10

	// journalPEMType is the type in the PEM header
	journalPEMType = "SPIRE CA JOURNAL"
)

type JournalEntries = journal.Entries
type X509CAEntry = journal.X509CAEntry
type JWTKeyEntry = journal.JWTKeyEntry

// Journal stores X509 CAs and JWT keys on disk as they are rotated by the
// manager. The data format on disk is a PEM encoded protocol buffer.
type Journal struct {
	path string

	mu      sync.RWMutex
	entries *JournalEntries
}

func LoadJournal(path string) (*Journal, error) {
	j := &Journal{
		path:    path,
		entries: new(JournalEntries),
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return j, nil
		}
		return nil, errs.Wrap(err)
	}
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errs.New("invalid PEM block")
	}
	if pemBlock.Type != journalPEMType {
		return nil, errs.New("invalid PEM block type %q", pemBlock.Type)
	}

	if err := proto.Unmarshal(pemBlock.Bytes, j.entries); err != nil {
		return nil, errs.New("unable to unmarshal entries: %v", err)
	}

	return j, nil
}

func (j *Journal) Entries() *JournalEntries {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return proto.Clone(j.entries).(*JournalEntries)
}

func (j *Journal) save() error {
	return saveJournalEntries(j.path, j.entries)
}

func saveJournalEntries(path string, entries *JournalEntries) error {
	entriesBytes, err := proto.Marshal(entries)
	if err != nil {
		return errs.Wrap(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  journalPEMType,
		Bytes: entriesBytes,
	})

	if err := diskutil.AtomicWritePubliclyReadableFile(path, pemBytes); err != nil {
		return errs.Wrap(err)
	}

	return nil
}

func chainDER(chain []*x509.Certificate) [][]byte {
	var der [][]byte
	for _, cert := range chain {
		der = append(der, cert.Raw)
	}
	return der
}
