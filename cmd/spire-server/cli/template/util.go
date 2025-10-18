package template

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

func printTemplate(t *types.SPIFFEIDTemplate, printf func(string, ...any) error) {
	_ = printf("ID         		: %s\n", printableID(t.Id))
	_ = printf("SPIFFE ID Template 	: %s\n", t.SpiffeIdTemplate)
	_ = printf("Parent ID          	: %s\n", protoToIDString(t.ParentId))
	_ = printf("Revision           	: %d\n", t.RevisionNumber)

	if t.X509SvidTtl == 0 {
		_ = printf("X509-SVID TTL    	: default\n")
	} else {
		_ = printf("X509-SVID TTL    	: %d\n", t.X509SvidTtl)
	}

	if t.JwtSvidTtl == 0 {
		_ = printf("JWT-SVID TTL     	: default\n")
	} else {
		_ = printf("JWT-SVID TTL     	: %d\n", t.JwtSvidTtl)
	}

	for _, s := range t.Selectors {
		_ = printf("Selector         	: %s:%s\n", s.Type, s.Value)
	}
	for _, id := range t.FederatesWith {
		_ = printf("FederatesWith    	: %s\n", id)
	}

	_ = printf("\n")
}

// idStringToProto converts a SPIFFE ID from the given string to *types.SPIFFEID
func idStringToProto(id string) (*types.SPIFFEID, error) {
	idType, err := spiffeid.FromString(id)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{
		TrustDomain: idType.TrustDomain().Name(),
		Path:        idType.Path(),
	}, nil
}

func printableID(id string) string {
	if id == "" {
		return "(none)"
	}
	return id
}

// protoToIDString converts a SPIFFE ID from the given *types.SPIFFEID to string
func protoToIDString(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}

// StringsFlag defines a custom type for string lists. Doing
// this allows us to support repeatable string flags.
type StringsFlag []string

// String returns the string flag.
func (s *StringsFlag) String() string {
	return fmt.Sprint(*s)
}

// Set appends the string flag.
func (s *StringsFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
