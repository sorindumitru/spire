package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/proto/spire/common"
)

func ProtoToSPIFFEIDTemplate(ctx context.Context, td spiffeid.TrustDomain, tmpl *types.SPIFFEIDTemplate) (*common.SPIFFEIDTemplate, error) {
	if tmpl == nil {
		return nil, errors.New("missing template")
	}

	parentID, err := TrustDomainMemberIDFromProto(ctx, td, tmpl.ParentId)
	if err != nil {
		return nil, fmt.Errorf("invalid parent ID: %w", err)
	}

	federatesWith := make([]string, 0, len(tmpl.FederatesWith))
	for _, trustDomainName := range tmpl.FederatesWith {
		td, err := spiffeid.TrustDomainFromString(trustDomainName)
		if err != nil {
			return nil, fmt.Errorf("invalid federated trust domain: %w", err)
		}
		federatesWith = append(federatesWith, td.IDString())
	}

	if len(tmpl.Selectors) == 0 {
		return nil, errors.New("selector list is empty")
	}
	selectors, err := SelectorsFromProto(tmpl.Selectors)
	if err != nil {
		return nil, err
	}

	return &common.SPIFFEIDTemplate{
		TemplateId:       tmpl.Id,
		ParentId:         parentID.String(),
		SpiffeIdTemplate: tmpl.SpiffeIdTemplate,
		FederatesWith:    federatesWith,
		Selectors:        selectors,
		RevisionNumber:   tmpl.RevisionNumber,
		X509SvidTtl:      tmpl.X509SvidTtl,
		JwtSvidTtl:       tmpl.JwtSvidTtl,
	}, nil
}

func SPIFFEIDTemplateToProto(t *common.SPIFFEIDTemplate) (*types.SPIFFEIDTemplate, error) {
	if t == nil {
		return nil, errors.New("missing template")
	}

	parentID, err := spiffeid.FromString(t.ParentId)
	if err != nil {
		return nil, fmt.Errorf("invalid parent ID: %w", err)
	}

	var federatesWith []string
	if len(t.FederatesWith) > 0 {
		federatesWith = make([]string, 0, len(t.FederatesWith))
		for _, trustDomainID := range t.FederatesWith {
			td, err := spiffeid.TrustDomainFromString(trustDomainID)
			if err != nil {
				return nil, fmt.Errorf("invalid federated trust domain: %w", err)
			}
			federatesWith = append(federatesWith, td.Name())
		}
	}

	return &types.SPIFFEIDTemplate{
		Id:               t.TemplateId,
		SpiffeIdTemplate: t.SpiffeIdTemplate,
		ParentId:         ProtoFromID(parentID),
		Selectors:        ProtoFromSelectors(t.Selectors),
		X509SvidTtl:      t.X509SvidTtl,
		JwtSvidTtl:       t.JwtSvidTtl,
		FederatesWith:    federatesWith,
		RevisionNumber:   t.RevisionNumber,
		CreatedAt:        t.CreatedAt,
	}, nil
}
