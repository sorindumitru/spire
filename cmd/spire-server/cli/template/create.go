package template

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	serverutil "github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
)

// NewCreateCommand creates a new "create" subcommand for "entry" command.
func NewCreateCommand() cli.Command {
	return newCreateCommand(commoncli.DefaultEnv)
}

func newCreateCommand(env *commoncli.Env) cli.Command {
	return serverutil.AdaptCommand(env, &createCommand{env: env})
}

type createCommand struct {
	// Path to an optional data file. If set, other
	// opts will be ignored.
	path string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// Registration entry ID
	templateID string

	// Workload parent spiffeID
	parentID string

	// Workload spiffeID
	spiffeIDTemplate string

	// TTL for x509 SVIDs issued to this workload
	x509SVIDTTL int

	// TTL for JWT SVIDs issued to this workload
	jwtSVIDTTL int

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	federatesWith StringsFlag

	// Entry hint, used to disambiguate entries with the same SPIFFE ID
	hint string

	printer cliprinter.Printer

	env *commoncli.Env
}

func (*createCommand) Name() string {
	return "entry create"
}

func (*createCommand) Synopsis() string {
	return "Creates registration entries"
}

func (c *createCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.templateID, "templateID", "", "A custom ID for this SPIFFE ID tempalte (optional). If not set, a new template ID will be generated")
	f.StringVar(&c.parentID, "parentID", "", "The SPIFFE ID of this record's parent")
	f.StringVar(&c.spiffeIDTemplate, "spiffeIDTemplate", "", "The SPIFFE ID template that this record represents")
	f.IntVar(&c.x509SVIDTTL, "x509SVIDTTL", 0, "The lifetime, in seconds, for x509-SVIDs issued based on this registration entry.")
	f.IntVar(&c.jwtSVIDTTL, "jwtSVIDTTL", 0, "The lifetime, in seconds, for JWT-SVIDs issued based on this registration entry.")
	f.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.federatesWith, "federatesWith", "SPIFFE ID of a trust domain to federate with. Can be used more than once")
	f.StringVar(&c.hint, "hint", "", "The entry hint, used to disambiguate entries with the same SPIFFE ID")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintCreate)
}

func (c *createCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient serverutil.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	templates, err := c.parseConfig()
	if err != nil {
		return err
	}

	resp, err := createTemplates(ctx, serverClient.NewEntryClient(), templates)
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

// validate performs basic validation, even on fields that we
// have defaults defined for.
func (c *createCommand) validate() (err error) {
	// If a path is set, we have all we need
	if c.path != "" {
		return nil
	}

	if len(c.selectors) < 1 && len(c.spiffeIDTemplate) == 0 {
		return errors.New("at least one selector is required")
	}

	if c.parentID == "" {
		return errors.New("a parent ID is required if the node flag is not set")
	}

	if c.spiffeIDTemplate == "" {
		return errors.New("a SPIFFE ID is required")
	}

	if c.x509SVIDTTL < 0 {
		return errors.New("a positive x509-SVID TTL is required")
	}

	if c.jwtSVIDTTL < 0 {
		return errors.New("a positive JWT-SVID TTL is required")
	}

	return nil
}

// parseConfig builds a registration entry from the given config
func (c *createCommand) parseConfig() ([]*types.SPIFFEIDTemplate, error) {
	parentID, err := idStringToProto(c.parentID)
	if err != nil {
		return nil, err
	}

	x509SvidTTL, err := util.CheckedCast[int32](c.x509SVIDTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid value for X509 SVID TTL: %w", err)
	}

	jwtSvidTTL, err := util.CheckedCast[int32](c.jwtSVIDTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid value for JWT SVID TTL: %w", err)
	}

	t := &types.SPIFFEIDTemplate{
		Id:               c.templateID,
		ParentId:         parentID,
		SpiffeIdTemplate: c.spiffeIDTemplate,
		X509SvidTtl:      x509SvidTTL,
		JwtSvidTtl:       jwtSvidTTL,
	}

	selectors := []*types.Selector{}
	for _, s := range c.selectors {
		cs, err := serverutil.ParseSelector(s)
		if err != nil {
			return nil, err
		}

		selectors = append(selectors, cs)
	}

	t.Selectors = selectors
	t.FederatesWith = c.federatesWith
	return []*types.SPIFFEIDTemplate{t}, nil
}

func createTemplates(ctx context.Context, c entryv1.EntryClient, templates []*types.SPIFFEIDTemplate) (resp *entryv1.BatchCreateSPIFFEIDTemplateResponse, err error) {
	resp, err = c.BatchCreateSPIFFEIDTemplate(ctx, &entryv1.BatchCreateSPIFFEIDTemplateRequest{Templates: templates})
	if err != nil {
		return
	}

	for i, r := range resp.Results {
		if r.Status.Code != int32(codes.OK) {
			// The Entry API does not include in the results the entries that
			// failed to be created, so we populate them from the request data.
			r.Template = templates[i]
		}
	}

	return
}

func prettyPrintCreate(env *commoncli.Env, results ...any) error {
	var succeeded, failed []*entryv1.BatchCreateSPIFFEIDTemplateResponse_Result
	createResp, ok := results[0].(*entryv1.BatchCreateSPIFFEIDTemplateResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}

	for _, r := range createResp.Results {
		switch r.Status.Code {
		case int32(codes.OK):
			succeeded = append(succeeded, r)
		default:
			failed = append(failed, r)
		}
	}

	for _, r := range succeeded {
		printTemplate(r.Template, env.Printf)
	}

	for _, r := range failed {
		env.ErrPrintf("Failed to create the following entry (code: %s, msg: %q):\n",
			util.MustCast[codes.Code](r.Status.Code),
			r.Status.Message)
		printTemplate(r.Template, env.ErrPrintf)
	}

	if len(failed) > 0 {
		return errors.New("failed to create one or more entries")
	}

	return nil
}
