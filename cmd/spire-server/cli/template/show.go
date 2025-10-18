package template

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/mitchellh/cli"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
)

const listEntriesRequestPageSize = 500

// NewShowCommand creates a new "show" subcommand for "entry" command.
func NewShowCommand() cli.Command {
	return newShowCommand(commoncli.DefaultEnv)
}

func newShowCommand(env *commoncli.Env) cli.Command {
	return util.AdaptCommand(env, &showCommand{env: env})
}

type showCommand struct {
	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// ID of the entry to be shown
	templateID string

	// Workload parent spiffeID
	parentID string

	// Entry hint
	hint string

	// List of SPIFFE IDs of trust domains the registration entry is federated with
	federatesWith StringsFlag

	// whether the entry is for a downstream SPIRE server
	downstream bool

	// Match used when filtering by federates with
	matchFederatesWithOn string

	// Match used when filtering by selectors
	matchSelectorsOn string

	printer cliprinter.Printer

	env *commoncli.Env
}

func (c *showCommand) Name() string {
	return "entry show"
}

func (*showCommand) Synopsis() string {
	return "Displays configured registration entries"
}

func (c *showCommand) AppendFlags(f *flag.FlagSet) {
	f.StringVar(&c.templateID, "templateID", "", "The ID of the records to show")
	f.StringVar(&c.parentID, "parentID", "", "The Parent ID of the records to show")
	f.BoolVar(&c.downstream, "downstream", false, "A boolean value that, when set, indicates that the entry describes a downstream SPIRE server")
	f.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
	f.Var(&c.federatesWith, "federatesWith", "SPIFFE ID of a trust domain an entry is federate with. Can be used more than once")
	f.StringVar(&c.matchFederatesWithOn, "matchFederatesWithOn", "superset", "The match mode used when filtering by federates with. Options: exact, any, superset and subset")
	f.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
	f.StringVar(&c.hint, "hint", "", "The Hint of the records to show (optional)")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, f, c.env, prettyPrintShow)
}

// Run executes all logic associated with a single invocation of the
// `spire-server entry show` CLI command
func (c *showCommand) Run(ctx context.Context, _ *commoncli.Env, serverClient util.ServerClient) error {
	if err := c.validate(); err != nil {
		return err
	}

	resp, err := c.fetchEntries(ctx, serverClient.NewEntryClient())
	if err != nil {
		return err
	}

	return c.printer.PrintProto(resp)
}

// validate ensures that the values in showCommand are valid
func (c *showCommand) validate() error {
	// If entryID is given, it should be the only constraint
	if c.templateID != "" {
		if c.parentID != "" || len(c.selectors) > 0 {
			return errors.New("the -templateID flag can't be combined with others")
		}
	}

	return nil
}

func (c *showCommand) fetchEntries(ctx context.Context, client entryv1.EntryClient) (*entryv1.ListSPIFFEIDTemplatesResponse, error) {
	listResp := &entryv1.ListSPIFFEIDTemplatesResponse{}

	pageToken := ""

	for {
		resp, err := client.ListSPIFFEIDTemplates(ctx, &entryv1.ListSPIFFEIDTemplatesRequest{
			PageSize:  listEntriesRequestPageSize,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, fmt.Errorf("error fetching entries: %w", err)
		}
		listResp.Templates = append(listResp.Templates, resp.Templates...)
		if pageToken = resp.NextPageToken; pageToken == "" {
			break
		}
	}

	return listResp, nil
}

func printTemplates(templates []*types.SPIFFEIDTemplate, env *commoncli.Env) {
	msg := fmt.Sprintf("Found %v ", len(templates))
	msg = util.Pluralizer(msg, "entry", "templates", len(templates))

	env.Println(msg)
	for _, t := range templates {
		printTemplate(t, env.Printf)
	}
}

func parseToSelectorMatch(match string) (types.SelectorMatch_MatchBehavior, error) {
	switch match {
	case "exact":
		return types.SelectorMatch_MATCH_EXACT, nil
	case "any":
		return types.SelectorMatch_MATCH_ANY, nil
	case "superset":
		return types.SelectorMatch_MATCH_SUPERSET, nil
	case "subset":
		return types.SelectorMatch_MATCH_SUBSET, nil
	default:
		return types.SelectorMatch_MATCH_SUPERSET, fmt.Errorf("match behavior %q unknown", match)
	}
}

func parseToFederatesWithMatch(match string) (types.FederatesWithMatch_MatchBehavior, error) {
	switch match {
	case "exact":
		return types.FederatesWithMatch_MATCH_EXACT, nil
	case "any":
		return types.FederatesWithMatch_MATCH_ANY, nil
	case "superset":
		return types.FederatesWithMatch_MATCH_SUPERSET, nil
	case "subset":
		return types.FederatesWithMatch_MATCH_SUBSET, nil
	default:
		return types.FederatesWithMatch_MATCH_SUPERSET, fmt.Errorf("match behavior %q unknown", match)
	}
}

func prettyPrintShow(env *commoncli.Env, results ...any) error {
	listResp, ok := results[0].(*entryv1.ListSPIFFEIDTemplatesResponse)
	if !ok {
		return cliprinter.ErrInternalCustomPrettyFunc
	}
	printTemplates(listResp.Templates, env)
	return nil
}
