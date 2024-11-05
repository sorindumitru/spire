package debug

import (
	"context"
	"flag"
	"net"
	"time"

	"github.com/mitchellh/cli"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	"github.com/spiffe/spire/cmd/spire-agent/cli/common"
	"github.com/spiffe/spire/cmd/spire-agent/cli/run"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/util"
)

const commandName = "debug"

func NewDebugCommand() cli.Command {
	return newDebugCommand(common_cli.DefaultEnv)
}

func newDebugCommand(env *common_cli.Env) *debugCommand {
	return &debugCommand{
		env: env,
	}
}

type debugCommand struct {
	env *common_cli.Env
}

// newClients is the default client maker
func newDebugClient(ctx context.Context, addr net.Addr) (debugv1.DebugClient, error) {
	target, err := util.GetTargetName(addr)
	if err != nil {
		return nil, err
	}
	conn, err := util.GRPCDialContext(ctx, target)
	if err != nil {
		return nil, err
	}
	return debugv1.NewDebugClient(conn), nil
}

// Help prints the agent cmd usage
func (c *debugCommand) Help() string {
	return run.Help(commandName, c.env.Stderr)
}

func (c *debugCommand) Synopsis() string {
	return "Prints debug information about spire-agent"
}

func (c *debugCommand) Run(args []string) int {
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)

	adminSocketPath := fs.String("adminSocketPath", common.DefaultAdminSocketPath, "Path to the spire-agent admin socket")
	if err := fs.Parse(args); err != nil {
		c.env.ErrPrintln(err)
		return 1
	}
	timeoutString := fs.String("timeout", "3s", "Overall timeout")

	timeout, err := time.ParseDuration(*timeoutString)
	if err != nil {
		c.env.ErrPrintln(err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	adminSocketAddr, err := util.GetUnixAddrWithAbsPath(*adminSocketPath)
	if err != nil {
		c.env.ErrPrintln(err)
		return 1
	}

	debugClient, err := newDebugClient(ctx, adminSocketAddr)
	if err != nil {
		c.env.ErrPrintln(err)
		return 1
	}

	debugInfo, err := debugClient.GetInfo(ctx, &debugv1.GetInfoRequest{})
	if err != nil {
		c.env.ErrPrintln(err)
		return 1
	}

	svidChain := debugInfo.GetSvidChain()
	if len(svidChain) == 0 {
		c.env.Println("Agent does not have a SVID")
	} else {
		c.env.Printf("Agent SPIFFE-ID: spiffe://%s%s\n", svidChain[0].GetId().TrustDomain, svidChain[0].GetId().Path)
	}

	c.env.Printf("Uptime: %ds\n", debugInfo.GetUptime())
	c.env.Printf("Last sync time: %s\n", time.Unix(debugInfo.GetLastSyncSuccess(), 0).Format(time.RFC3339Nano))
	c.env.Printf("Cached X509-SVID count: %d\n", debugInfo.GetCachedX509SvidsCount())
	c.env.Printf("Cached JWT-SVID count: %d\n", debugInfo.GetCachedJwtSvidsCount())
	c.env.Printf("Cached SVIDStore X509-SVID count: %d\n", debugInfo.GetCachedSvidstoreX509SvidsCount())

	return 0
}
