package wit

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	serverutil "github.com/spiffe/spire/cmd/spire-server/util"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/cliprinter"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/util"
)

func NewMintCommand() cli.Command {
	return newMintCommand(commoncli.DefaultEnv)
}

func newMintCommand(env *commoncli.Env) cli.Command {
	return serverutil.AdaptCommand(env, &mintCommand{env: env})
}

type mintCommand struct {
	spiffeID string
	ttl      time.Duration
	write    string
	env      *commoncli.Env
	printer  cliprinter.Printer
}

func (c *mintCommand) Name() string {
	return "wit mint"
}

func (c *mintCommand) Synopsis() string {
	return "Mints a WIT-SVID"
}

func (c *mintCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID of the WIT-SVID")
	fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the WIT-SVID")
	fs.StringVar(&c.write, "write", "", "File to write token to instead of stdout")
	cliprinter.AppendFlagWithCustomPretty(&c.printer, fs, c.env, prettyPrintMint)
}

func (c *mintCommand) Run(ctx context.Context, env *commoncli.Env, serverClient serverutil.ServerClient) error {
	if c.spiffeID == "" {
		return errors.New("spiffeID must be specified")
	}
	spiffeID, err := spiffeid.FromString(c.spiffeID)
	if err != nil {
		return err
	}
	ttl, err := ttlToSeconds(c.ttl)
	if err != nil {
		return fmt.Errorf("invalid value for TTL: %w", err)
	}

	signer, err := keymanager.ECP256.GenerateSigner()
	if err != nil {
		return fmt.Errorf("could not generate public/private key pair: %w", err)
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("could not marshal public/private key pair: %w", err)
	}

	client := serverClient.NewSVIDClient()
	resp, err := client.MintWITSVID(ctx, &svidv1.MintWITSVIDRequest{
		Id: &types.SPIFFEID{
			TrustDomain: spiffeID.TrustDomain().Name(),
			Path:        spiffeID.Path(),
		},
		PublicKey: publicKeyDer,
		Ttl:       ttl,
	})
	if err != nil {
		return fmt.Errorf("unable to mint SVID: %w", err)
	}
	token := resp.Svid.Token
	if err := c.validateToken(token, env); err != nil {
		return err
	}

	// Print in stdout
	if c.write == "" {
		return c.printer.PrintProto(resp)
	}

	// TODO: Save in file, must also include private key somehow
	tokenPath := env.JoinPath(c.write)
	if err := diskutil.WritePrivateFile(tokenPath, []byte(token)); err != nil {
		return fmt.Errorf("unable to write token: %w", err)
	}
	return env.Printf("WIT-SVID written to %s\n", tokenPath)
}

func (c *mintCommand) validateToken(token string, env *commoncli.Env) error {
	if token == "" {
		return errors.New("server response missing token")
	}

	eol, err := getWITSVIDEndOfLife(token)
	if err != nil {
		env.ErrPrintf("Unable to determine WIT-SVID lifetime: %v\n", err)
		return nil
	}

	if time.Until(eol) < c.ttl {
		env.ErrPrintf("WIT-SVID lifetime was capped shorter than specified ttl; expires %q\n", eol.UTC().Format(time.RFC3339))
	}

	return nil
}

func getWITSVIDEndOfLife(token string) (time.Time, error) {
	t, err := jwt.ParseSigned(token, jwtsvid.AllowedSignatureAlgorithms)
	if err != nil {
		return time.Time{}, err
	}

	claims := new(jwt.Claims)
	if err := t.UnsafeClaimsWithoutVerification(claims); err != nil {
		return time.Time{}, err
	}

	if claims.Expiry == nil {
		return time.Time{}, errors.New("no expiry claim")
	}

	return claims.Expiry.Time(), nil
}

// ttlToSeconds returns the number of seconds in a duration, rounded up to
// the nearest second
func ttlToSeconds(ttl time.Duration) (int32, error) {
	return util.CheckedCast[int32]((ttl + time.Second - 1) / time.Second)
}

func prettyPrintMint(env *commoncli.Env, results ...any) error {
	if resp, ok := results[0].(*svidv1.MintWITSVIDResponse); ok {
		return env.Println(resp.Svid.Token)
	}
	return cliprinter.ErrInternalCustomPrettyFunc
}
