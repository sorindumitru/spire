package run

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/log"
)

const (
	defaultConfigPath = "conf/agent/agent.conf"

	defaultSocketPath = "./spire_api"

	// TODO: Make my defaults sane
	defaultDataDir   = "."
	defaultLogLevel  = "INFO"
	defaultPluginDir = "conf/agent/plugin"

	defaultUmask = 0077
)

// RunConfig represents the available configurables for file
// and CLI options
type runConfig struct {
	AgentConfig    agentConfig                                   `hcl:"agent"`
	PluginsConfigs map[string]map[string]catalog.HclPluginConfig `hcl:"plugins"`
}

type agentConfig struct {
	ServerAddress   string `hcl:"server_address"`
	ServerPort      int    `hcl:"server_port"`
	TrustDomain     string `hcl:"trust_domain"`
	TrustBundlePath string `hcl:"trust_bundle_path"`
	JoinToken       string `hcl:"join_token"`

	SocketPath string `hcl:"socket_path"`
	DataDir    string `hcl:"data_dir"`
	PluginDir  string `hcl:"plugin_dir"`
	LogFile    string `hcl:"log_file"`
	LogLevel   string `hcl:"log_level"`

	ConfigPath string `hcl:"config_path"`
	Umask      string `hcl:"umask"`
}

type RunCLI struct {
}

func (*RunCLI) Help() string {
	_, err := parseFlags([]string{"-h"})
	return err.Error()
}

func (*RunCLI) Run(args []string) int {
	cliConfig, err := parseFlags(args)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	fileConfig, err := parseFile(cliConfig.AgentConfig.ConfigPath)
	if err != nil {
		fmt.Println(err.Error())
		return 1
	}

	c := newDefaultConfig()
	err = mergeConfigs(c, fileConfig, cliConfig)
	if err != nil {
		fmt.Println(err.Error)
	}

	err = validateConfig(c)
	if err != nil {
		fmt.Println(err.Error())
	}
	ctx, cancel := context.WithCancel(context.Background())
	signalListener(ctx, cancel)

	agt := agent.New(ctx, c)

	err = agt.Run()
	if err != nil {
		c.Log.Error(err.Error())
		return 1
	}

	return 0
}

func (*RunCLI) Synopsis() string {
	return "Runs the agent"
}

func parseFile(filePath string) (*runConfig, error) {
	c := &runConfig{}

	// Return a friendly error if the file is missing
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		msg := "could not find config file %s: please use the -config flag"
		p, err := filepath.Abs(filePath)
		if err != nil {
			p = filePath
			msg = "could not determine CWD; config file not found at %s: use -config"
		}
		return nil, fmt.Errorf(msg, p)
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	hclTree, err := hcl.Parse(string(data))
	if err != nil {
		return nil, err
	}
	if err := hcl.DecodeObject(&c, hclTree); err != nil {
		return nil, err
	}

	return c, nil
}

func parseFlags(args []string) (*runConfig, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &runConfig{}

	flags.StringVar(&c.AgentConfig.ServerAddress, "serverAddress", "", "IP address or DNS name of the SPIRE server")
	flags.IntVar(&c.AgentConfig.ServerPort, "serverPort", 0, "Port number of the SPIRE server")
	flags.StringVar(&c.AgentConfig.TrustDomain, "trustDomain", "", "The trust domain that this agent belongs to")
	flags.StringVar(&c.AgentConfig.TrustBundlePath, "trustBundle", "", "Path to the SPIRE server CA bundle")
	flags.StringVar(&c.AgentConfig.JoinToken, "joinToken", "", "An optional token which has been generated by the SPIRE server")
	flags.StringVar(&c.AgentConfig.SocketPath, "socketPath", "", "Location to bind the workload API socket")
	flags.StringVar(&c.AgentConfig.DataDir, "dataDir", "", "A directory the agent can use for its runtime data")
	flags.StringVar(&c.AgentConfig.PluginDir, "pluginDir", "", "Plugin conf.d configuration directory")
	flags.StringVar(&c.AgentConfig.LogFile, "logFile", "", "File to write logs to")
	flags.StringVar(&c.AgentConfig.LogLevel, "logLevel", "", "DEBUG, INFO, WARN or ERROR")

	flags.StringVar(&c.AgentConfig.ConfigPath, "config", defaultConfigPath, "Path to a SPIRE config file")
	flags.StringVar(&c.AgentConfig.Umask, "umask", "", "Umask value to use for new files")

	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func mergeConfigs(c *agent.Config, fileConfig, cliConfig *runConfig) error {
	// CLI > File, merge fileConfig first
	err := mergeConfig(c, fileConfig)
	if err != nil {
		return err
	}

	return mergeConfig(c, cliConfig)
}

func mergeConfig(orig *agent.Config, cmd *runConfig) error {
	// Parse server address
	if cmd.AgentConfig.ServerAddress != "" {
		ips, err := net.LookupIP(cmd.AgentConfig.ServerAddress)
		if err != nil {
			return err
		}

		if len(ips) == 0 {
			return fmt.Errorf("Could not resolve ServerAddress %s", cmd.AgentConfig.ServerAddress)
		}
		serverAddress := ips[0]

		orig.ServerAddress.IP = serverAddress
	}

	if cmd.AgentConfig.ServerPort != 0 {
		orig.ServerAddress.Port = cmd.AgentConfig.ServerPort
	}

	if cmd.AgentConfig.TrustDomain != "" {
		trustDomain := url.URL{
			Scheme: "spiffe",
			Host:   cmd.AgentConfig.TrustDomain,
		}

		orig.TrustDomain = trustDomain
	}

	// Parse trust bundle
	if cmd.AgentConfig.TrustBundlePath != "" {
		bundle, err := parseTrustBundle(cmd.AgentConfig.TrustBundlePath)
		if err != nil {
			return fmt.Errorf("Error parsing trust bundle: %s", err)
		}

		orig.TrustBundle = bundle
	}

	if cmd.AgentConfig.JoinToken != "" {
		orig.JoinToken = cmd.AgentConfig.JoinToken
	}

	if cmd.AgentConfig.SocketPath != "" {
		orig.BindAddress.Name = cmd.AgentConfig.SocketPath
	}

	if cmd.AgentConfig.DataDir != "" {
		orig.DataDir = cmd.AgentConfig.DataDir
	}

	if cmd.AgentConfig.PluginDir != "" {
		orig.PluginDir = cmd.AgentConfig.PluginDir
	}

	// Handle log file and level
	if cmd.AgentConfig.LogFile != "" || cmd.AgentConfig.LogLevel != "" {
		logLevel := defaultLogLevel
		if cmd.AgentConfig.LogLevel != "" {
			logLevel = cmd.AgentConfig.LogLevel
		}

		logger, err := log.NewLogger(logLevel, cmd.AgentConfig.LogFile)
		if err != nil {
			return fmt.Errorf("Could not open log file %s: %s", cmd.AgentConfig.LogFile, err)
		}

		orig.Log = logger
	}

	if cmd.AgentConfig.Umask != "" {
		umask, err := strconv.ParseInt(cmd.AgentConfig.Umask, 0, 0)
		if err != nil {
			return fmt.Errorf("Could not parse umask %s: %s", cmd.AgentConfig.Umask, err)
		}
		orig.Umask = int(umask)
	}

	if cmd.PluginsConfigs != nil {
		orig.PluginsConfigs = cmd.PluginsConfigs
	}
	if orig.PluginsConfigs != nil {
		cmd.PluginsConfigs = orig.PluginsConfigs
	}

	return nil
}

func validateConfig(c *agent.Config) error {
	if c.ServerAddress.IP == nil || c.ServerAddress.Port == 0 {
		return errors.New("ServerAddress and ServerPort are required")
	}

	if c.TrustDomain.String() == "" {
		return errors.New("TrustDomain is required")
	}

	if c.TrustBundle == nil {
		return errors.New("TrustBundle is required")
	}

	return nil
}

func newDefaultConfig() *agent.Config {
	bindAddr := &net.UnixAddr{Name: defaultSocketPath, Net: "unix"}

	certDN := &pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"SPIRE"},
	}
	errCh := make(chan error)
	// log.NewLogger() cannot return error when using STDOUT
	logger, _ := log.NewLogger(defaultLogLevel, "")
	serverAddress := &net.TCPAddr{}

	return &agent.Config{
		BindAddress:   bindAddr,
		CertDN:        certDN,
		DataDir:       defaultDataDir,
		PluginDir:     defaultPluginDir,
		ErrorCh:       errCh,
		Log:           logger,
		ServerAddress: serverAddress,
		Umask:         defaultUmask,
	}
}

func parseTrustBundle(path string) (*x509.CertPool, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("No valid certificates found at %s", path)
	}
	return certPool, nil
}

func stringDefault(option string, defaultValue string) string {
	if option == "" {
		return defaultValue
	}

	return option
}

func signalListener(ctx context.Context, cancel context.CancelFunc) {

	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(signalCh)
		select {
		case <-ctx.Done():
		case <-signalCh:
			cancel()
		}
	}()
	return
}
