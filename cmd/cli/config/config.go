package config

import (
	"fmt"
	"github.com/kubero-dev/kubero-cli/cmd/common"
	"github.com/kubero-dev/kubero-cli/internal/config"
	"github.com/spf13/cobra"
	"path/filepath"
)

func ConfigCmds() []*cobra.Command {
	cfgRootCmd := cmdConfigCli()
	cfgRootCmd.AddCommand(cmdConfigSet())
	cfgRootCmd.AddCommand(cmdConfigGet())
	cfgRootCmd.AddCommand(ConfigAddonsCmds()...)
	cfgRootCmd.AddCommand(ConfigBuildpacksCmds()...)
	cfgRootCmd.AddCommand(ConfigPodsizesCmds()...)
	return []*cobra.Command{
		cfgRootCmd,
	}
}

func cmdConfigCli() *cobra.Command {
	var path string

	cfgCmd := &cobra.Command{
		Use:   "config",
		Short: "Show your configuration",
		Long: `Show your configuration. This command will show your current configuration.
You can use the 'config set' command to set a new configuration.`,
		Annotations: common.GetDescriptions([]string{
			"Show your configuration",
			`Show your configuration. This command will show your current configuration.
You can use the 'config set' command to set a new configuration.`,
		}, false),
		Run: func(cmd *cobra.Command, args []string) {
			pt := filepath.Dir(path)
			nm := filepath.Base(path)

			cfgManager := config.NewViperConfig(pt, nm)
			cfgMap := cfgManager.GetConfig()

			fmt.Println(fmt.Sprintf("Configuration file: %s", path))
			fmt.Println("Configuration:")
			fmt.Println(cfgMap)
		},
	}

	cfgCmd.Flags().StringVarP(&path, "path", "p", "", "Path to the configuration file")

	return cfgCmd
}

func cmdConfigSet() *cobra.Command {
	var path string

	cfgCmd := &cobra.Command{
		Use:   "set",
		Short: "Set a new configuration",
		Long: `Set a new configuration. This command will set a new configuration.
You can use the 'config' command to show your current configuration.`,
		Annotations: common.GetDescriptions([]string{
			"Set a new configuration",
			`Set a new configuration. This command will set a new configuration.
You can use the 'config' command to show your current configuration.`,
		}, false),
		RunE: func(cmd *cobra.Command, args []string) error {
			pt := filepath.Dir(path)
			nm := filepath.Base(path)
			cfgManager := config.NewViperConfig(pt, nm)

			if ptErr := cfgManager.SetPath(pt); ptErr != nil {
				return ptErr
			}
			if nmErr := cfgManager.SetName(nm); nmErr != nil {
				return nmErr
			}

			return nil
		},
	}

	cfgCmd.Flags().StringVarP(&path, "path", "p", "", "Path to the configuration file")

	return cfgCmd
}

func cmdConfigGet() *cobra.Command {
	var path string

	cfgCmd := &cobra.Command{
		Use:   "get",
		Short: "Get a configuration",
		Long: `Get a configuration. This command will get a configuration.
You can use the 'config' command to show your current configuration.`,
		Annotations: common.GetDescriptions([]string{
			"Get a configuration",
			`Get a configuration. This command will get a configuration.
You can use the 'config' command to show your current configuration.`,
		}, false),
		Run: func(cmd *cobra.Command, args []string) {
			pt := filepath.Dir(path)
			nm := filepath.Base(path)

			cfgManager := config.NewViperConfig(pt, nm)
			cfgMap := cfgManager.GetConfig()

			fmt.Println(fmt.Sprintf("Configuration file: %s", path))
			fmt.Println("Configuration:")

			fmt.Println(cfgMap)
		},
	}

	cfgCmd.Flags().StringVarP(&path, "path", "p", "", "Path to the configuration file")

	return cfgCmd
}

// Add a new section for authentication strategies in the configuration file
type AuthConfig struct {
	Strategy       string `mapstructure:"strategy"`
	OAuth2JWT      OAuth2JWTConfig `mapstructure:"oauth2_jwt"`
	UserRSA        UserRSAConfig `mapstructure:"user_rsa"`
	UserRSAPassword UserRSAPasswordConfig `mapstructure:"user_rsa_password"`
}

type OAuth2JWTConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	TokenEndpoint string `mapstructure:"token_endpoint"`
}

type UserRSAConfig struct {
	User             string `mapstructure:"user"`
	RSACertificatePath string `mapstructure:"rsa_certificate_path"`
}

type UserRSAPasswordConfig struct {
	User             string `mapstructure:"user"`
	RSACertificatePath string `mapstructure:"rsa_certificate_path"`
	Password         string `mapstructure:"password"`
}

// Implement methods to set and get the authentication strategy in the configuration file
func (cfg *AuthConfig) SetStrategy(strategy string) {
	cfg.Strategy = strategy
}

func (cfg *AuthConfig) GetStrategy() string {
	return cfg.Strategy
}

// Update the `cmdConfigSet` function to allow setting the authentication strategy
func cmdConfigSetAuth() *cobra.Command {
	var path string
	var strategy string

	cfgCmd := &cobra.Command{
		Use:   "set-auth",
		Short: "Set the authentication strategy",
		Long: `Set the authentication strategy. This command will set the authentication strategy.
You can use the 'config' command to show your current configuration.`,
		Annotations: common.GetDescriptions([]string{
			"Set the authentication strategy",
			`Set the authentication strategy. This command will set the authentication strategy.
You can use the 'config' command to show your current configuration.`,
		}, false),
		RunE: func(cmd *cobra.Command, args []string) error {
			pt := filepath.Dir(path)
			nm := filepath.Base(path)
			cfgManager := config.NewViperConfig(pt, nm)

			if ptErr := cfgManager.SetPath(pt); ptErr != nil {
				return ptErr
			}
			if nmErr := cfgManager.SetName(nm); nmErr != nil {
				return nmErr
			}

			authConfig := &AuthConfig{}
			authConfig.SetStrategy(strategy)
			cfgManager.SetProp("authentication", authConfig)

			return nil
		},
	}

	cfgCmd.Flags().StringVarP(&path, "path", "p", "", "Path to the configuration file")
	cfgCmd.Flags().StringVarP(&strategy, "strategy", "s", "", "Authentication strategy (oauth2_jwt, user_rsa, user_rsa_password)")

	return cfgCmd
}
