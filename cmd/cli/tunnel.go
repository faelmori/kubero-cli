package cli

import (
	"github.com/i582/cfmt/cmd/cfmt"
	"github.com/kubero-dev/kubero-cli/cmd/common"
	"github.com/kubero-dev/kubero-cli/internal/network"
	"github.com/kubero-dev/kubero-cli/internal/config"
	"github.com/spf13/cobra"
)

func TunnelCmds() []*cobra.Command {
	return []*cobra.Command{
		cmdTunnel(),
	}
}

func cmdTunnel() *cobra.Command {
	var tunnelHost string
	var tunnelPort int
	var tunnelSubdomain string
	var tunnelDuration string

	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: cfmt.Sprint("Create a tunnel to the cluster in NATed infrastructures {{[BETA]}}::cyan "),
		Long:  `Use the tunnel subcommand to create a tunnel to the cluster in NATed infrastructures.`,
		Annotations: common.GetDescriptions([]string{
			cfmt.Sprint("Create a tunnel to the cluster in NATed infrastructures {{[BETA]}}::cyan "),
			`Use the tunnel subcommand to create a tunnel to the cluster in NATed infrastructures.`,
		}, false),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := config.NewViperConfig("", "")
			if ensureOrCreateErr := cfg.GetInstanceManager().EnsureInstanceOrCreate(); ensureOrCreateErr != nil {
				cfmt.Errorln("Error ensuring instance or creating: ", ensureOrCreateErr)
				return
			}

			authConfig := cfg.GetProp("authentication").(*config.AuthConfig)
			switch authConfig.GetStrategy() {
			case "oauth2_jwt":
				if err := network.NewLogin(cfg).HandleOAuth2JWTLogin(cfg, authConfig.OAuth2JWT); err != nil {
					cfmt.Errorln("Error handling OAuth2 JWT login: ", err)
					return
				}
			case "user_rsa":
				if err := network.NewLogin(cfg).HandleUserRSALogin(cfg, authConfig.UserRSA); err != nil {
					cfmt.Errorln("Error handling User RSA login: ", err)
					return
				}
			case "user_rsa_password":
				if err := network.NewLogin(cfg).HandleUserRSAPasswordLogin(cfg, authConfig.UserRSAPassword); err != nil {
					cfmt.Errorln("Error handling User RSA Password login: ", err)
					return
				}
			default:
				cfmt.Errorln("Unsupported authentication strategy: ", authConfig.GetStrategy())
				return
			}

			tunnel := network.NewTunnel(tunnelPort, tunnelHost, tunnelSubdomain, tunnelDuration)
			tunnel.StartTunnel()
		},
	}

	cmd.Flags().StringVarP(&tunnelHost, "host", "H", "localhost", "Hostname")
	cmd.Flags().IntVarP(&tunnelPort, "port", "p", 80, "Port to use")
	cmd.Flags().StringVarP(&tunnelDuration, "timeout", "t", "1h", "Timeout for the tunnel")

	cmd.Flags().StringVarP(&tunnelSubdomain, "subdomain", "s", "", "Subdomain to use ('-' to generate a random one)")

	return cmd
}
