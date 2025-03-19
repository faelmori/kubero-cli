package cli

import (
	"fmt"
	"github.com/kubero-dev/kubero-cli/cmd/common"
	c "github.com/kubero-dev/kubero-cli/internal/config"
	"github.com/kubero-dev/kubero-cli/internal/network"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"io/ioutil"
	"os"
	"path/filepath"
)

func LoginCmds() []*cobra.Command {
	return []*cobra.Command{
		cmdLogin(),
	}
}

func cmdLogin() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Login to your Kubero instance",
		Long:  `Use the login subcommand to login to your Kubero instance.`,
		Annotations: common.GetDescriptions([]string{
			"Login to your Kubero instance",
			`Use the login subcommand to login to your Kubero instance.`,
		}, false),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := c.NewViperConfig("", "")
			if ensureOrCreateErr := cfg.GetInstanceManager().EnsureInstanceOrCreate(); ensureOrCreateErr != nil {
				return ensureOrCreateErr
			}

			authConfig := cfg.GetProp("authentication").(*c.AuthConfig)
			switch authConfig.GetStrategy() {
			case "oauth2_jwt":
				return handleOAuth2JWTLogin(cfg, authConfig.OAuth2JWT)
			case "user_rsa":
				return handleUserRSALogin(cfg, authConfig.UserRSA)
			case "user_rsa_password":
				return handleUserRSAPasswordLogin(cfg, authConfig.UserRSAPassword)
			default:
				return fmt.Errorf("unsupported authentication strategy: %s", authConfig.GetStrategy())
			}
		},
	}
}

func handleOAuth2JWTLogin(cfg c.IConfigManager, oauth2Config c.OAuth2JWTConfig) error {
	oauth2Endpoint := oauth2.Endpoint{
		AuthURL:  oauth2Config.TokenEndpoint,
		TokenURL: oauth2Config.TokenEndpoint,
	}

	oauth2Config := &oauth2.Config{
		ClientID:     oauth2Config.ClientID,
		ClientSecret: oauth2Config.ClientSecret,
		Endpoint:     oauth2Endpoint,
	}

	token, err := oauth2Config.PasswordCredentialsToken(oauth2.NoContext, "", "")
	if err != nil {
		return fmt.Errorf("failed to obtain OAuth2 token: %v", err)
	}

	cfg.GetCredentialsManager().SetCredentials(cfg.GetCredentialsManager().GetCredentials())
	return nil
}

func handleUserRSALogin(cfg c.IConfigManager, userRSAConfig c.UserRSAConfig) error {
	rsaCertPath := userRSAConfig.RSACertificatePath
	if _, err := os.Stat(rsaCertPath); os.IsNotExist(err) {
		return fmt.Errorf("RSA certificate file not found: %s", rsaCertPath)
	}

	rsaCert, err := ioutil.ReadFile(rsaCertPath)
	if err != nil {
		return fmt.Errorf("failed to read RSA certificate file: %v", err)
	}

	// Implement the logic to use the RSA certificate for authentication
	// ...

	cfg.GetCredentialsManager().SetCredentials(cfg.GetCredentialsManager().GetCredentials())
	return nil
}

func handleUserRSAPasswordLogin(cfg c.IConfigManager, userRSAPasswordConfig c.UserRSAPasswordConfig) error {
	rsaCertPath := userRSAPasswordConfig.RSACertificatePath
	if _, err := os.Stat(rsaCertPath); os.IsNotExist(err) {
		return fmt.Errorf("RSA certificate file not found: %s", rsaCertPath)
	}

	rsaCert, err := ioutil.ReadFile(rsaCertPath)
	if err != nil {
		return fmt.Errorf("failed to read RSA certificate file: %v", err)
	}

	password := userRSAPasswordConfig.Password

	// Implement the logic to use the RSA certificate and password for authentication
	// ...

	cfg.GetCredentialsManager().SetCredentials(cfg.GetCredentialsManager().GetCredentials())
	return nil
}
