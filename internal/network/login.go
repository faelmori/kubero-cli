package network

import (
	"fmt"
	"io/ioutil"
	"os"

	c "github.com/kubero-dev/kubero-cli/internal/config"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type Login struct {
	credentialsCfg  *viper.Viper
	instanceManager *c.InstanceManager
}

func NewLogin(cfg c.IConfigManager) *Login {
	if cfg == nil {
		cfg = c.NewViperConfig("", "")
	}
	if loadCredErr := cfg.GetCredentialsManager().LoadCredentials(); loadCredErr != nil {
		fmt.Println("Error loading credentials: ", loadCredErr)
		return nil
	}
	instanceManager := c.NewInstanceManager(cfg.GetCredentialsManager().GetCredentials())
	credentialsCfg := cfg.GetProp("credentials")
	if credentialsCfg == nil {
		credentialsCfg = viper.New()
		cfg.SetProp("credentials", credentialsCfg)
	}

	return &Login{
		credentialsCfg:  credentialsCfg.(*viper.Viper),
		instanceManager: instanceManager,
	}
}

func (l *Login) EnsureInstanceOrCreate() error {
	cfg := c.NewViperConfig("", "")
	if loadCredErr := cfg.GetCredentialsManager().LoadCredentials(); loadCredErr != nil {
		fmt.Println("Error loading credentials: ", loadCredErr)
		return loadCredErr
	}

	instanceNameList := l.instanceManager.GetInstanceNameList()
	instanceName := selectFromList("Select an instance", instanceNameList, l.instanceManager.GetCurrentInstance().Name)
	instance := l.instanceManager.GetInstance(instanceName)
	if instance.ApiUrl == "" {
		if createInstanceErr := l.instanceManager.CreateInstanceForm(); createInstanceErr != nil {
			return createInstanceErr
		}
	} else {
		if setCurInstanceErr := l.instanceManager.SetCurrentInstance(instanceName); setCurInstanceErr != nil {
			fmt.Println("Error setting current instance: ", setCurInstanceErr)
			return setCurInstanceErr
		}
	}

	return nil
}

func (l *Login) SetKuberoCredentials(token string) error {
	if token == "" {
		token = promptLine("Kubero Token", "", "")
	}

	l.credentialsCfg.Set(l.instanceManager.GetCurrentInstance().Name, token)
	writeConfigErr := l.credentialsCfg.WriteConfig()
	if writeConfigErr != nil {
		fmt.Println("Error writing config file: ", writeConfigErr)
		return writeConfigErr
	}

	return nil
}

func (l *Login) HandleOAuth2JWTLogin(cfg c.IConfigManager, oauth2Config c.OAuth2JWTConfig) error {
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

func (l *Login) HandleUserRSALogin(cfg c.IConfigManager, userRSAConfig c.UserRSAConfig) error {
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

func (l *Login) HandleUserRSAPasswordLogin(cfg c.IConfigManager, userRSAPasswordConfig c.UserRSAPasswordConfig) error {
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
