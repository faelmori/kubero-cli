package api

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	t "github.com/kubero-dev/kubero-cli/types"
	v "github.com/kubero-dev/kubero-cli/version"
	"io/ioutil"
	"os"
	"golang.org/x/oauth2"
)

type Client struct {
	baseURL     string
	bearerToken string
	client      *resty.Request
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Init(baseURL string, bearerToken string) *resty.Request {
	if baseURL == "" || bearerToken == "" {
		panic("baseURL and bearerToken are required to initialize the API client")
	}

	client := resty.New().SetBaseURL(baseURL).R().
		EnableTrace().
		SetAuthScheme("Bearer").
		SetAuthToken(bearerToken).
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetHeader("User-Agent", "kubero-cli/"+v.Version())

	c.baseURL = baseURL
	c.bearerToken = bearerToken
	c.client = client

	return client
}
func (c *Client) DeployPipeline(pipeline t.PipelineCRD) (*resty.Response, error) {
	c.client.SetBody(pipeline.Spec)
	res, err := c.client.Post("/api/v3/pipelines/")

	return res, err
}
func (c *Client) UnDeployPipeline(pipelineName string) (*resty.Response, error) {
	res, err := c.client.Delete("/api/v3/pipelines/" + pipelineName)

	return res, err
}
func (c *Client) GetPipeline(pipelineName string) (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/pipelines/" + pipelineName)

	return res, err
}
func (c *Client) UnDeployApp(pipelineName string, stageName string, appName string) (*resty.Response, error) {
	res, err := c.client.Delete("/api/v3/pipelines/" + pipelineName + "/" + stageName + "/" + appName)

	return res, err
}
func (c *Client) GetApp(pipelineName string, stageName string, appName string) (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/pipelines/" + pipelineName + "/" + stageName + "/" + appName)

	return res, err
}
func (c *Client) GetApps() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/apps")

	return res, err
}
func (c *Client) GetPipelines() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/pipelines")
	return res, handleError(res, err)
}
func (c *Client) DeployApp(app t.AppCRD) (*resty.Response, error) {
	c.client.SetBody(app.Spec)
	res, err := c.client.Post("/api/v3/apps")

	return res, err
}
func (c *Client) GetPipelineApps(pipelineName string) (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/pipelines/" + pipelineName + "/apps")

	return res, err
}
func (c *Client) GetAddons() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/addons")

	return res, err
}
func (c *Client) GetBuildpacks() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/config/buildpacks")

	return res, err
}
func (c *Client) GetPodsize() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/config/podsize")

	return res, err
}
func (c *Client) GetRepositories() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/config/repositories")

	return res, err
}
func (c *Client) GetContexts() (*resty.Response, error) {
	res, err := c.client.Get("/api/v3/config/k8s/context")

	return res, err
}
func (c *Client) WithBody(body interface{}) *Client {
	c.client.SetBody(body)
	return c
}

func handleError(response *resty.Response, err error) error {
	if err != nil {
		return err
	}

	if response.IsError() {
		return fmt.Errorf("API error: %s", response.String())
	}

	return nil
}

func (c *Client) HandleOAuth2JWTLogin(oauth2Config t.OAuth2JWTConfig) error {
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

	c.bearerToken = token.AccessToken
	return nil
}

func (c *Client) HandleUserRSALogin(userRSAConfig t.UserRSAConfig) error {
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

	return nil
}

func (c *Client) HandleUserRSAPasswordLogin(userRSAPasswordConfig t.UserRSAPasswordConfig) error {
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

	return nil
}
