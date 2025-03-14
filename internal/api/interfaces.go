package api

import (
	"github.com/faelmori/kubero-cli/types"
	"github.com/go-resty/resty/v2"
)

type Repository interface {
	GetRepositories() (repositoriesResponse *resty.Response, err error)
	GetContexts() (contextsResponse *resty.Response, err error)
	loadContexts()
	loadRepositories()
}

type Context interface {
	GetName() string
	GetURL() string
}

type ClientAPI interface {
	Init(baseURL string, bearerToken string) *resty.Request
	DeployPipeline(pipeline types.PipelineCRD) (*resty.Response, error)
	UnDeployPipeline(pipelineName string) (*resty.Response, error)
	GetPipeline(pipelineName string) (*resty.Response, error)
	UnDeployApp(pipelineName string, stageName string, appName string) (*resty.Response, error)
	GetApp(pipelineName string, stageName string, appName string) (*resty.Response, error)
	GetApps() (*resty.Response, error)
	GetPipelines() (*resty.Response, error)
	DeployApp(app types.AppCRD) (*resty.Response, error)
	GetPipelineApps(pipelineName string) (*resty.Response, error)
	GetAddons() (*resty.Response, error)
	GetBuildpacks() (*resty.Response, error)
	GetPodsize() (*resty.Response, error)
	GetRepositories() (*resty.Response, error)
	GetContexts() (*resty.Response, error)
	WithBody(body interface{}) *Client
}
