package kuberoCli

import (
	"kubero/pkg/kuberoApi"
	"time"
)

type Pipeline struct {
	Buildpack struct {
		Build struct {
			Command    string `json:"command"`
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"build"`
		Fetch struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"fetch"`
		Language string `json:"language"`
		Name     string `json:"name"`
		Run      struct {
			Command    string `json:"command"`
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"run"`
	} `json:"buildpack"`
	Deploymentstrategy string `json:"deploymentstrategy"`
	Dockerimage        string `json:"dockerimage"`
	Git                struct {
		Keys struct {
			CreatedAt time.Time `json:"created_at"`
			ID        int       `json:"id"`
			Priv      string    `json:"priv"`
			Pub       string    `json:"pub"`
			ReadOnly  bool      `json:"read_only"`
			Title     string    `json:"title"`
			URL       string    `json:"url"`
			Verified  bool      `json:"verified"`
		} `json:"keys"`
		Repository struct {
			Admin         bool   `json:"admin"`
			CloneURL      string `json:"clone_url"`
			DefaultBranch string `json:"default_branch"`
			Description   string `json:"description"`
			Homepage      string `json:"homepage"`
			ID            int    `json:"id"`
			Language      string `json:"language"`
			Name          string `json:"name"`
			NodeID        string `json:"node_id"`
			Owner         string `json:"owner"`
			Private       bool   `json:"private"`
			Push          bool   `json:"push"`
			SSHURL        string `json:"ssh_url"`
			Visibility    string `json:"visibility"`
		} `json:"repository"`
		Webhook struct {
			Active    bool      `json:"active"`
			CreatedAt time.Time `json:"created_at"`
			Events    []string  `json:"events"`
			ID        int       `json:"id"`
			Insecure  string    `json:"insecure"`
			URL       string    `json:"url"`
		} `json:"webhook"`
		Webhooks struct {
		} `json:"webhooks"`
	} `json:"git"`
	Name   string `json:"name"`
	Phases []struct {
		Context string `json:"context"`
		Enabled bool   `json:"enabled"`
		Name    string `json:"name"`
		Apps    []App  `json:"apps"`
	} `json:"phases"`
	Reviewapps bool `json:"reviewapps"`
}
type PipelinesList struct {
	Items []Pipeline `json:"items"`
}

type Contexts []struct {
	Cluster string `json:"cluster"`
	Name    string `json:"name"`
	User    string `json:"user"`
}

type Repositories struct {
	Github    bool `json:"github"`
	Gitea     bool `json:"gitea"`
	Gitlab    bool `json:"gitlab"`
	Bitbucket bool `json:"bitbucket"`
	Docker    bool `json:"docker"`
}

type App struct {
	Addons   []interface{} `json:"addons"`
	Affinity struct {
	} `json:"affinity"`
	Autodeploy  bool `json:"autodeploy"`
	Autoscale   bool `json:"autoscale"`
	Autoscaling struct {
		Enabled bool `json:"enabled"`
	} `json:"autoscaling"`
	Branch             string        `json:"branch"`
	Cronjobs           []interface{} `json:"cronjobs"`
	Deploymentstrategy string        `json:"deploymentstrategy"`
	Domain             string        `json:"domain"`
	EnvVars            []interface{} `json:"envVars"`
	FullnameOverride   string        `json:"fullnameOverride"`
	Gitrepo            struct {
		Admin         bool   `json:"admin"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
		Description   string `json:"description"`
		Homepage      string `json:"homepage"`
		ID            int    `json:"id"`
		Language      string `json:"language"`
		Name          string `json:"name"`
		NodeID        string `json:"node_id"`
		Owner         string `json:"owner"`
		Private       bool   `json:"private"`
		Push          bool   `json:"push"`
		SSHURL        string `json:"ssh_url"`
		Visibility    string `json:"visibility"`
	} `json:"gitrepo"`
	Image struct {
		Build struct {
			Command    string `json:"command"`
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"build"`
		ContainerPort int `json:"containerPort"`
		Fetch         struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"fetch"`
		PullPolicy string `json:"pullPolicy"`
		Repository string `json:"repository"`
		Run        struct {
			Command    string `json:"command"`
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"run"`
		Tag string `json:"tag"`
	} `json:"image"`
	ImagePullSecrets []interface{} `json:"imagePullSecrets"`
	Ingress          struct {
		Annotations struct {
		} `json:"annotations"`
		ClassName string `json:"className"`
		Enabled   bool   `json:"enabled"`
		Hosts     []struct {
			Host  string `json:"host"`
			Paths []struct {
				Path     string `json:"path"`
				PathType string `json:"pathType"`
			} `json:"paths"`
		} `json:"hosts"`
		TLS []interface{} `json:"tls"`
	} `json:"ingress"`
	Name         string `json:"name"`
	NameOverride string `json:"nameOverride"`
	NodeSelector struct {
	} `json:"nodeSelector"`
	Phase          string `json:"phase"`
	Pipeline       string `json:"pipeline"`
	PodAnnotations struct {
	} `json:"podAnnotations"`
	PodSecurityContext struct {
	} `json:"podSecurityContext"`
	Podsize      string `json:"podsize"`
	ReplicaCount int    `json:"replicaCount"`
	Service      struct {
		Port int    `json:"port"`
		Type string `json:"type"`
	} `json:"service"`
	ServiceAccount struct {
		Annotations struct {
		} `json:"annotations"`
		Create bool   `json:"create"`
		Name   string `json:"name"`
	} `json:"serviceAccount"`
	Tolerations []interface{} `json:"tolerations"`
	Web         struct {
		Autoscaling struct {
			MaxReplicas                       int `json:"maxReplicas"`
			MinReplicas                       int `json:"minReplicas"`
			TargetCPUUtilizationPercentage    int `json:"targetCPUUtilizationPercentage"`
			TargetMemoryUtilizationPercentage int `json:"targetMemoryUtilizationPercentage"`
		} `json:"autoscaling"`
		ReplicaCount int `json:"replicaCount"`
	} `json:"web"`
	Worker struct {
		Autoscaling struct {
			MaxReplicas                       int `json:"maxReplicas"`
			MinReplicas                       int `json:"minReplicas"`
			TargetCPUUtilizationPercentage    int `json:"targetCPUUtilizationPercentage"`
			TargetMemoryUtilizationPercentage int `json:"targetMemoryUtilizationPercentage"`
		} `json:"autoscaling"`
		ReplicaCount int `json:"replicaCount"`
	} `json:"worker"`
}

type Addon struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Version struct {
		Latest    string `json:"latest"`
		Installed string `json:"installed"`
	} `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Readme      string `json:"readme,omitempty"`
	ArtifactURL string `json:"artifact_url"`
	Kind        string `json:"kind"`
	Install     string `json:"install"`
	Beta        bool   `json:"beta"`
}

type buildPacks []struct {
	Name     string `json:"name"`
	Language string `json:"language"`
	Fetch    struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
	} `json:"fetch"`
	Build struct {
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Command    string `json:"command"`
	} `json:"build"`
	Run struct {
		Repository         string `json:"repository"`
		Tag                string `json:"tag"`
		ReadOnlyAppStorage bool   `json:"readOnlyAppStorage"`
		SecurityContext    *struct {
			AllowPrivilegeEscalation *bool `json:"allowPrivilegeEscalation"`
			ReadOnlyRootFilesystem   *bool `json:"readOnlyRootFilesystem"`
		} `json:"securityContext"`
		Command string `json:"command"`
	} `json:"run,omitempty"`
}

type Podsize struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     bool   `json:"default,omitempty"`
	Resources   struct {
		Requests struct {
			Memory string `json:"memory"`
			CPU    string `json:"cpu"`
		} `json:"requests"`
		Limits struct {
			Memory string `json:"memory"`
			CPU    string `json:"cpu"`
		} `json:"limits,omitempty"`
	} `json:"resources,omitempty"`
	Active bool `json:"active,omitempty"`
}

type pipelinesConfigsList map[string]kuberoApi.PipelineCRD

type appShort struct {
	Name     string `json:"name"`
	Phase    string `json:"phase"`
	Pipeline string `json:"pipeline"`
}

type Instance struct {
	Name       string `json:"-" yaml:"-"`
	Apiurl     string `json:"apiurl" yaml:"apiurl"`
	IacBaseDir string `json:"iacBaseDir,omitempty" yaml:"iacBaseDir,omitempty"`
	ConfigPath string `json:"-" yaml:"-"`
	Tunnel     struct {
		Subdomain string `json:"subdomain" yaml:"subdomain"`
		Port      int    `json:"port" yaml:"port"`
		Host      string `json:"host" yaml:"host"`
	} `json:"tunnel,omitempty" yaml:"tunnel,omitempty"`
}

type Config struct {
	Api struct {
		Url   string `json:"url" yaml:"url"`
		Token string `json:"token" yaml:"token"`
	} `json:"api" yaml:"api"`
}

type GithubVersion struct {
	Name       string `json:"name"`
	ZipballURL string `json:"zipball_url"`
	TarballURL string `json:"tarball_url"`
	Commit     struct {
		Sha string `json:"sha"`
		URL string `json:"url"`
	} `json:"commit"`
	NodeID string `json:"node_id"`
}
