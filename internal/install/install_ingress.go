package install

import (
	"github.com/i582/cfmt/cmd/cfmt"
	"log"

	"os/exec"
)

func installIngress() {
	ingressInstalled, _ := exec.Command("kubectl", "get", "ns", "ingress-nginx").Output()
	if len(ingressInstalled) > 0 {
		_, _ = cfmt.Println("{{✓ Ingress is already installed}}::lightGreen")
		return
	}

	ingressInstall := promptLine("4) Install Ingress", "[y,n]", "y")
	if ingressInstall != "y" {
		return
	} else {

		if clusterType == "" {
			clusterType = selectFromList("Which cluster type have you installed?", clusterTypeList, "")
		}

		prefill := "baremetal"
		switch clusterType {
		case "kind":
			prefill = "kind"
		case "linode":
			prefill = "cloud"
		case "gke":
			prefill = "cloud"
		case "scaleway":
			prefill = "scw"
		case "digitalocean":
			prefill = "do"
		}

		ingressProviderList := []string{"kind", "aws", "baremetal", "cloud", "do", "exoscale", "scw"}
		ingressProvider := selectFromList("Provider [kind, aws, baremetal, cloud(Azure,Google,Oracle,Linode), do(digital ocean), exoscale, scw(scaleway)]", ingressProviderList, prefill)

		ingressSpinner := spinner.New("Install Ingress")
		URL := "https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-" + ingressControllerVersion + "/deploy/static/provider/" + ingressProvider + "/deploy.yaml"
		_, _ = cfmt.Println("  run command : kubectl apply -f " + URL)
		ingressSpinner.Start("Install Ingress")
		_, ingressErr := exec.Command("kubectl", "apply", "-f", URL).Output()
		if ingressErr != nil {
			ingressSpinner.Error("Failed to run command. Try running this command manually: kubectl apply -f " + URL)
			log.Fatal(ingressErr)
		}

		ingressSpinner.Success("Ingress installed successfully")
	}
}
