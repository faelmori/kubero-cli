package install

import (
	"os"
	"os/exec"
	"testing"
)

func TestInstallKubernetes(t *testing.T) {
	// Mock user input and command execution
	os.Setenv("CLUSTER_TYPE", "kind")
	defer os.Unsetenv("CLUSTER_TYPE")
	InstallKubernetes()
	// Add assertions to verify the expected state
}

func TestInstallMetrics(t *testing.T) {
	// Mock command output
	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()
	InstallMetrics()
	// Add assertions to verify the expected state
}

func TestInstallIngress(t *testing.T) {
	// Mock user input and command execution
	os.Setenv("CLUSTER_TYPE", "kind")
	defer os.Unsetenv("CLUSTER_TYPE")
	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()
	InstallIngress()
	// Add assertions to verify the expected state
}

func TestInstallCertManager(t *testing.T) {
	// Mock user input and command execution
	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()
	InstallCertManager()
	// Add assertions to verify the expected state
}

func TestInstallKuberoOperator(t *testing.T) {
	// Mock command output
	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()
	InstallKuberoOperator()
	// Add assertions to verify the expected state
}

func TestInstallKuberoUi(t *testing.T) {
	// Mock user input and command execution
	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()
	InstallKuberoUi()
	// Add assertions to verify the expected state
}

func TestInstallMonitoring(t *testing.T) {
	// Mock command output
	execCommand = mockExecCommand
	defer func() { execCommand = exec.Command }()
	InstallMonitoring()
	// Add assertions to verify the expected state
}

// Mock function to replace exec.Command for testing
func mockExecCommand(command string, args ...string) *exec.Cmd {
	cmd := exec.Command("echo", append([]string{command}, args...)...)
	return cmd
}
