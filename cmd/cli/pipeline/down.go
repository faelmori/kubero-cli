package pipeline

import (
	"github.com/faelmori/kubero-cli/internal/pipeline"
	"github.com/spf13/cobra"
)

func PipelineDownCmds() []*cobra.Command {
	return []*cobra.Command{
		cmdDownPL(),
		cmdDownAppPL(),
		cmdDownPipelinePL(),
	}
}

func cmdDownPL() *cobra.Command {
	var downCmd = &cobra.Command{
		Use:     "down",
		Aliases: []string{"undeploy", "dn"},
		Short:   "Undeploy your pipelines and apps from the cluster",
		Long: `Use the pipeline or app subcommand to undeploy your pipelines and apps from the cluster
Subcommands:
  kubero down [pipeline|app]`,
		Run: func(cmd *cobra.Command, args []string) {
			if pipelineName != "" && appName == "" {
				pipeline.DownPipeline()
			} else if appName != "" {
				pipeline.DownApp()
			} else {
				pipeline.DownAllPipelines()
			}
		},
	}

	downCmd.Flags().StringVarP(&pipelineName, "pipeline", "p", "", "name of the pipeline")
	downCmd.Flags().StringVarP(&stageName, "stage", "s", "", "Name of the stage [test|stage|production]")
	downCmd.Flags().StringVarP(&appName, "app", "a", "", "name of the app")
	downCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Skip asking for confirmation")

	return downCmd
}

func cmdDownAppPL() *cobra.Command {
	var downAppCmd = &cobra.Command{
		Use:   "app",
		Short: "Undeploy an apps from the cluster",
		Long:  `Use the app subcommand to undeploy your apps from the cluster`,
		Run: func(cmd *cobra.Command, args []string) {
			pipeline.DownApp()
		},
	}

	downAppCmd.Flags().StringVarP(&pipelineName, "pipeline", "p", "", "name of the pipeline")
	downAppCmd.Flags().StringVarP(&stageName, "stage", "s", "", "Name of the stage [test|stage|production]")
	downAppCmd.Flags().StringVarP(&appName, "app", "a", "", "name of the app")
	downAppCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Skip asking for confirmation")

	return downAppCmd
}

func cmdDownPipelinePL() *cobra.Command {
	var downPipelineCmd = &cobra.Command{
		Use:     "pipeline",
		Aliases: []string{"pl"},
		Short:   "Undeploy a pipeline from the cluster",
		Long:    `Use the pipeline subcommand to undeploy your pipelines from the cluster`,
		Run: func(cmd *cobra.Command, args []string) {
			pipeline.DownPipeline()
		},
	}

	downPipelineCmd.Flags().StringVarP(&pipelineName, "pipeline", "p", "", "name of the pipeline")
	downPipelineCmd.Flags().StringVarP(&stageName, "stage", "s", "", "Name of the stage [test|stage|production]")
	downPipelineCmd.Flags().StringVarP(&appName, "app", "a", "", "name of the app")
	downPipelineCmd.PersistentFlags().BoolVarP(&force, "force", "f", false, "Skip asking for confirmation")

	return downPipelineCmd
}
