// A module for DaggerSkopeo functions
package main

import (
	"context"
	"dagger/dagger-skopeo/internal/dagger"
	"fmt"
	"strconv"

	"golang.org/x/sync/errgroup"
)

type Skopeo struct{}

// SkopeoAgent: natural-language "assignment" drives dagger-skopeo functions.
func (m *Skopeo) Ask(
	ctx context.Context,
	question string, // e.g. "inspect nginx:1.27"
) (string, error) {
	env := dag.Env().
		WithStringInput("question", question, "The question about the OCI image").
		// expose THIS module (all exported functions on Skopeo) as tools under the name "skopeo"
		WithModuleInput(
			"skopeo",
			dag.CurrentModule().Source().AsModule(), // <-- correct way to get a Module
			"Tools for skopeo operations (e.g., SkopeoInspect)",
		)

	prompt := `
You are a container-registry operations agent.
You can call functions from the $skopeo module.

Goal: answer the user's question using real tool calls when needed.
If inspection is required, call: skopeo.SkopeoInspect(imageRef: string) -> stdout JSON.

Question: $question
`

	return dag.LLM().
		WithEnv(env).
		WithPrompt(prompt).
		LastReply(ctx)
}

// Return a Container from the official trivy image.
func (m *Skopeo) Base(
	// +optional
	// +default="latest"
	// Trivy image version tag.
	trivyImageTag string,
) *dagger.Container {
	return dag.Container().
		From(fmt.Sprintf("aquasec/trivy:%s", trivyImageTag)).
		WithMountedCache("/root/.cache/trivy", dag.CacheVolume("trivy-db-cache"))
}

// Scan an image ref.
func (m *Skopeo) ScanImage(
	ctx context.Context,
	// Reference to the image to scan
	imageRef string,
	// +optional
	// +default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
	// which severity levels to include in the scan
	severity string,
	// +optional
	// +default=0
	// exit code to return if vulnerabilities are found
	exitCode int,
	// +optional
	// +default="table"
	// output format of the scan results
	format string,
	// +optional
	// +default="latest"
	// Trivy image version tag
	trivyImageTag string,
	// token for authentication
	auth *dagger.Secret,
) (string, error) {
	return m.Base(trivyImageTag).
		WithSecretVariable("TRIVY_PASSWORD", auth).
		WithEnvVariable("TRIVY_USERNAME", "eladav").
		WithExec([]string{"trivy", "image", "--quiet", "--severity", severity, "--exit-code", strconv.Itoa(exitCode), "--format", format, imageRef}).Stdout(ctx)
}

// MirrorOne mirrors a single image from a source registry to a destination registry using Skopeo.
func (m *Skopeo) MirrorOne(
	ctx context.Context,
	// path for AWS credentials file used for authentication
	// +optional
	awsCreds *dagger.File,
	// AWS region for ECR
	// +optional
	awsRegion string,
	// source and destination registries and repository tag
	srcRegistry, dstRegistry, repoTag string,
	// destination user for authentication
	dstUser string,
	// destination password for authentication
	// +optional
	dstPass *dagger.Secret,
	// +optional
	// default=false
	// destination reference for the image, if empty, uses the repoTag
	dstRef string,
	// wether to pull the image from AWS ECR or not
	awsPull bool,
) error {
	var rawTok = ""
	if awsPull {
		tok, err := dag.Aws().
			EcrGetLoginPassword(ctx, awsCreds, awsRegion)
		if err != nil {
			return err
		}
		rawTok = tok
	}
	srcPass := dag.SetSecret("ecr-pass", rawTok)
	if dstRef != "" {
		dstRef = fmt.Sprintf("docker://%s/%s", dstRegistry, dstRef)
	} else {
		dstRef = fmt.Sprintf("docker://%s/%s", dstRegistry, repoTag)
	}
	srcRef := fmt.Sprintf("docker://%s/%s", srcRegistry, repoTag)
	//

	cmd := fmt.Sprintf(
		`skopeo copy --preserve-digests --src-creds AWS:$SRC_PASS --dest-creds %s:$DST_PASS %s %s`,
		dstUser, srcRef, dstRef)

	_, err := dag.Container().
		From("quay.io/skopeo/stable:latest").
		WithSecretVariable("SRC_PASS", srcPass).
		WithSecretVariable("DST_PASS", dstPass).
		WithExec([]string{"sh", "-c", cmd}).
		Stdout(ctx)
	return err
}

// MirrorMany mirrors multiple images from a source registry to a destination registry using Skopeo.
func (m *Skopeo) MirrorMany(
	ctx context.Context,
	// path for AWS credentials file used for authentication
	awsCreds *dagger.File,
	// AWS region for ECR
	awsRegion string,
	// source and destination registries and repository tags
	srcRegistry, dstRegistry string,
	// repository tags to mirror
	repoTags []string,
	// destination user for authentication
	dstUser string,
	// destination password for authentication
	dstPass *dagger.Secret,
	// +optional
	// default=false
	// destination reference for the image, if empty, uses the repoTag
	dstRef string,
	// whether to pull the image from AWS ECR or not
	awsPull bool,
) error {
	if len(repoTags) == 0 {
		return fmt.Errorf("repoTags cannot be empty")
	}

	g, gctx := errgroup.WithContext(ctx)

	for _, tag := range repoTags {
		g.Go(func() error {
			return m.MirrorOne(
				gctx, awsCreds, awsRegion,
				srcRegistry, dstRegistry, tag,
				dstUser, dstPass, dstRef, false,
			)
		})
	}

	return g.Wait()
}

func (m *Skopeo) SkopeoInspect(
	ctx context.Context,
	// Reference to the image to inspect
	imageRef string,
) (string, error) {
	return dag.Container().
		From("quay.io/skopeo/stable:latest").
		WithExec([]string{"skopeo", "inspect", "--raw", imageRef}).Stdout(ctx)
}
