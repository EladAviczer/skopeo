// A module for DaggerSkopeo functions
package main

import (
	"context"
	"dagger/dagger-skopeo/internal/dagger"
	"fmt"
	"strconv"

	"golang.org/x/sync/errgroup"
)

// New constructs the Skopeo module with configurable defaults.
func New(
	// +default="latest"
	// Version tag for quay.io/skopeo/stable
	skopeoImageTag string,
) *Skopeo {
	return &Skopeo{
		SkopeoImageTag: skopeoImageTag,
	}
}

type Skopeo struct {
	SkopeoImageTag string
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
	// default=""
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
		From(fmt.Sprintf("quay.io/skopeo/stable:%s", m.SkopeoImageTag)).
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
	// default=""
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
	// +optional
	// +default="{{.Name}}:{{.Tag}} Digest: {{.Digest}} Arch: {{.Architecture}} | OS: {{.Os}}"
	// Go template format string for skopeo inspect
	format string,
	registry string,
) (string, error) {

	//dstRef = fmt.Sprintf("docker://%s/%s", dstRegistry, dstRef)
	ref := fmt.Sprintf("docker://%s/%s", registry, imageRef)
	return dag.Container().
		From(fmt.Sprintf("quay.io/skopeo/stable:%s", m.SkopeoImageTag)).
		WithExec([]string{"skopeo", "inspect", "--format", format, ref}).Stdout(ctx)
}

// Check version of the skopeo image used.
func (m *Skopeo) Version(ctx context.Context) (string, error) {
	return dag.Container().
		From(fmt.Sprintf("quay.io/skopeo/stable:%s", m.SkopeoImageTag)).
		WithExec([]string{"skopeo", "--version"}).Stdout(ctx)
}

// Delete an image from a registry.
func (m *Skopeo) Delete(
	ctx context.Context,
	// Reference to the image to delete
	imageRef string,
	registry string,
) (string, error) {
	ref := fmt.Sprintf("docker://%s/%s", registry, imageRef)
	return dag.Container().
		From(fmt.Sprintf("quay.io/skopeo/stable:%s", m.SkopeoImageTag)).
		WithExec([]string{"skopeo", "delete", ref}).Stdout(ctx)
}
