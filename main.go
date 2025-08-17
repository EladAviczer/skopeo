// A module for DaggerSkopeo functions
package main

import (
	"context"
	"dagger/dagger-skopeo/internal/dagger"
	"fmt"
	"strconv"

	"golang.org/x/sync/errgroup"
)

type DaggerSkopeo struct{}

// Return a Container from the official trivy image.
func (m *DaggerSkopeo) Base(
	// +optional
	// +default="latest"
	trivyImageTag string,
) *dagger.Container {
	return dag.Container().
		From(fmt.Sprintf("aquasec/trivy:%s", trivyImageTag)).
		WithMountedCache("/root/.cache/trivy", dag.CacheVolume("trivy-db-cache"))
}

// Scan an image ref.
func (m *DaggerSkopeo) ScanImage(
	ctx context.Context,
	imageRef string,
	// +optional
	// +default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
	severity string,
	// +optional
	// +default=0
	exitCode int,
	// +optional
	// +default="table"
	format string,
	// +optional
	// +default="latest"
	trivyImageTag string,
	auth *dagger.Secret,
) (string, error) {
	return m.Base(trivyImageTag).
		WithSecretVariable("TRIVY_PASSWORD", auth).
		WithEnvVariable("TRIVY_USERNAME", "eladav").
		// WithExec([]string{"echo", "$TRIVY_PASSWORD", "|", "trivy", "registry", "login", "--username", "eladav", "--password-stdin", "artifactory.rafael.co.il:6079"}).
		WithExec([]string{"trivy", "image", "--quiet", "--severity", severity, "--exit-code", strconv.Itoa(exitCode), "--format", format, imageRef}).Stdout(ctx)
}

// Module entry-point
// type Module struct{}

// Copy an image from one registry to another using Core API and daggerverse
func (m *DaggerSkopeo) Copy(ctx context.Context, src, dst string) error {
	_, err := dag.Container().
		From(src).
		Publish(ctx, dst)
	return err
}

func (m *DaggerSkopeo) MirrorOne(
	ctx context.Context,
	awsCreds *dagger.File,
	awsRegion string,
	srcRegistry, dstRegistry, repoTag string,
	dstUser string,
	dstPass *dagger.Secret,
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

	srcRef := fmt.Sprintf("docker://%s/%s", srcRegistry, repoTag)
	dstRef := fmt.Sprintf("docker://%s/%s", dstRegistry, repoTag)

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

func (m *DaggerSkopeo) MirrorMany(
	ctx context.Context,
	awsCreds *dagger.File,
	awsRegion string,
	srcRegistry, dstRegistry string,
	repoTags []string,
	dstUser string,
	dstPass *dagger.Secret,
	awsPull bool,
) error {
	if len(repoTags) == 0 {
		return fmt.Errorf("repoTags cannot be empty")
	}

	g, gctx := errgroup.WithContext(ctx)

	for _, tag := range repoTags {
		// capture loop variable
		tag := tag
		g.Go(func() error {
			return m.MirrorOne(
				gctx, awsCreds, awsRegion,
				srcRegistry, dstRegistry, tag,
				dstUser, dstPass, false,
			)
		})
	}

	return g.Wait()
}
