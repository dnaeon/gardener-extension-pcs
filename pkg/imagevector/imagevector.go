// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	_ "embed"

	"github.com/gardener/gardener/pkg/utils/imagevector"
	"k8s.io/apimachinery/pkg/util/runtime"
)

const (
	// ImageNamePodCertificateSigner specifies the name of the image for the
	// PodCertificateRequest signer implementation.
	ImageNamePodCertificateSigner = "pod-certificate-signer"
)

var (
	//go:embed images.yaml
	imagesYAML  string
	imageVector imagevector.ImageVector
)

func init() {
	var err error

	imageVector, err = imagevector.Read([]byte(imagesYAML))
	runtime.Must(err)

	imageVector, err = imagevector.WithEnvOverride(imageVector, imagevector.OverrideEnv)
	runtime.Must(err)
}

// Images returns the image vector which contains all images.
func Images() imagevector.ImageVector {
	return imageVector
}
