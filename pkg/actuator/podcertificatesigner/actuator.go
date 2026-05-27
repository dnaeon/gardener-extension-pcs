// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package actuator provides the implementation of a Gardener extension
// actuator.
package podcertificatesigner

import (
	"context"
	"errors"
	"fmt"
	"time"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/component-base/featuregate"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-pcs/pkg/imagevector"
)

// ErrInvalidActuator is an error which is returned when creating an [Actuator]
// with invalid config settings.
var ErrInvalidActuator = errors.New("invalid actuator")

const (
	// Name is the name of the actuator
	Name = "pod-certificate-signer"
	// ExtensionType is the type of the extension resources, which the
	// actuator reconciles.
	ExtensionType = "pod-certificate-signer"
	// FinalizerSuffix is the finalizer suffix used by the actuator
	FinalizerSuffix = "pod-certificate-signer"
)

// Actuator is an implementation of [extension.Actuator].
type Actuator struct {
	client  client.Client
	decoder runtime.Decoder

	// The following fields are usually derived from the list of extra Helm
	// values provided by gardenlet during the deployment of the extension.
	//
	// See the link below for more details about how gardenlet provides
	// extra values to Helm during the extension deployment.
	//
	// https://github.com/gardener/gardener/blob/d5071c800378616eb6bb2c7662b4b28f4cfe7406/pkg/gardenlet/controller/controllerinstallation/controllerinstallation/reconciler.go#L236-L263
	gardenerVersion       string
	gardenletFeatureGates map[featuregate.Feature]bool
}

var _ extension.Actuator = &Actuator{}

// Option is a function, which configures the [Actuator].
type Option func(a *Actuator) error

// New creates a new actuator with the given options.
func New(c client.Client, opts ...Option) (*Actuator, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: no client specified", ErrInvalidActuator)
	}

	act := &Actuator{
		client:                c,
		gardenletFeatureGates: make(map[featuregate.Feature]bool),
	}

	for _, opt := range opts {
		if err := opt(act); err != nil {
			return nil, err
		}
	}

	if act.decoder == nil {
		act.decoder = serializer.NewCodecFactory(c.Scheme(), serializer.EnableStrict).UniversalDecoder()
	}

	return act, nil
}

// WithDecoder is an [Option], which configures the [Actuator] with the given
// [runtime.Decoder].
func WithDecoder(d runtime.Decoder) Option {
	opt := func(a *Actuator) error {
		a.decoder = d

		return nil
	}

	return opt
}

// WithGardenerVersion is an [Option], which configures the [Actuator] with the
// given version of Gardener. This version of Gardener is usually provided by
// the gardenlet as part of the extra Helm values during deployment of the
// extension.
func WithGardenerVersion(v string) Option {
	opt := func(a *Actuator) error {
		a.gardenerVersion = v

		return nil
	}

	return opt
}

// WithGardenletFeatures is an [Option], which configures the [Actuator] with
// the given gardenlet feature gates. These feature gates are usually provided
// by the gardenlet as part of the extra Helm values during deployment of the
// extension.
func WithGardenletFeatures(feats map[featuregate.Feature]bool) Option {
	opt := func(a *Actuator) error {
		a.gardenletFeatureGates = feats

		return nil
	}

	return opt
}

// Name returns the name of the actuator. This name can be used when registering
// a controller for the actuator.
func (a *Actuator) Name() string {
	return Name
}

// FinalizerSuffix returns the finalizer suffix to use for the actuator. The
// result of this method may be used when registering a controller with the
// actuator.
func (a *Actuator) FinalizerSuffix() string {
	return FinalizerSuffix
}

// ExtensionType returns the type of extension resources the actuator
// reconciles. The result of this method may be used when registering a
// controller with the actuator.
func (a *Actuator) ExtensionType() string {
	return ExtensionType
}

// ExtensionClass returns the [extensionsv1alpha1.ExtensionClass] for the
// actuator. The result of this method may be used when registering a controller
// with the actuator.
func (a *Actuator) ExtensionClass() extensionsv1alpha1.ExtensionClass {
	return extensionsv1alpha1.ExtensionClassShoot
}

// Reconcile reconciles the [extensionsv1alpha1.Extension] resource by taking
// care of any resources managed by the [Actuator]. This method implements the
// [extension.Actuator] interface.
func (a *Actuator) Reconcile(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	// The cluster name is the same as the name of the namespace for our
	// [extensionsv1alpha1.Extension] resource.
	clusterName := ex.Namespace

	logger.Info("reconciling extension", "name", ex.Name, "cluster", clusterName)

	cluster, err := extensionscontroller.GetCluster(ctx, a.client, clusterName)
	if err != nil {
		return fmt.Errorf("failed to get cluster: %w", err)
	}

	// Nothing to do here, if the shoot cluster is hibernated at the moment.
	if v1beta1helper.HibernationIsEnabled(cluster.Shoot) {
		return nil
	}

	secretsManager, err := a.newSecretsManager(ctx, logger, ex.Namespace)
	if err != nil {
		return fmt.Errorf("failed to create a new secrets manager: %w", err)
	}

	// Generate TLS secret for the CA
	if _, err := secretsManager.Generate(ctx, &secretsutils.CertificateSecretConfig{
		Name:       secretNameCACert,
		CommonName: Name,
		CertType:   secretsutils.CACert,
		Validity:   new(30 * 24 * time.Hour),
	}, secretsmanager.Rotate(secretsmanager.KeepOld), secretsmanager.IgnoreOldSecretsAfter(24*time.Hour)); err != nil {
		return fmt.Errorf("failed to generate CA certificate secret: %w", err)
	}

	caSecret, _ := secretsManager.Get(secretNameCACert, secretsmanager.Current)
	pscImage, err := imagevector.Images().FindImage(imagevector.ImageNamePodCertificateSigner)
	if err != nil {
		return fmt.Errorf("failed to find image for %s: %w", imagevector.ImageNamePodCertificateSigner, err)
	}

	// Bundle things up in a managed resource
	registry := managedresources.NewRegistry(
		kubernetes.SeedScheme,
		kubernetes.SeedCodec,
		kubernetes.SeedSerializer,
	)

	data, err := registry.AddAllAndSerialize(
		a.getServiceAccount(ex.Namespace),
		a.getRole(ex.Namespace),
		a.getRoleBinding(ex.Namespace),
		a.getClusterRole(ex.Namespace),
		a.getClusterRoleBinding(ex.Namespace),
		a.getService(ex.Namespace),
		a.getDeployment(ex.Namespace, pscImage, caSecret),
	)

	if err != nil {
		return fmt.Errorf("failed to add managed resources to registry: %w", err)
	}

	return managedresources.CreateForSeed(
		ctx,
		a.client,
		ex.Namespace,
		baseResourceName,
		false,
		data,
	)
}

// Delete deletes any resources managed by the [Actuator]. This method
// implements the [extension.Actuator] interface.
func (a *Actuator) Delete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	logger.Info("deleting resources managed by extension")

	secretsManager, err := a.newSecretsManager(ctx, logger, ex.Namespace)
	if err != nil {
		return fmt.Errorf("failed creating a new secrets manager: %w", err)
	}

	if err := secretsManager.Cleanup(ctx); err != nil {
		return fmt.Errorf("failed cleaning up secrets managed by secrets manager: %w", err)
	}

	return client.IgnoreNotFound(managedresources.DeleteForSeed(ctx, a.client, ex.Namespace, baseResourceName))
}

// ForceDelete signals the [Actuator] to delete any resources managed by it,
// because of a force-delete event of the shoot cluster. This method implements
// the [extension.Actuator] interface.
func (a *Actuator) ForceDelete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Delete(ctx, logger, ex)
}

// Restore restores the resources managed by the extension [Actuator]. This
// method implements the [extension.Actuator] interface.
func (a *Actuator) Restore(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, logger, ex)
}

// Migrate signals the [Actuator] to reconcile the resources managed by it,
// because of a shoot control-plane migration event. This method implements the
// [extension.Actuator] interface.
func (a *Actuator) Migrate(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, logger, ex)
}

// newSecretsManager creates a new [secretsmanager.Interface] for the [Actuator].
func (a *Actuator) newSecretsManager(ctx context.Context, logger logr.Logger, namespace string) (secretsmanager.Interface, error) {
	m, err := secretsmanager.New(
		ctx,
		logger,
		clock.RealClock{},
		a.client,
		fmt.Sprintf("gardener-extension-%s", a.Name()),
		secretsmanager.WithCASecretAutoRotation(),
		secretsmanager.WithNamespaces(namespace),
	)

	return m, err
}
