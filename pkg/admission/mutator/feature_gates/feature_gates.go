// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package feature_gates provides a [genericmutator.Ensurer] implementation
// which enables the Kubernetes feature gates required by the
// pod-certificate-signer extension on the kube-apiserver,
// kube-controller-manager and kubelet of the shoot cluster.
//
// Enabling this extension is a contract.
//
// "Part of the ship, part of the crew"
//
// The gates ride along whether the operator likes it or not.
package feature_gates

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/Masterminds/semver/v3"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionswebhookctx "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/component/extensions/operatingsystemconfig/original/components/kubelet"
	oscutils "github.com/gardener/gardener/pkg/component/extensions/operatingsystemconfig/utils"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podcertificatesigneractuator "github.com/gardener/gardener-extension-pcs/pkg/actuator/podcertificatesigner"
)

// ErrInvalidEnsurer is an error returned when attempting to create a
// [genericmutator.Ensurer] with an invalid configuration.
var ErrInvalidEnsurer = errors.New("invalid ensurer")

// featureGates is the set of feature gates the ensurer enables on the shoot's
// kube-apiserver, kube-controller-manager and kubelet.
var featureGates = []string{
	"PodCertificateRequests",
	"ClusterTrustBundle",
	"ClusterTrustBundleProjection",
}

const (
	// featureGatesArgPrefix is the prefix of the `--feature-gates' command-line
	// option used by the kube-apiserver and kube-controller-manager. The kubelet
	// receives the same gates via its config file rather than via command-line
	// flags, so this prefix is not used for kubelet mutation.
	featureGatesArgPrefix = "--feature-gates="

	// runtimeConfigArgPrefix is the prefix of the `--runtime-config' command-line
	// option used by the kube-apiserver.
	runtimeConfigArgPrefix = "--runtime-config="
)

// ensurer is an implementation of [genericmutator.Ensurer] which enables a
// fixed set of feature gates required by the pod-certificate-signer extension
// on the shoot's kube-apiserver, kube-controller-manager and kubelet.
type ensurer struct {
	genericmutator.NoopEnsurer

	client        client.Client
	logger        logr.Logger
	extensionType string
}

var _ genericmutator.Ensurer = &ensurer{}

// newEnsurer returns a new [ensurer].
func newEnsurer(c client.Client, logger logr.Logger) (*ensurer, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: invalid client specified", ErrInvalidEnsurer)
	}

	ens := &ensurer{
		client:        c,
		logger:        logger,
		extensionType: podcertificatesigneractuator.ExtensionType,
	}

	return ens, nil
}

// NewEnsurer returns a new [genericmutator.Ensurer] which enables the feature
// gates required by the pod-certificate-signer extension.
func NewEnsurer(c client.Client, logger logr.Logger) (genericmutator.Ensurer, error) {
	return newEnsurer(c, logger)
}

// EnsureKubeAPIServerDeployment implements the [genericmutator.Ensurer]
// interface. It enables the required feature gates on the kube-apiserver
// container of the given Deployment.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, gctx extensionswebhookctx.GardenContext, newObj, _ *appsv1.Deployment) error {
	skip, err := e.shouldSkip(ctx, gctx)
	if err != nil || skip {
		return err
	}

	if newObj == nil {
		return nil
	}

	c := extensionswebhook.ContainerWithName(newObj.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeAPIServer)
	if c == nil {
		return nil
	}

	// Enable feature gates and certificates.k8s.io/v1beta1 API group
	extensionswebhook.LogMutation(e.logger, newObj.Kind, newObj.Namespace, newObj.Name)
	for _, fg := range featureGates {
		feature := fmt.Sprintf("%s=true", fg)
		c.Args = extensionswebhook.EnsureStringWithPrefixContains(
			c.Args,
			featureGatesArgPrefix,
			feature,
			",",
		)
	}

	c.Args = extensionswebhook.EnsureStringWithPrefixContains(
		c.Args,
		runtimeConfigArgPrefix,
		"certificates.k8s.io/v1beta1=true",
		",",
	)

	return nil
}

// EnsureKubeControllerManagerDeployment implements the [genericmutator.Ensurer]
// interface. It enables the required feature gates on the
// kube-controller-manager container of the given Deployment.
func (e *ensurer) EnsureKubeControllerManagerDeployment(ctx context.Context, gctx extensionswebhookctx.GardenContext, newObj, _ *appsv1.Deployment) error {
	skip, err := e.shouldSkip(ctx, gctx)
	if err != nil || skip {
		return err
	}

	if newObj == nil {
		return nil
	}

	c := extensionswebhook.ContainerWithName(newObj.Spec.Template.Spec.Containers, v1beta1constants.DeploymentNameKubeControllerManager)
	if c == nil {
		return nil
	}

	// Enable feature gates
	extensionswebhook.LogMutation(e.logger, newObj.Kind, newObj.Namespace, newObj.Name)
	for _, fg := range featureGates {
		feature := fmt.Sprintf("%s=true", fg)
		c.Command = extensionswebhook.EnsureStringWithPrefixContains(
			c.Command,
			featureGatesArgPrefix,
			feature,
			",",
		)
	}

	return nil
}

// EnsureKubeletConfiguration implements the [genericmutator.Ensurer]
// interface. It enables the required feature gates in the kubelet
// configuration.
func (e *ensurer) EnsureKubeletConfiguration(ctx context.Context, gctx extensionswebhookctx.GardenContext, _ *semver.Version, newObj, _ *kubeletconfigv1beta1.KubeletConfiguration) error {
	skip, err := e.shouldSkip(ctx, gctx)
	if err != nil || skip {
		return err
	}
	if newObj.FeatureGates == nil {
		newObj.FeatureGates = make(map[string]bool, len(featureGates))
	}
	for _, fg := range featureGates {
		newObj.FeatureGates[fg] = true
	}

	return nil
}

// shouldSkip is a predicate which returns true if the webhook should not
// mutate the current object. It returns true when the shoot is missing,
// being deleted, hibernated, or the extension is not enabled in the shoot
// spec. Cluster-lookup failures are returned to the caller as errors.
func (e *ensurer) shouldSkip(ctx context.Context, gctx extensionswebhookctx.GardenContext) (bool, error) {
	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to find cluster: %w", err)
	}

	if cluster.Shoot == nil {
		return true, nil
	}
	if cluster.Shoot.GetDeletionTimestamp() != nil {
		return true, nil
	}
	if v1beta1helper.HibernationIsEnabled(cluster.Shoot) {
		return true, nil
	}
	if !e.isExtensionEnabled(cluster.Shoot) {
		return true, nil
	}

	return false, nil
}

// isExtensionEnabled returns true if the extension is present and not
// explicitly disabled in the shoot spec.
func (e *ensurer) isExtensionEnabled(shoot *gardencorev1beta1.Shoot) bool {
	if shoot == nil {
		return false
	}

	idx := slices.IndexFunc(shoot.Spec.Extensions, func(ext gardencorev1beta1.Extension) bool {
		return ext.Type == e.extensionType
	})
	if idx == -1 {
		return false
	}
	if shoot.Spec.Extensions[idx].Disabled != nil && *shoot.Spec.Extensions[idx].Disabled {
		return false
	}

	return true
}

// NewWebhook returns a new mutating [extensionswebhook.Webhook] which enables
// the feature gates required by the pod-certificate-signer extension on the
// shoot's kube-apiserver, kube-controller-manager and kubelet.
func NewWebhook(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger := mgr.GetLogger()
	ens, err := newEnsurer(mgr.GetClient(), logger)
	if err != nil {
		return nil, err
	}

	name := fmt.Sprintf("ensurer.feature-gates.%s", ens.extensionType)
	extensionLabel := fmt.Sprintf("%s%s", v1beta1constants.LabelExtensionPrefix, ens.extensionType)
	path := fmt.Sprintf("/webhooks/ensurer/feature-gates/%s", ens.extensionType)
	logger.Info("setting up webhook", "name", name, "path", path, "label", extensionLabel)

	fciCodec := oscutils.NewFileContentInlineCodec()
	mutator := genericmutator.NewMutator(
		mgr,
		ens,
		oscutils.NewUnitSerializer(),
		kubelet.NewConfigCodec(fciCodec),
		fciCodec,
		logger,
	)

	objTypes := []extensionswebhook.Type{
		{Obj: &appsv1.Deployment{}},
		{Obj: &extensionsv1alpha1.OperatingSystemConfig{}},
	}

	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithMutator(mutator, objTypes...).Build()
	if err != nil {
		return nil, err
	}

	return &extensionswebhook.Webhook{
		Name:    name,
		Path:    path,
		Types:   objTypes,
		Target:  extensionswebhook.TargetSeed,
		Webhook: &admission.Webhook{Handler: handler},
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				extensionLabel: "true",
			},
		},
	}, nil
}
