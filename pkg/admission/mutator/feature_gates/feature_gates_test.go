// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package feature_gates

import (
	"context"
	"slices"
	"strings"
	"testing"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	podcertificatesigneractuator "github.com/gardener/gardener-extension-pcs/pkg/actuator/podcertificatesigner"
)

func TestFeatureGatesEnsurer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "feature_gates Ensurer Suite")
}

// shootWithExtension returns a Shoot whose spec has the
// pod-certificate-signer extension enabled.
func shootWithExtension() *gardencorev1beta1.Shoot {
	return &gardencorev1beta1.Shoot{
		Spec: gardencorev1beta1.ShootSpec{
			Extensions: []gardencorev1beta1.Extension{
				{Type: podcertificatesigneractuator.ExtensionType},
			},
		},
	}
}

func gardenContextFor(shoot *gardencorev1beta1.Shoot) gcontext.GardenContext {
	return gcontext.NewInternalGardenContext(&extensionscontroller.Cluster{Shoot: shoot})
}

// containsAllRequiredFeatureGates is a Gomega matcher that succeeds when
// the actual []string contains a single `--feature-gates=...` arg whose
// comma-separated value sets every entry of `featureGates` to `=true`.
func containsAllRequiredFeatureGates() types.GomegaMatcher {
	return &requiredGatesMatcher{}
}

type requiredGatesMatcher struct {
	actualValue string
}

func (m *requiredGatesMatcher) Match(actual any) (bool, error) {
	args, ok := actual.([]string)
	if !ok {
		return false, nil
	}
	for _, a := range args {
		if !strings.HasPrefix(a, featureGatesArgPrefix) {
			continue
		}
		m.actualValue = strings.TrimPrefix(a, featureGatesArgPrefix)
		entries := strings.Split(m.actualValue, ",")
		for _, fg := range featureGates {
			if !slices.Contains(entries, fg+"=true") {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

func (m *requiredGatesMatcher) FailureMessage(actual any) string {
	return "expected the args to contain a single --feature-gates= arg with all required gates set to true; got: " + m.actualValue
}

func (m *requiredGatesMatcher) NegatedFailureMessage(actual any) string {
	return "did not expect the args to contain --feature-gates= with all required gates"
}

var _ = Describe("Ensurer", func() {
	var (
		ctx     = context.TODO()
		ensurer *ensurer
	)

	BeforeEach(func() {
		c := fakeclient.NewClientBuilder().Build()
		var err error
		ensurer, err = newEnsurer(c, logf.Log)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("#EnsureKubeAPIServerDeployment", func() {
		var dep *appsv1.Deployment

		BeforeEach(func() {
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.DeploymentNameKubeAPIServer, Namespace: "shoot--test"},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{
								Name:    v1beta1constants.DeploymentNameKubeAPIServer,
								Command: []string{"/usr/local/bin/kube-apiserver"},
								Args:    []string{"--allow-privileged=true"},
							}},
						},
					},
				},
			}
		})

		It("adds the --feature-gates arg when none is present", func() {
			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c := dep.Spec.Template.Spec.Containers[0]
			Expect(c.Args).To(containsAllRequiredFeatureGates())
		})

		It("enables the certificates.k8s.io/v1beta1 API group via --runtime-config", func() {
			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c := dep.Spec.Template.Spec.Containers[0]
			Expect(c.Args).To(ContainElement("--runtime-config=certificates.k8s.io/v1beta1=true"))
		})

		It("appends missing gates to an existing --feature-gates arg", func() {
			c := &dep.Spec.Template.Spec.Containers[0]
			c.Args = append(c.Args, featureGatesArgPrefix+"FooBar=true")

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c2 := dep.Spec.Template.Spec.Containers[0]
			Expect(c2.Args).To(containsAllRequiredFeatureGates())
			// Pre-existing entry must survive.
			Expect(c2.Args).To(ContainElement(ContainSubstring("FooBar=true")))
		})

		It("forces our gates to true even when the operator set one to false (last-wins via the kube parser)", func() {
			c := &dep.Spec.Template.Spec.Containers[0]
			c.Args = append(c.Args, featureGatesArgPrefix+"PodCertificateRequest=false")

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c2 := dep.Spec.Template.Spec.Containers[0]
			var fg string
			for _, a := range c2.Args {
				if after, ok := strings.CutPrefix(a, featureGatesArgPrefix); ok {
					fg = after
				}
			}
			// The pre-existing =false stays in place; our =true is appended
			// after it. The kube-apiserver flag parser uses last-wins per
			// key, so the effective value is true.
			parts := strings.Split(fg, ",")
			Expect(parts).To(ContainElement("PodCertificateRequest=true"))
			Expect(parts).To(ContainElement("ClusterTrustBundle=true"))
			Expect(parts).To(ContainElement("ClusterTrustBundleProjection=true"))
			lastIdxFalse := slices.Index(parts, "PodCertificateRequest=false")
			lastIdxTrue := slices.Index(parts, "PodCertificateRequest=true")
			if lastIdxFalse >= 0 {
				Expect(lastIdxTrue).To(BeNumerically(">", lastIdxFalse))
			}
		})

		It("is a no-op when the named container is missing", func() {
			dep.Spec.Template.Spec.Containers[0].Name = "something-else"

			Expect(ensurer.EnsureKubeAPIServerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c := dep.Spec.Template.Spec.Containers[0]
			Expect(c.Args).NotTo(ContainElement(ContainSubstring("--feature-gates=")))
			Expect(c.Command).NotTo(ContainElement(ContainSubstring("--feature-gates=")))
		})
	})

	Describe("#EnsureKubeControllerManagerDeployment", func() {
		var dep *appsv1.Deployment

		BeforeEach(func() {
			// Gardener's KCM puts every flag inline in Command, with Args nil.
			// The Ensurer mutates Command to match.
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: v1beta1constants.DeploymentNameKubeControllerManager, Namespace: "shoot--test"},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{
								Name: v1beta1constants.DeploymentNameKubeControllerManager,
								Command: []string{
									"/usr/local/bin/kube-controller-manager",
									"--allocate-node-cidrs=true",
								},
							}},
						},
					},
				},
			}
		})

		It("appends a --feature-gates arg to Command", func() {
			Expect(ensurer.EnsureKubeControllerManagerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c := dep.Spec.Template.Spec.Containers[0]
			Expect(c.Command).To(containsAllRequiredFeatureGates())
			// Args must remain untouched -- mutating both would duplicate the
			// flag in argv on every reconcile.
			Expect(c.Args).NotTo(ContainElement(ContainSubstring(featureGatesArgPrefix)))
		})

		It("merges into a --feature-gates flag that already lives in Command (last-wins per key)", func() {
			c := &dep.Spec.Template.Spec.Containers[0]
			c.Command = append(c.Command, featureGatesArgPrefix+"PodCertificateRequest=false")

			Expect(ensurer.EnsureKubeControllerManagerDeployment(ctx, gardenContextFor(shootWithExtension()), dep, nil)).To(Succeed())

			c2 := dep.Spec.Template.Spec.Containers[0]
			// The pre-existing entry stays in place; our =true is appended to
			// the same comma-separated list. The kube parser uses last-wins
			// per key, so the effective value is true.
			var fg string
			for _, a := range c2.Command {
				if after, ok := strings.CutPrefix(a, featureGatesArgPrefix); ok {
					fg = after
				}
			}
			parts := strings.Split(fg, ",")
			Expect(parts).To(ContainElement("PodCertificateRequest=true"))
			Expect(parts).To(ContainElement("ClusterTrustBundle=true"))
			Expect(parts).To(ContainElement("ClusterTrustBundleProjection=true"))
			lastIdxFalse := slices.Index(parts, "PodCertificateRequest=false")
			lastIdxTrue := slices.Index(parts, "PodCertificateRequest=true")
			if lastIdxFalse >= 0 {
				Expect(lastIdxTrue).To(BeNumerically(">", lastIdxFalse))
			}
		})
	})

	Describe("#EnsureKubeletConfiguration", func() {
		It("enables all required feature gates in the kubelet config", func() {
			cfg := &kubeletconfigv1beta1.KubeletConfiguration{}

			Expect(ensurer.EnsureKubeletConfiguration(ctx, gardenContextFor(shootWithExtension()), nil, cfg, nil)).To(Succeed())

			Expect(cfg.FeatureGates).NotTo(BeNil())
			for _, fg := range featureGates {
				Expect(cfg.FeatureGates).To(HaveKeyWithValue(fg, true))
			}
		})

		It("does not overwrite operator-set values", func() {
			cfg := &kubeletconfigv1beta1.KubeletConfiguration{
				FeatureGates: map[string]bool{
					"PodCertificateRequest": false,
				},
			}

			Expect(ensurer.EnsureKubeletConfiguration(ctx, gardenContextFor(shootWithExtension()), nil, cfg, nil)).To(Succeed())

			// We currently overwrite kubelet-config gates to true unconditionally
			// (the kubelet config is a typed map, not a CLI-arg merge). If we
			// later decide to mirror the CLI-arg "preserve operator value"
			// semantics here, this assertion will need to flip.
			Expect(cfg.FeatureGates).To(HaveKeyWithValue("PodCertificateRequest", true))
			Expect(cfg.FeatureGates).To(HaveKeyWithValue("ClusterTrustBundle", true))
			Expect(cfg.FeatureGates).To(HaveKeyWithValue("ClusterTrustBundleProjection", true))
		})
	})

	Describe("#shouldSkip", func() {
		It("skips when the cluster has no Shoot object", func() {
			gctx := gcontext.NewInternalGardenContext(&extensionscontroller.Cluster{})
			skip, err := ensurer.shouldSkip(ctx, gctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(skip).To(BeTrue())
		})

		It("skips when the Shoot is being deleted", func() {
			shoot := shootWithExtension()
			now := metav1.Now()
			shoot.SetDeletionTimestamp(&now)

			skip, err := ensurer.shouldSkip(ctx, gardenContextFor(shoot))
			Expect(err).NotTo(HaveOccurred())
			Expect(skip).To(BeTrue())
		})

		It("skips when the Shoot is hibernated", func() {
			shoot := shootWithExtension()
			shoot.Spec.Hibernation = &gardencorev1beta1.Hibernation{Enabled: new(true)}

			skip, err := ensurer.shouldSkip(ctx, gardenContextFor(shoot))
			Expect(err).NotTo(HaveOccurred())
			Expect(skip).To(BeTrue())
		})

		It("skips when the extension is not enabled in the Shoot spec", func() {
			shoot := &gardencorev1beta1.Shoot{}

			skip, err := ensurer.shouldSkip(ctx, gardenContextFor(shoot))
			Expect(err).NotTo(HaveOccurred())
			Expect(skip).To(BeTrue())
		})

		It("skips when the extension is explicitly disabled", func() {
			shoot := shootWithExtension()
			shoot.Spec.Extensions[0].Disabled = new(true)

			skip, err := ensurer.shouldSkip(ctx, gardenContextFor(shoot))
			Expect(err).NotTo(HaveOccurred())
			Expect(skip).To(BeTrue())
		})

		It("does not skip when the Shoot is healthy and the extension is enabled", func() {
			skip, err := ensurer.shouldSkip(ctx, gardenContextFor(shootWithExtension()))
			Expect(err).NotTo(HaveOccurred())
			Expect(skip).To(BeFalse())
		})
	})
})
