// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package podcertificatesigner

import (
	"fmt"
	"time"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/component/kubernetes/apiserver/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/utils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	imagevectorutils "github.com/gardener/gardener/pkg/utils/imagevector"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	appsv1 "k8s.io/api/apps/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// baseResourceName is the base name for resources created by the [Actuator].
	baseResourceName = "pod-certificate-signer"

	// shootResourceName is the name of the ClusterRole and
	// ClusterRoleBinding deployed into the shoot cluster for the signer.
	shootResourceName = "extension.gardener.cloud:" + baseResourceName

	// shootResourceSetName is the name of the ManagedResource which carries
	// the shoot-side resources reconciled by gardener-resource-manager.
	shootResourceSetName = baseResourceName + "-shoot"

	// shootServiceAccountName is the name of the ServiceAccount in the
	// shoot's kube-system namespace whose token the signer assumes when
	// talking to the shoot kube-apiserver. The shoot-access secret in the
	// seed CP namespace is reconciled by gardener-resource-manager to this
	// ServiceAccount.
	shootServiceAccountName = baseResourceName

	// metricsPort is the port on which the pod-certificate-signer exposes
	// its metrics.
	metricsPort int32 = 8080

	// healthProbePort is the port for the health probe.
	healthProbePort int32 = 8081

	// secretNameCACert is the name of the CA certificate secret, which will
	// be used by the pod-certificate-signer.
	secretNameCACert = "ca-" + Name

	// signerMaxOldCerts is the value passed to the signer's
	// --signer-max-old-certs flag.
	signerMaxOldCerts = 2

	// signerDefaultLifetime is the default lifetime of certificates issued
	// by the signer when the requester does not pin one.
	signerDefaultLifetime = 7 * 24 * time.Hour

	// signerLogLevel is the log level of the signer pod.
	signerLogLevel = "info"

	// signerLogFormat is the log format of the signer pod.
	signerLogFormat = "text"

	// signerMaxConcurrentReconciles is the value passed to the signer's
	// --max-concurrent-reconciles flag.
	signerMaxConcurrentReconciles = 5
)

// getCommonLabels returns the common set of labels used for the resources
// created by the [Actuator].
func (a *Actuator) getCommonLabels() map[string]string {
	items := map[string]string{
		"app.kubernetes.io/name":             a.Name(),
		v1beta1constants.GardenRoleExtension: a.Name(),
	}

	return items
}

// getNetworkLabels returns the set of labels related to Gardener Network
// Policies. The signer pod runs in the seed shoot control-plane namespace
// and needs egress to:
//   - DNS (always),
//   - the runtime/seed kube-apiserver (for the in-cluster leader-election lease),
//   - the shoot kube-apiserver on tcp/443 (for reconciling PodCertificateRequests).
func (a *Actuator) getNetworkLabels() map[string]string {
	items := map[string]string{
		v1beta1constants.LabelNetworkPolicyToDNS:                                                                    v1beta1constants.LabelNetworkPolicyAllowed,
		v1beta1constants.LabelNetworkPolicyToRuntimeAPIServer:                                                       v1beta1constants.LabelNetworkPolicyAllowed,
		gardenerutils.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
	}

	return items
}

// getSignerName returns the name of the signer for the given namespace.
func (a *Actuator) getSignerName(namespace string) string {
	// TODO(dnaeon): use the const from Gardener
	return fmt.Sprintf("certificates.gardener.cloud/%s", namespace)
}

// getSeedServiceAccount returns the [corev1.ServiceAccount] used by the signer
// pod in the seed.
func (a *Actuator) getSeedServiceAccount(namespace string) *corev1.ServiceAccount {
	obj := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseResourceName,
			Namespace: namespace,
			Labels:    a.getCommonLabels(),
		},
		AutomountServiceAccountToken: new(false),
	}

	return obj
}

// getShootClusterRole returns the [rbacv1.ClusterRole] that grants the signer
// the permissions it needs in the shoot cluster in order to reconcile
// PodCertificateRequest and ClusterTrustBundle resources, and to sign with
// our signer name.
func (a *Actuator) getShootClusterRole(seedNamespace string) *rbacv1.ClusterRole {
	obj := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   shootResourceName,
			Labels: a.getCommonLabels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{corev1.GroupName, eventsv1.GroupName},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
			{
				APIGroups: []string{corev1.GroupName},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{certificatesv1beta1.GroupName},
				Resources: []string{"podcertificaterequests"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{certificatesv1beta1.GroupName},
				Resources: []string{"podcertificaterequests/status"},
				Verbs:     []string{"patch"},
			},
			{
				APIGroups: []string{certificatesv1beta1.GroupName},
				Resources: []string{"clustertrustbundles"},
				Verbs:     []string{"get", "create", "update", "patch"},
			},
			{
				APIGroups:     []string{certificatesv1beta1.GroupName},
				Resources:     []string{"signers"},
				ResourceNames: []string{a.getSignerName(seedNamespace)},
				Verbs:         []string{"sign", "attest"},
			},
		},
	}

	return obj
}

// getShootClusterRoleBinding returns the [rbacv1.ClusterRoleBinding] that binds
// [Actuator.getShootClusterRole] to the shoot service account assumed by the signer.
func (a *Actuator) getShootClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	obj := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   shootResourceName,
			Labels: a.getCommonLabels(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      shootServiceAccountName,
				Namespace: metav1.NamespaceSystem,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     shootResourceName,
		},
	}

	return obj
}

// getSeedRole returns the [rbacv1.Role] that grants the signer's seed
// ServiceAccount the namespaced permissions it needs in the shoot control-plane
// namespace on the seed cluster.
func (a *Actuator) getSeedRole(namespace string) *rbacv1.Role {
	obj := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseResourceName,
			Namespace: namespace,
			Labels:    a.getCommonLabels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "delete", "patch"},
			},
			{
				APIGroups: []string{corev1.GroupName, eventsv1.GroupName},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
		},
	}

	return obj
}

// getSeedRoleBinding returns the [rbacv1.RoleBinding] which binds the role from
// [Actuator.getSeedRole] to the ServiceAccount from
// [Actuator.getSeedServiceAccount].
func (a *Actuator) getSeedRoleBinding(namespace string) *rbacv1.RoleBinding {
	obj := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseResourceName,
			Namespace: namespace,
			Labels:    a.getCommonLabels(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      baseResourceName,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     baseResourceName,
		},
	}

	return obj
}

// getService returns the [corev1.Service] managed by the [Actuator] for
// metrics scraping.
func (a *Actuator) getService(namespace string) *corev1.Service {
	obj := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseResourceName,
			Namespace: namespace,
			Labels:    a.getCommonLabels(),
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: a.getCommonLabels(),
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics",
					Port:       metricsPort,
					TargetPort: intstr.FromInt32(metricsPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	return obj
}

// getDeployment returns the [appsv1.Deployment] managed by the [Actuator].  The
// pod runs in the shoot control-plane namespace on the seed, but talks to the
// shoot kube-apiserver via the generic-token-kubeconfig + shoot access token
// mounted by gardener-resource-manager.
//
// The caller is responsible for injecting the generic kubeconfig into the
// returned Deployment via [gardenerutils.InjectGenericKubeconfig].
func (a *Actuator) getDeployment(namespace string, image *imagevectorutils.Image, caSecret *corev1.Secret) *appsv1.Deployment {
	allLabels := utils.MergeStringMaps(a.getCommonLabels(), a.getNetworkLabels())

	obj := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseResourceName,
			Namespace: namespace,
			Labels:    a.getCommonLabels(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             new(int32(1)),
			RevisionHistoryLimit: new(int32(2)),
			Selector: &metav1.LabelSelector{
				MatchLabels: allLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: allLabels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:           baseResourceName,
					AutomountServiceAccountToken: new(true),
					Containers: []corev1.Container{
						{
							Image:           image.String(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Name:            "signer",
							Command: []string{
								"/manager",
								"--leader-election=true",
								fmt.Sprintf("--signer-max-old-certs=%d", signerMaxOldCerts),
								fmt.Sprintf("--default-lifetime=%s", signerDefaultLifetime),
								fmt.Sprintf("--log-level=%s", signerLogLevel),
								fmt.Sprintf("--log-format=%s", signerLogFormat),
								fmt.Sprintf("--max-concurrent-reconciles=%d", signerMaxConcurrentReconciles),
								fmt.Sprintf("--reconciliation-timeout=%s", controllerutils.DefaultReconciliationTimeout),
								fmt.Sprintf("--signer-cert-path=/app/signer/ca/%s", secretsutils.DataKeyCertificateCA),
								fmt.Sprintf("--signer-key-path=/app/signer/ca/%s", secretsutils.DataKeyPrivateKeyCA),
								fmt.Sprintf("--leader-election-id=%s", baseResourceName),
								fmt.Sprintf("--leader-election-namespace=%s", namespace),
								fmt.Sprintf("--signer-name=%s", a.getSignerName(namespace)),
								fmt.Sprintf("--health-probe-bind-address=:%d", healthProbePort),
								fmt.Sprintf("--metrics-bind-address=:%d", metricsPort),
								fmt.Sprintf("--kubeconfig=%s", gardenerutils.PathGenericKubeconfig),
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "metrics",
									ContainerPort: metricsPort,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "health",
									ContainerPort: healthProbePort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromString("health"),
									},
								},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstr.FromString("health"),
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									ReadOnly:  true,
									Name:      "ca-cert",
									MountPath: "/app/signer/ca",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: caSecret.Name,
								},
							},
						},
					},
				},
			},
		},
	}

	return obj
}
