// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package podcertificatesigner

import (
	"fmt"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/utils"
	imagevectorutils "github.com/gardener/gardener/pkg/utils/imagevector"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	appsv1 "k8s.io/api/apps/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// baseResourceName is the base name for resources created by the [Actuator].
	baseResourceName = "pod-certificate-signer"

	// metricsPort is the port on which the pod-certificate-signer exposes
	// its metrics.
	metricsPort int32 = 8080

	// healthProbePort is the port for the health probe.
	healthProbePort int32 = 8081

	// secretNameCACert is the name of the CA certificate secret, which will
	// be used by the pod-certificate-signer.
	secretNameCACert = "ca-" + Name
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
// Policies.
func (a *Actuator) getNetworkLabels() map[string]string {
	items := map[string]string{
		v1beta1constants.LabelNetworkPolicyToDNS:              v1beta1constants.LabelNetworkPolicyAllowed,
		v1beta1constants.LabelNetworkPolicyToRuntimeAPIServer: v1beta1constants.LabelNetworkPolicyAllowed,
	}

	return items
}

// getSignerName returns the name of the signer for the given namespace.
func (a *Actuator) getSignerName(namespace string) string {
	return fmt.Sprintf("certificates.gardener.cloud/%s", namespace)
}

// getServiceAccount returns the [corev1.ServiceAccount] managed by the [Actuator].
func (a *Actuator) getServiceAccount(namespace string) *corev1.ServiceAccount {
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

// getRole returns the [rbacv1.Role] managed by the [Actuator].
func (a *Actuator) getRole(namespace string) *rbacv1.Role {
	obj := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      baseResourceName,
			Namespace: namespace,
			Labels:    a.getCommonLabels(),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{coordinationv1.GroupName},
				Resources: []string{"leases"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "delete", "patch"},
			},
		},
	}

	return obj
}

// getRoleBinding returns the [rbacv1.RoleBinding] managed by the [Actuator].
func (a *Actuator) getRoleBinding(namespace string) *rbacv1.RoleBinding {
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

// getClusterRole returns the [rbacv1.ClusterRole] managed by the [Actuator].
func (a *Actuator) getClusterRole(namespace string) *rbacv1.ClusterRole {
	obj := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   baseResourceName,
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
				APIGroups: []string{certificatesv1.GroupName},
				Resources: []string{"podcertificaterequests"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{certificatesv1.GroupName},
				Resources: []string{"podcertificaterequests/status"},
				Verbs:     []string{"patch"},
			},
			{
				APIGroups: []string{certificatesv1.GroupName},
				Resources: []string{"clustertrustbundles"},
				Verbs:     []string{"get", "create", "update", "patch"},
			},
			{
				APIGroups:     []string{certificatesv1.GroupName},
				Resources:     []string{"signers"},
				ResourceNames: []string{a.getSignerName(namespace)},
				Verbs:         []string{"sign", "attest"},
			},
		},
	}

	return obj
}

// getClusterRoleBinding returns the [rbacv1.ClusterRoleBinding] managed by the
// [Actuator].
func (a *Actuator) getClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	obj := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   baseResourceName,
			Labels: a.getCommonLabels(),
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
			Kind:     "ClusterRole",
			Name:     baseResourceName,
		},
	}

	return obj
}

// getService returns the [corev1.Service] managed by the [Actuator].
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

// getDeployment returns the [appsv1.Deployment] managed by the [Actuator].
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
								"--signer-max-old-certs=2",
								"--default-lifetime=24h",
								"--log-level=info",
								"--log-format=text",
								"--max-concurrent-reconciles=5",
								"--reconciliation-timeout=3m",
								fmt.Sprintf("--signer-cert-path=/app/signer/ca/%s", secretsutils.DataKeyCertificateCA),
								fmt.Sprintf("--signer-key-path=/app/signer/ca/%s", secretsutils.DataKeyPrivateKeyCA),
								fmt.Sprintf("--leader-election-id=%s", baseResourceName),
								fmt.Sprintf("--leader-election-namespace=%s", namespace),
								fmt.Sprintf("--signer-name=%s", a.getSignerName(namespace)),
								fmt.Sprintf("--health-probe-bind-address=:%d", healthProbePort),
								fmt.Sprintf("--metrics-bind-address=:%d", metricsPort),
								fmt.Sprintf("--watch-namespaces=%s", namespace),
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
