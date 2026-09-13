package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NATPortRangeRequestSpec struct {
	PodName      string `json:"podName"`
	PodNamespace string `json:"podNamespace"`
	PodIP        string `json:"podIP"`
	NodeName     string `json:"nodeName"`
	NATConfig    string `json:"natConfig"`
	// PortRangeCount is the number of fixed-size blocks to allocate per external IP.
	// Defaults to 1 if unset.
	PortRangeCount *int32 `json:"portRangeCount,omitempty"`
}

type NATPortRangeRequestStatus struct {
	// DeletionGracePeriodExpiry is set by the daemon when the pod is deleted.
	// The daemon waits until this time before removing the NATPortRangeRequest.
	DeletionGracePeriodExpiry *metav1.Time `json:"deletionGracePeriodExpiry,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=".spec.nodeName"

type NATPortRangeRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NATPortRangeRequestSpec   `json:"spec,omitempty"`
	Status NATPortRangeRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type NATPortRangeRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NATPortRangeRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NATPortRangeRequest{}, &NATPortRangeRequestList{})
}
