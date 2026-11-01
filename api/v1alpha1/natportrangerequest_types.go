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
	// ExcludePorts lists this pod's own declared container ports (set once by
	// the daemon from the pod's spec at NPRR creation time, not operator-authored).
	// Each listed port's containing block is excluded from this pod's own
	// allocation only, so a NAT-allocated port can't land on one of the pod's
	// own listeners.
	// +optional
	ExcludePorts []int32 `json:"excludePorts,omitempty"`
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
