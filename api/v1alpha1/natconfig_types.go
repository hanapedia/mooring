package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NATConfigSpec struct {
	// ExternalIPPool is the list of external IP CIDRs available for SNAT.
	ExternalIPPool []string `json:"externalIPPool"`
	// PortRangeSize is the fixed number of ports per allocation block.
	// All pods under this NATConfig use the same block size.
	PortRangeSize int32 `json:"portRangeSize"`
	// TargetCIDRs lists the destination CIDRs that trigger SNAT.
	TargetCIDRs []string `json:"targetCIDRs"`
	// ReservedPorts lists individual ports this NATConfig's allocator must
	// never hand out. Each listed port's containing block is excluded from
	// allocation on every external IP in the pool. An already-allocated
	// block is not revoked by adding its port here; removing a port from
	// this list makes its block allocatable again.
	// +optional
	ReservedPorts []int32 `json:"reservedPorts,omitempty"`
	// PodSelector selects pods managed by this NATConfig.
	PodSelector metav1.LabelSelector `json:"podSelector"`
	// NodeSelector selects nodes that should advertise the return path via BGP.
	// If not specified, all nodes advertise.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type NATConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NATConfigSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

type NATConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NATConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NATConfig{}, &NATConfigList{})
}
