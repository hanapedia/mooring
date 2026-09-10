package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NATConfigSpec struct {
	// ExternalIPPool is the list of external IP CIDRs available for SNAT.
	ExternalIPPool []string `json:"externalIPPool"`
	// DefaultPortRangeSize is the number of ports allocated per pod when
	// NATPortRangeRequest does not specify portRangeSize.
	DefaultPortRangeSize int32 `json:"defaultPortRangeSize"`
	// TargetCIDRs lists the destination CIDRs that trigger SNAT.
	TargetCIDRs []string `json:"targetCIDRs"`
	// PodSelector selects pods managed by this NATConfig.
	PodSelector metav1.LabelSelector `json:"podSelector"`
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
