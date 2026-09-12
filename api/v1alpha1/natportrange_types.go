package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PortAllocation struct {
	ExternalIP string `json:"externalIP"`
	PortStart  int32  `json:"portStart"`
	PortEnd    int32  `json:"portEnd"`
}

type NATPortRangeSpec struct {
	PodName      string           `json:"podName"`
	PodNamespace string           `json:"podNamespace"`
	PodIP        string           `json:"podIP"`
	NodeName     string           `json:"nodeName"`
	NATConfig    string           `json:"natConfig"`
	// TargetCIDRs mirrors NATConfig.Spec.TargetCIDRs so the daemon sync
	// controller can key snat_config entries by (podIP, targetCIDR) without
	// fetching the NATConfig on every reconcile.
	TargetCIDRs  []string         `json:"targetCIDRs"`
	// PortRangeCount mirrors NATPortRangeRequest.Spec.PortRangeCount so the
	// NATConfig controller can read it without looking up the request.
	PortRangeCount int32          `json:"portRangeCount"`
	Allocations    []PortAllocation `json:"allocations"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

type NATPortRange struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NATPortRangeSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

type NATPortRangeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NATPortRange `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NATPortRange{}, &NATPortRangeList{})
}
