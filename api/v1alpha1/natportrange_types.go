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
	PodName      string          `json:"podName"`
	PodNamespace string          `json:"podNamespace"`
	PodIP        string          `json:"podIP"`
	NodeName     string          `json:"nodeName"`
	NATConfig    string          `json:"natConfig"`
	Allocations  []PortAllocation `json:"allocations"`
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
