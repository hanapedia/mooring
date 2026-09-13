// +groupName=hanapedia.link

//go:generate go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.22.0 object paths="./..." crd output:crd:artifacts:config=../../manifests/crds

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "hanapedia.link", Version: "v1alpha1"}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)
