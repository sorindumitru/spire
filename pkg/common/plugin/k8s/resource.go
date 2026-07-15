package k8s

// RequestedResource describes a single Kubernetes access check that the
// k8s_resource node attestor agent asks the server to verify against the
// agent's service account via the SubjectAccessReview API. The fields mirror
// authorizationv1.ResourceAttributes.
type RequestedResource struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb,omitempty"`
	Group       string `json:"group,omitempty"`
	Version     string `json:"version,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// ResourceAttestationData is the attestation payload sent by the k8s_resource
// agent plugin. It carries the projected service account token (as in
// PSATAttestationData) plus the list of resources the agent's service account
// must be authorized to access for attestation to succeed.
type ResourceAttestationData struct {
	Cluster   string              `json:"cluster"`
	Token     string              `json:"token"`
	Resources []RequestedResource `json:"resources"`
}
