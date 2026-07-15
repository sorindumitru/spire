//go:build !windows

package k8sresource

func getDefaultTokenPath() string {
	return defaultTokenPath
}
