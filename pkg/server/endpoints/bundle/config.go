package bundle

import (
	"net"
	"time"
)

type EndpointConfig struct {
	// Address is the address on which to serve the federation bundle endpoint.
	Address *net.TCPAddr

	Web    *WebProfile
	SPIFFE *SPIFFEProfile

	RefreshHint *time.Duration
}

type WebProfile struct {
	ACME *ACMEConfig
}

type SPIFFEProfile struct {
}
