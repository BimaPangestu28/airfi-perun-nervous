// Package router provides WiFi router integration for access control.
package router

import "context"

// Router defines the interface for WiFi access control.
type Router interface {
	// AuthorizeMAC allows a MAC address to access the internet.
	AuthorizeMAC(ctx context.Context, macAddress, ipAddress, comment string) error

	// DeauthorizeMAC removes a MAC address from the authorized list.
	DeauthorizeMAC(ctx context.Context, macAddress string) error

	// TestConnection tests the connection to the router.
	TestConnection(ctx context.Context) error
}

// NoopRouter is a no-op router for testing or when no router is configured.
type NoopRouter struct{}

// AuthorizeMAC does nothing.
func (r *NoopRouter) AuthorizeMAC(ctx context.Context, macAddress, ipAddress, comment string) error {
	return nil
}

// DeauthorizeMAC does nothing.
func (r *NoopRouter) DeauthorizeMAC(ctx context.Context, macAddress string) error {
	return nil
}

// TestConnection always succeeds.
func (r *NoopRouter) TestConnection(ctx context.Context) error {
	return nil
}
