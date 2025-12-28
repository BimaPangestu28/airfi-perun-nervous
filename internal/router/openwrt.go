// Package router provides WiFi router integration for access control.
package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// OpenWrtConfig holds the configuration for OpenWrt router with OpenNDS.
type OpenWrtConfig struct {
	Address     string // Router SSH address (e.g., "192.168.1.1")
	Port        int    // SSH port (default: 22)
	Username    string // SSH username (usually "root")
	Password    string // SSH password
	PrivateKey  string // SSH private key (alternative to password)
	AuthTimeout int    // Session timeout in seconds (0 = use OpenNDS default)
}

// OpenWrtClient handles communication with OpenWrt router running OpenNDS.
type OpenWrtClient struct {
	config    OpenWrtConfig
	sshConfig *ssh.ClientConfig
	logger    *zap.Logger
}

// NewOpenWrtClient creates a new OpenWrt/OpenNDS client.
func NewOpenWrtClient(config OpenWrtConfig, logger *zap.Logger) (*OpenWrtClient, error) {
	if config.Port == 0 {
		config.Port = 22
	}

	var authMethods []ssh.AuthMethod

	if config.Password != "" {
		authMethods = append(authMethods, ssh.Password(config.Password))
	}

	if config.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(config.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method provided (password or private key required)")
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For simplicity; use known_hosts in production
		Timeout:         10 * time.Second,
	}

	return &OpenWrtClient{
		config:    config,
		sshConfig: sshConfig,
		logger:    logger,
	}, nil
}

// AuthorizeMAC allows a MAC address to access the internet via OpenNDS.
func (c *OpenWrtClient) AuthorizeMAC(ctx context.Context, macAddress, ipAddress, comment string) error {
	c.logger.Info("authorizing MAC address via OpenNDS",
		zap.String("mac", macAddress),
		zap.String("ip", ipAddress),
	)

	// Normalize MAC address format (OpenNDS expects lowercase with colons)
	mac := normalizeMACAddress(macAddress)

	// Build ndsctl auth command
	// ndsctl auth <mac> [timeout_in_seconds]
	cmd := fmt.Sprintf("ndsctl auth %s", mac)
	if c.config.AuthTimeout > 0 {
		cmd = fmt.Sprintf("ndsctl auth %s %d", mac, c.config.AuthTimeout)
	}

	output, err := c.runSSHCommand(ctx, cmd)
	if err != nil {
		return fmt.Errorf("failed to authorize MAC: %w", err)
	}

	// Check for success
	if strings.Contains(output, "already authenticated") {
		c.logger.Info("MAC already authorized", zap.String("mac", mac))
		return nil
	}

	if strings.Contains(output, "authenticated") || strings.Contains(output, "Authenticated") {
		c.logger.Info("MAC authorized successfully", zap.String("mac", mac))
		return nil
	}

	// Check for client not found (not connected to WiFi yet)
	if strings.Contains(output, "not found") || strings.Contains(output, "Client not found") {
		return fmt.Errorf("client not connected to WiFi network (MAC not found in OpenNDS)")
	}

	c.logger.Warn("unexpected ndsctl output", zap.String("output", output))
	return nil
}

// DeauthorizeMAC removes a MAC address from the authorized list.
func (c *OpenWrtClient) DeauthorizeMAC(ctx context.Context, macAddress string) error {
	c.logger.Info("deauthorizing MAC address via OpenNDS", zap.String("mac", macAddress))

	mac := normalizeMACAddress(macAddress)
	cmd := fmt.Sprintf("ndsctl deauth %s", mac)

	output, err := c.runSSHCommand(ctx, cmd)
	if err != nil {
		// Not found is not an error for deauth
		if strings.Contains(err.Error(), "not found") {
			c.logger.Info("MAC not found (already deauthorized)", zap.String("mac", mac))
			return nil
		}
		return fmt.Errorf("failed to deauthorize MAC: %w", err)
	}

	if strings.Contains(output, "not found") || strings.Contains(output, "Client not found") {
		c.logger.Info("MAC not found (already deauthorized)", zap.String("mac", mac))
		return nil
	}

	c.logger.Info("MAC deauthorized successfully", zap.String("mac", mac))
	return nil
}

// TestConnection tests the connection to the OpenWrt router.
func (c *OpenWrtClient) TestConnection(ctx context.Context) error {
	// Try to run ndsctl status to verify OpenNDS is running
	output, err := c.runSSHCommand(ctx, "ndsctl status")
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	// Check if OpenNDS is running
	if strings.Contains(output, "openNDS") || strings.Contains(output, "Version") {
		c.logger.Info("OpenNDS connection test successful")
		return nil
	}

	// Try alternative check
	output, err = c.runSSHCommand(ctx, "pgrep opennds || pgrep nodogsplash")
	if err == nil && output != "" {
		c.logger.Info("OpenNDS/NoDogSplash process found")
		return nil
	}

	return fmt.Errorf("OpenNDS does not appear to be running")
}

// ListAuthenticatedClients returns all currently authenticated clients.
func (c *OpenWrtClient) ListAuthenticatedClients(ctx context.Context) ([]string, error) {
	output, err := c.runSSHCommand(ctx, "ndsctl json")
	if err != nil {
		return nil, err
	}

	// For now, just return raw output
	// In production, parse the JSON to extract MAC addresses
	c.logger.Debug("authenticated clients", zap.String("output", output))

	return nil, nil
}

// GetClientStatus checks if a MAC address is authenticated.
func (c *OpenWrtClient) GetClientStatus(ctx context.Context, macAddress string) (bool, error) {
	mac := normalizeMACAddress(macAddress)
	output, err := c.runSSHCommand(ctx, "ndsctl json")
	if err != nil {
		return false, err
	}

	// Simple check - look for MAC in output
	return strings.Contains(strings.ToLower(output), strings.ToLower(mac)), nil
}

// runSSHCommand executes a command on the router via SSH.
func (c *OpenWrtClient) runSSHCommand(ctx context.Context, cmd string) (string, error) {
	addr := net.JoinHostPort(c.config.Address, fmt.Sprintf("%d", c.config.Port))

	client, err := ssh.Dial("tcp", addr, c.sshConfig)
	if err != nil {
		return "", fmt.Errorf("SSH connection failed: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		// Check if it's just a non-zero exit code with useful output
		if len(output) > 0 {
			return string(output), nil
		}
		return "", fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// normalizeMACAddress converts MAC address to lowercase colon-separated format.
func normalizeMACAddress(mac string) string {
	// Remove any existing separators
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ".", "")
	mac = strings.ToLower(mac)

	// Insert colons
	if len(mac) == 12 {
		return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			mac[0:2], mac[2:4], mac[4:6],
			mac[6:8], mac[8:10], mac[10:12])
	}

	return mac
}
