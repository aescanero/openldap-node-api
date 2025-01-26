package ldap

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap"
)

type LDAPConfig struct {
	Host     string
	Port     int
	BindDN   string
	BindPass string
	BaseDN   string
	UseSSL   bool
}

// LDAPClient maneja la conexión con el servidor LDAP
type LDAPClient struct {
	Config *LDAPConfig
	conn   *ldap.Conn
}

// NewLDAPClient crea una nueva instancia de LDAPClient
func NewLDAPClient(config *LDAPConfig) *LDAPClient {
	return &LDAPClient{
		Config: config,
	}
}

// Connect establece la conexión con el servidor LDAP
func (c *LDAPClient) Connect() error {
	var err error
	address := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)

	if c.Config.UseSSL {
		c.conn, err = ldap.DialTLS("tcp", address, &tls.Config{InsecureSkipVerify: true})
	} else {
		c.conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %v", err)
	}

	// Realizar bind con las credenciales proporcionadas
	err = c.conn.Bind(c.Config.BindDN, c.Config.BindPass)
	if err != nil {
		return fmt.Errorf("failed to bind with LDAP server: %v", err)
	}

	return nil
}

// Close cierra la conexión LDAP
func (c *LDAPClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
