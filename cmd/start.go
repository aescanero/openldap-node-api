/*Copyright [2023] [Alejandro Escanero Blanco <aescanero@disasterproject.com>]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.*/

package cmd

import (
	"log"
	"os"
	"strconv"

	"github.com/aescanero/openldap-node-api/api"
	"github.com/aescanero/openldap-node-api/internal/ldap"
	"github.com/spf13/cobra"
)

var ()

func init() {

}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Openldap Node",
	Long:  `Start Openldap Node`,
	Run: func(cmd *cobra.Command, args []string) {
		ldapPort := 389
		if portStr := os.Getenv("LDAP_PORT"); portStr != "" {
			if port, err := strconv.Atoi(portStr); err == nil {
				ldapPort = port
			}
		}

		ldapConfig := &ldap.LDAPConfig{
			Host:     os.Getenv("LDAP_HOST"),
			Port:     ldapPort, // o usar os.Getenv para hacerlo configurable
			BindDN:   os.Getenv("LDAP_BIND_DN"),
			BindPass: os.Getenv("LDAP_BIND_PASS"),
			BaseDN:   os.Getenv("LDAP_BASE_DN"),
			UseSSL:   os.Getenv("LDAP_USE_SSL") == "true",
		}

		// Configuración de autenticación
		authConfig := &api.AuthConfig{
			DexIssuer:      os.Getenv("DEX_ISSUER"),
			JWKSEndpoint:   os.Getenv("DEX_JWKS_ENDPOINT"),
			AdminGroupName: os.Getenv("ADMIN_GROUP_NAME"),
		}

		// Configuración completa de la API
		config := &api.Config{
			LDAPConfig: ldapConfig,
			AuthConfig: authConfig,
		}

		api, err := api.NewAPI(config)
		if err != nil {
			log.Fatalf("Failed to create API: %v", err)
		}

		// Iniciar el servidor
		log.Fatal(api.Run(":8080"))
	},
}
