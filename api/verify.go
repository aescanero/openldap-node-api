package api

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type JWKSResponse struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type KeyCache struct {
	keys    map[string]*rsa.PublicKey
	expires time.Time
	mu      sync.RWMutex
}

type AuthConfig struct {
	DexIssuer      string
	JWKSEndpoint   string
	AdminGroupName string
}

func NewKeyCache() *KeyCache {
	return &KeyCache{
		keys: make(map[string]*rsa.PublicKey),
	}
}

// Claims estructura personalizada para el token JWT
type Claims struct {
	jwt.StandardClaims
	Groups []string `json:"groups"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
}

func parseTokenUnverified(tokenString string) (*jwt.Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token contains an invalid number of segments")
	}

	var err error
	token := &jwt.Token{
		Claims: &Claims{},
	}

	// Decodificar el header
	var headerBytes []byte
	if headerBytes, err = jwt.DecodeSegment(parts[0]); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return nil, err
	}

	// Decodificar los claims
	var claimBytes []byte
	if claimBytes, err = jwt.DecodeSegment(parts[1]); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(claimBytes, token.Claims); err != nil {
		return nil, err
	}

	return token, nil
}

// decodeBase64URL decodifica una cadena base64url
func decodeBase64URL(s string) ([]byte, error) {
	// Añadir padding si es necesario
	padding := 4 - (len(s) % 4)
	if padding != 4 {
		s += strings.Repeat("=", padding)
	}
	return base64.URLEncoding.DecodeString(s)
}

// parseRSAPublicKeyFromJWK convierte los componentes JWK en una clave pública RSA
func parseRSAPublicKeyFromJWK(n, e string) (*rsa.PublicKey, error) {
	// Decodificar el módulo
	nBytes, err := decodeBase64URL(n)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %v", err)
	}
	modulus := new(big.Int).SetBytes(nBytes)

	// Decodificar el exponente
	eBytes, err := decodeBase64URL(e)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %v", err)
	}

	var exponent uint64
	if len(eBytes) <= 4 {
		for i := 0; i < len(eBytes); i++ {
			exponent = exponent<<8 + uint64(eBytes[i])
		}
	} else {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: modulus,
		E: int(exponent),
	}, nil
}

func AuthMiddleware(config AuthConfig, cache *KeyCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extraer el token del header Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		// Parsear el token sin verificar para obtener el kid
		token, err := parseTokenUnverified(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}

		if token.Header["kid"] == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token missing kid"})
			c.Abort()
			return
		}

		kid := token.Header["kid"].(string)

		// Obtener la clave pública correspondiente
		key, err := getPublicKey(kid, config.JWKSEndpoint, cache)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to get public key"})
			c.Abort()
			return
		}

		// Verificar el token
		claims := &Claims{}
		token, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return key, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is not valid"})
			c.Abort()
			return
		}

		// Verificar el issuer
		if claims.Issuer != config.DexIssuer {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token issuer"})
			c.Abort()
			return
		}

		// Verificar que el usuario pertenece al grupo admin
		isAdmin := false
		for _, group := range claims.Groups {
			if group == config.AdminGroupName {
				isAdmin = true
				break
			}
		}

		if !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "User is not an admin"})
			c.Abort()
			return
		}

		// Almacenar información del usuario en el contexto
		c.Set("user_email", claims.Email)
		c.Set("user_name", claims.Name)
		c.Set("user_groups", claims.Groups)

		c.Next()
	}
}

func getPublicKey(kid, jwksURL string, cache *KeyCache) (*rsa.PublicKey, error) {
	cache.mu.RLock()
	key, exists := cache.keys[kid]
	validCache := exists && time.Now().Before(cache.expires)
	cache.mu.RUnlock()

	if validCache {
		return key, nil
	}

	// Obtener nuevas claves
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	var jwks JWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %v", err)
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Limpiar cache existente
	cache.keys = make(map[string]*rsa.PublicKey)
	cache.expires = time.Now().Add(24 * time.Hour)

	// Almacenar nuevas claves
	for _, jwk := range jwks.Keys {
		pubKey, err := parseRSAPublicKeyFromJWK(jwk.N, jwk.E)
		if err != nil {
			continue
		}
		cache.keys[jwk.Kid] = pubKey
	}

	return cache.keys[kid], nil
}
