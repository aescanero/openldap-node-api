package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aescanero/openldap-node-api/internal/ldap"
	"github.com/gin-gonic/gin"
)

type Config struct {
	LDAPConfig *ldap.LDAPConfig
	AuthConfig *AuthConfig
}

// API estructura principal para la API
type API struct {
	ldapClient *ldap.LDAPClient
	router     *gin.Engine
	authConfig *AuthConfig
	keyCache   *KeyCache
}

// NewAPI crea una nueva instancia de la API
func NewAPI(config *Config) (*API, error) {
	client := ldap.NewLDAPClient(config.LDAPConfig)
	err := client.Connect()
	if err != nil {
		return nil, err
	}

	api := &API{
		ldapClient: client,
		router:     gin.Default(),
		authConfig: config.AuthConfig,
		keyCache:   NewKeyCache(),
	}

	api.setupRoutes()
	return api, nil
}

// / setupRoutes configura las rutas de la API
func (a *API) setupRoutes() {
	// Middleware de autenticación para todas las rutas
	a.router.Use(AuthMiddleware(*a.authConfig, a.keyCache))

	// Rutas de usuarios
	users := a.router.Group("/api/v1/users")
	{
		users.GET("", a.getListUsers)       // getList
		users.GET("/:uid", a.getOneUser)    // getOne
		users.POST("", a.createUser)        // create
		users.PUT("/:uid", a.updateUser)    // update
		users.DELETE("/:uid", a.deleteUser) // delete
	}

	// Rutas de grupos
	groups := a.router.Group("/api/v1/groups")
	{
		groups.GET("", a.getListGroups)      // getList
		groups.GET("/:cn", a.getOneGroup)    // getOne
		groups.POST("", a.createGroup)       // create
		groups.PUT("/:cn", a.updateGroup)    // update
		groups.DELETE("/:cn", a.deleteGroup) // delete
	}
}

// QueryParams estructura para los parámetros de consulta
type QueryParams struct {
	Sort   []string               `json:"sort"`
	Range  []int                  `json:"range"`
	Filter map[string]interface{} `json:"filter"`
}

// UserRequest estructura para las peticiones de usuario
type UserRequest struct {
	ID        string `json:"id,omitempty"`
	UID       string `json:"uid" binding:"required"`
	CN        string `json:"cn" binding:"required"`
	SN        string `json:"sn" binding:"required"`
	GivenName string `json:"givenName" binding:"required"`
	Mail      string `json:"mail" binding:"required"`
	Password  string `json:"password,omitempty"`
}

// GroupRequest estructura para las peticiones de grupo
type GroupRequest struct {
	CN          string   `json:"cn" binding:"required"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
}

// UserResponse estructura para las respuestas de usuario
type UserResponse struct {
	ID        string `json:"id"`
	UID       string `json:"uid"`
	CN        string `json:"cn"`
	SN        string `json:"sn"`
	GivenName string `json:"givenName"`
	Mail      string `json:"mail"`
	UIDNumber int    `json:"uidNumber"`
}

// GroupResponse estructura para las respuestas de grupo
type GroupResponse struct {
	ID          string   `json:"id"`
	CN          string   `json:"cn"`
	Description string   `json:"description"`
	GIDNumber   int      `json:"gidNumber"`
	Members     []string `json:"members"`
}

// ErrorResponse estructura para respuestas de error
type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code,omitempty"`
}

// ListResponse estructura para respuestas de lista
type ListResponse struct {
	Data  interface{} `json:"data"`
	Total int         `json:"total"`
}

// ConvertToUserResponse convierte un usuario LDAP en una respuesta de API
func ConvertToUserResponse(user *ldap.User) UserResponse {
	return UserResponse{
		ID:        user.UID, // Usando UID como ID para React Admin
		UID:       user.UID,
		CN:        user.CN,
		SN:        user.SN,
		GivenName: user.GivenName,
		Mail:      user.Mail,
		UIDNumber: user.UIDNumber,
	}
}

// ConvertToGroupResponse convierte un grupo LDAP en una respuesta de API
func ConvertToGroupResponse(group *ldap.Group) GroupResponse {
	return GroupResponse{
		ID:          group.CN, // Usando CN como ID para React Admin
		CN:          group.CN,
		Description: group.Description,
		GIDNumber:   group.GIDNumber,
		Members:     group.Members,
	}
}

func parseQueryParams(c *gin.Context) (*QueryParams, error) {
	params := &QueryParams{
		Filter: make(map[string]interface{}),
	}

	// Parse sort parameters
	if sortStr := c.Query("sort"); sortStr != "" {
		var sort []string
		if err := json.Unmarshal([]byte(sortStr), &sort); err != nil {
			return nil, fmt.Errorf("invalid sort parameter: %v", err)
		}
		// React Admin sends sort as ["field", "ASC/DESC"]
		if len(sort) == 2 && (sort[1] == "ASC" || sort[1] == "DESC") {
			params.Sort = sort
		}
	}

	// Parse range parameters
	if rangeStr := c.Query("range"); rangeStr != "" {
		var rangeParts []int
		if err := json.Unmarshal([]byte(rangeStr), &rangeParts); err != nil {
			return nil, fmt.Errorf("invalid range parameter: %v", err)
		}
		// React Admin sends range as [startIndex, endIndex]
		if len(rangeParts) == 2 && rangeParts[0] <= rangeParts[1] {
			params.Range = rangeParts
		}
	}

	// Parse filter parameters
	if filterStr := c.Query("filter"); filterStr != "" {
		var filter map[string]interface{}
		if err := json.Unmarshal([]byte(filterStr), &filter); err != nil {
			return nil, fmt.Errorf("invalid filter parameter: %v", err)
		}

		// Process special filters
		for key, value := range filter {
			switch v := value.(type) {
			case []interface{}:
				// Handle array filters (e.g., for getManyReference)
				params.Filter[key] = v
			case map[string]interface{}:
				// Handle complex filters (e.g., for range or nested conditions)
				params.Filter[key] = v
			default:
				// Handle simple filters (e.g., string matches)
				params.Filter[key] = v
			}
		}
	}

	// Handle q parameter for full-text search if present
	if q := c.Query("q"); q != "" {
		params.Filter["q"] = q
	}

	return params, nil
}

// Helper function to set Content-Range header for pagination
func setContentRange(c *gin.Context, start, end, total int) {
	// Format: "posts start-end/total"
	c.Header("Content-Range", fmt.Sprintf("%d-%d/%d", start, end, total))

	// If partial content, return 206, otherwise 200
	if end < total-1 {
		c.Status(http.StatusPartialContent)
	}
}

// Run inicia el servidor de la API
func (a *API) Run(addr string) error {
	return a.router.Run(addr)
}
