package api

import (
	"fmt"
	"net/http"

	"github.com/aescanero/openldap-node-api/internal/ldap"
	"github.com/gin-gonic/gin"
)

// Handlers para Usuarios

func (a *API) getListUsers(c *gin.Context) {
	params, err := parseQueryParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Construir filtro LDAP basado en los parámetros
	filter := "(objectClass=posixAccount)"
	if title, ok := params.Filter["title"].(string); ok {
		filter = fmt.Sprintf("(&%s(cn=*%s*))", filter, title)
	}

	users, err := ldap.Search(a.ldapClient, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Convertir usuarios LDAP a respuestas API
	responses := make([]UserResponse, len(users))
	for i, user := range users {
		responses[i] = ConvertToUserResponse(user)
	}

	// Aplicar paginación
	start := 0
	end := len(responses)
	if len(params.Range) == 2 {
		start = params.Range[0]
		end = params.Range[1] + 1
		if end > len(responses) {
			end = len(responses)
		}
	}

	// Aplicar ordenación si está especificada
	if len(params.Sort) == 2 {
		field := params.Sort[0]
		order := params.Sort[1]
		sortUserResponses(responses, field, order == "ASC")
	}

	// Establecer headers de rango
	setContentRange(c, start, end-1, len(responses))

	// Devolver subconjunto de usuarios
	if start < end {
		c.JSON(http.StatusOK, responses[start:end])
	} else {
		c.JSON(http.StatusOK, []UserResponse{})
	}
}

func (a *API) getOneUser(c *gin.Context) {
	uid := c.Param("uid")
	user := ldap.NewUser(a.ldapClient)

	if err := user.Get(uid); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, ConvertToUserResponse(user))
}

func (a *API) createUser(c *gin.Context) {
	var req UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	user := ldap.NewUser(a.ldapClient)
	user.UID = req.UID
	user.CN = req.CN
	user.SN = req.SN
	user.GivenName = req.GivenName
	user.Mail = req.Mail
	user.UserPassword = req.Password
	user.DN = fmt.Sprintf("uid=%s,ou=people,%s", req.UID, a.ldapClient.Config.BaseDN)

	if err := user.Create(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, ConvertToUserResponse(user))
}

func (a *API) updateUser(c *gin.Context) {
	uid := c.Param("uid")
	var req UserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	user := ldap.NewUser(a.ldapClient)
	if err := user.Get(uid); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	if req.CN != "" {
		user.CN = req.CN
	}
	if req.SN != "" {
		user.SN = req.SN
	}
	if req.GivenName != "" {
		user.GivenName = req.GivenName
	}
	if req.Mail != "" {
		user.Mail = req.Mail
	}
	if req.Password != "" {
		user.UserPassword = req.Password
	}

	if err := user.Update(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, ConvertToUserResponse(user))
}

func (a *API) deleteUser(c *gin.Context) {
	uid := c.Param("uid")
	user := ldap.NewUser(a.ldapClient)

	if err := user.Get(uid); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	if err := user.Delete(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// Handlers para Grupos

func (a *API) getListGroups(c *gin.Context) {
	params, err := parseQueryParams(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	filter := "(objectClass=posixGroup)"
	if title, ok := params.Filter["title"].(string); ok {
		filter = fmt.Sprintf("(&%s(cn=*%s*))", filter, title)
	}

	groups, err := ldap.SearchGroups(a.ldapClient, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	responses := make([]GroupResponse, len(groups))
	for i, group := range groups {
		responses[i] = ConvertToGroupResponse(group)
	}

	start := 0
	end := len(responses)
	if len(params.Range) == 2 {
		start = params.Range[0]
		end = params.Range[1] + 1
		if end > len(responses) {
			end = len(responses)
		}
	}

	if len(params.Sort) == 2 {
		field := params.Sort[0]
		order := params.Sort[1]
		sortGroupResponses(responses, field, order == "ASC")
	}

	setContentRange(c, start, end-1, len(responses))

	if start < end {
		c.JSON(http.StatusOK, responses[start:end])
	} else {
		c.JSON(http.StatusOK, []GroupResponse{})
	}
}

func (a *API) getOneGroup(c *gin.Context) {
	cn := c.Param("cn")
	group := ldap.NewGroup(a.ldapClient)

	if err := group.Get(cn); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, ConvertToGroupResponse(group))
}

func (a *API) createGroup(c *gin.Context) {
	var req GroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	group := ldap.NewGroup(a.ldapClient)
	group.CN = req.CN
	group.Description = req.Description
	group.Members = req.Members
	group.DN = fmt.Sprintf("cn=%s,ou=groups,%s", req.CN, a.ldapClient.Config.BaseDN)

	if err := group.Create(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, ConvertToGroupResponse(group))
}

func (a *API) updateGroup(c *gin.Context) {
	cn := c.Param("cn")
	var req GroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	group := ldap.NewGroup(a.ldapClient)
	if err := group.Get(cn); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	if req.Description != "" {
		group.Description = req.Description
	}
	if len(req.Members) > 0 {
		group.Members = req.Members
	}

	if err := group.Update(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, ConvertToGroupResponse(group))
}

func (a *API) deleteGroup(c *gin.Context) {
	cn := c.Param("cn")
	group := ldap.NewGroup(a.ldapClient)

	if err := group.Get(cn); err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	if err := group.Delete(); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// Funciones auxiliares

func sortUserResponses(responses []UserResponse, field string, ascending bool) {
	// TODO: Implementar ordenación de usuarios
}

func sortGroupResponses(responses []GroupResponse, field string, ascending bool) {
	// TODO: Implementar ordenación de grupos
}
