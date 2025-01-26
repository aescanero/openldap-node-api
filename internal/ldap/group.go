package ldap

import (
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap"
)

// Group representa un grupo LDAP y sus operaciones
type Group struct {
	DN          string
	CN          string
	Description string
	GIDNumber   int
	Members     []string // Lista de DNs de miembros
	client      *LDAPClient
}

// NewGroup crea una nueva instancia de Group
func NewGroup(client *LDAPClient) *Group {
	return &Group{
		client:  client,
		Members: make([]string, 0),
	}
}

// getNextGIDNumber encuentra el siguiente GID number disponible
func getNextGIDNumber(client *LDAPClient) (int, error) {
	searchRequest := ldap.NewSearchRequest(
		client.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=posixGroup)(gidNumber=*))",
		[]string{"gidNumber"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return 0, fmt.Errorf("failed to search gidNumbers: %v", err)
	}

	maxGID := 1000 // Valor inicial por defecto
	for _, entry := range sr.Entries {
		gidStr := entry.GetAttributeValue("gidNumber")
		gid, err := strconv.Atoi(gidStr)
		if err != nil {
			continue
		}
		if gid > maxGID {
			maxGID = gid
		}
	}

	return maxGID + 1, nil
}

// Create crea un nuevo grupo en LDAP
func (g *Group) Create() error {
	if g.DN == "" || g.CN == "" {
		return fmt.Errorf("DN and CN are required fields")
	}

	// Si no se proporcionó un GIDNumber, obtener el siguiente disponible
	if g.GIDNumber == 0 {
		nextGID, err := getNextGIDNumber(g.client)
		if err != nil {
			return fmt.Errorf("failed to get next GID number: %v", err)
		}
		g.GIDNumber = nextGID
	}

	addReq := ldap.NewAddRequest(g.DN, []ldap.Control{})

	addReq.Attribute("objectClass", []string{
		"top",
		"posixGroup",
		"groupOfNames",
	})
	addReq.Attribute("cn", []string{g.CN})
	addReq.Attribute("gidNumber", []string{strconv.Itoa(g.GIDNumber)})

	if g.Description != "" {
		addReq.Attribute("description", []string{g.Description})
	}

	// En LDAP, un grupo debe tener al menos un miembro
	if len(g.Members) == 0 {
		// Usar un DN placeholder si no hay miembros
		g.Members = append(g.Members, "cn=placeholder")
	}
	addReq.Attribute("member", g.Members)

	err := g.client.conn.Add(addReq)
	if err != nil {
		return fmt.Errorf("failed to create group: %v", err)
	}

	return nil
}

// Get obtiene un grupo por su CN
func (g *Group) Get(cn string) error {
	searchRequest := ldap.NewSearchRequest(
		g.client.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=posixGroup)(cn=%s))", cn),
		[]string{"dn", "cn", "description", "gidNumber", "member"},
		nil,
	)

	sr, err := g.client.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search group: %v", err)
	}

	if len(sr.Entries) != 1 {
		return fmt.Errorf("group not found or multiple entries returned")
	}

	entry := sr.Entries[0]
	g.DN = entry.DN
	g.CN = entry.GetAttributeValue("cn")
	g.Description = entry.GetAttributeValue("description")
	g.Members = entry.GetAttributeValues("member")

	gidNumber, err := strconv.Atoi(entry.GetAttributeValue("gidNumber"))
	if err == nil {
		g.GIDNumber = gidNumber
	}

	return nil
}

// Update actualiza los atributos del grupo en LDAP
func (g *Group) Update() error {
	if g.DN == "" {
		return fmt.Errorf("DN is required for update")
	}

	modifyReq := ldap.NewModifyRequest(g.DN, []ldap.Control{})

	if g.CN != "" {
		modifyReq.Replace("cn", []string{g.CN})
	}
	if g.Description != "" {
		modifyReq.Replace("description", []string{g.Description})
	}
	if g.GIDNumber != 0 {
		modifyReq.Replace("gidNumber", []string{strconv.Itoa(g.GIDNumber)})
	}
	if len(g.Members) > 0 {
		modifyReq.Replace("member", g.Members)
	}

	err := g.client.conn.Modify(modifyReq)
	if err != nil {
		return fmt.Errorf("failed to update group: %v", err)
	}

	return nil
}

// Delete elimina el grupo de LDAP
func (g *Group) Delete() error {
	if g.DN == "" {
		return fmt.Errorf("DN is required for deletion")
	}

	delReq := ldap.NewDelRequest(g.DN, []ldap.Control{})

	err := g.client.conn.Del(delReq)
	if err != nil {
		return fmt.Errorf("failed to delete group: %v", err)
	}

	return nil
}

// AddMember añade un miembro al grupo
func (g *Group) AddMember(memberDN string) error {
	if g.DN == "" {
		return fmt.Errorf("group DN is required")
	}

	// Verificar si el miembro ya existe
	for _, member := range g.Members {
		if member == memberDN {
			return nil // El miembro ya existe
		}
	}

	modifyReq := ldap.NewModifyRequest(g.DN, []ldap.Control{})
	modifyReq.Add("member", []string{memberDN})

	err := g.client.conn.Modify(modifyReq)
	if err != nil {
		return fmt.Errorf("failed to add member: %v", err)
	}

	g.Members = append(g.Members, memberDN)
	return nil
}

// RemoveMember elimina un miembro del grupo
func (g *Group) RemoveMember(memberDN string) error {
	if g.DN == "" {
		return fmt.Errorf("group DN is required")
	}

	// Verificar que no sea el último miembro
	if len(g.Members) <= 1 {
		return fmt.Errorf("cannot remove last member from group")
	}

	modifyReq := ldap.NewModifyRequest(g.DN, []ldap.Control{})
	modifyReq.Delete("member", []string{memberDN})

	err := g.client.conn.Modify(modifyReq)
	if err != nil {
		return fmt.Errorf("failed to remove member: %v", err)
	}

	// Actualizar la lista de miembros local
	newMembers := make([]string, 0)
	for _, member := range g.Members {
		if member != memberDN {
			newMembers = append(newMembers, member)
		}
	}
	g.Members = newMembers

	return nil
}

// SearchGroups busca grupos según un filtro LDAP
func SearchGroups(client *LDAPClient, filter string) ([]*Group, error) {
	searchRequest := ldap.NewSearchRequest(
		client.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn", "cn", "description", "gidNumber", "member"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search groups: %v", err)
	}

	var groups []*Group
	for _, entry := range sr.Entries {
		group := &Group{
			DN:          entry.DN,
			CN:          entry.GetAttributeValue("cn"),
			Description: entry.GetAttributeValue("description"),
			Members:     entry.GetAttributeValues("member"),
			client:      client,
		}

		gidNumber, err := strconv.Atoi(entry.GetAttributeValue("gidNumber"))
		if err == nil {
			group.GIDNumber = gidNumber
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// GetNextGIDNumber obtiene el siguiente GID number disponible
func (g *Group) GetNextGIDNumber() (int, error) {
	return getNextGIDNumber(g.client)
}
