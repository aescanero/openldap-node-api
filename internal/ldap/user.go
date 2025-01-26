package ldap

import (
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap"
)

type User struct {
	DN           string
	UID          string
	CN           string
	SN           string
	GivenName    string
	Mail         string
	UserPassword string
	UIDNumber    int
	client       *LDAPClient
}

// NewUser crea una nueva instancia de User
func NewUser(client *LDAPClient) *User {
	return &User{
		client: client,
	}
}

// getNextUIDNumber encuentra el siguiente UID number disponible
func getNextUIDNumber(client *LDAPClient) (int, error) {
	// Buscar todos los uidNumbers existentes
	searchRequest := ldap.NewSearchRequest(
		client.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=posixAccount)(uidNumber=*))",
		[]string{"uidNumber"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return 0, fmt.Errorf("failed to search uidNumbers: %v", err)
	}

	// Encontrar el máximo uidNumber
	maxUID := 1000 // Valor inicial por defecto
	for _, entry := range sr.Entries {
		uidStr := entry.GetAttributeValue("uidNumber")
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}
		if uid > maxUID {
			maxUID = uid
		}
	}

	// Retornar el siguiente número disponible
	return maxUID + 1, nil
}

// Create crea un nuevo usuario en LDAP
func (u *User) Create() error {
	if u.DN == "" || u.UID == "" {
		return fmt.Errorf("DN and UID are required fields")
	}

	// Si no se proporcionó un UIDNumber, obtener el siguiente disponible
	if u.UIDNumber == 0 {
		nextUID, err := getNextUIDNumber(u.client)
		if err != nil {
			return fmt.Errorf("failed to get next UID number: %v", err)
		}
		u.UIDNumber = nextUID
	}

	addReq := ldap.NewAddRequest(u.DN, []ldap.Control{})

	addReq.Attribute("objectClass", []string{
		"inetOrgPerson",
		"organizationalPerson",
		"person",
		"posixAccount",
		"top",
	})
	addReq.Attribute("uid", []string{u.UID})
	addReq.Attribute("cn", []string{u.CN})
	addReq.Attribute("sn", []string{u.SN})
	addReq.Attribute("givenName", []string{u.GivenName})
	addReq.Attribute("mail", []string{u.Mail})
	addReq.Attribute("uidNumber", []string{strconv.Itoa(u.UIDNumber)})
	addReq.Attribute("gidNumber", []string{"100"}) // Grupo por defecto, podría ser configurable
	addReq.Attribute("homeDirectory", []string{fmt.Sprintf("/home/%s", u.UID)})
	addReq.Attribute("loginShell", []string{"/bin/bash"})

	if u.UserPassword != "" {
		addReq.Attribute("userPassword", []string{u.UserPassword})
	}

	err := u.client.conn.Add(addReq)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}

	return nil
}

// Get obtiene un usuario por su UID
func (u *User) Get(uid string) error {
	searchRequest := ldap.NewSearchRequest(
		u.client.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(uid=%s)", uid),
		[]string{"dn", "uid", "cn", "sn", "givenName", "mail", "uidNumber"},
		nil,
	)

	sr, err := u.client.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("failed to search user: %v", err)
	}

	if len(sr.Entries) != 1 {
		return fmt.Errorf("user not found or multiple entries returned")
	}

	entry := sr.Entries[0]
	u.DN = entry.DN
	u.UID = entry.GetAttributeValue("uid")
	u.CN = entry.GetAttributeValue("cn")
	u.SN = entry.GetAttributeValue("sn")
	u.GivenName = entry.GetAttributeValue("givenName")
	u.Mail = entry.GetAttributeValue("mail")

	uidNumber, err := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
	if err == nil {
		u.UIDNumber = uidNumber
	}

	return nil
}

// Update actualiza los atributos del usuario en LDAP
func (u *User) Update() error {
	if u.DN == "" {
		return fmt.Errorf("DN is required for update")
	}

	modifyReq := ldap.NewModifyRequest(u.DN, []ldap.Control{})

	// Actualizamos cada atributo no vacío
	if u.CN != "" {
		modifyReq.Replace("cn", []string{u.CN})
	}
	if u.SN != "" {
		modifyReq.Replace("sn", []string{u.SN})
	}
	if u.GivenName != "" {
		modifyReq.Replace("givenName", []string{u.GivenName})
	}
	if u.Mail != "" {
		modifyReq.Replace("mail", []string{u.Mail})
	}
	if u.UIDNumber != 0 {
		modifyReq.Replace("uidNumber", []string{strconv.Itoa(u.UIDNumber)})
	}
	if u.UserPassword != "" {
		modifyReq.Replace("userPassword", []string{u.UserPassword})
	}

	err := u.client.conn.Modify(modifyReq)
	if err != nil {
		return fmt.Errorf("failed to update user: %v", err)
	}

	return nil
}

// GetNextUIDNumber obtiene el siguiente UID number disponible
func (u *User) GetNextUIDNumber() (int, error) {
	return getNextUIDNumber(u.client)
}

// Search busca usuarios según un filtro LDAP
func Search(client *LDAPClient, filter string) ([]*User, error) {
	searchRequest := ldap.NewSearchRequest(
		client.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn", "uid", "cn", "sn", "givenName", "mail", "uidNumber"},
		nil,
	)

	sr, err := client.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %v", err)
	}

	var users []*User
	for _, entry := range sr.Entries {
		user := &User{
			DN:        entry.DN,
			UID:       entry.GetAttributeValue("uid"),
			CN:        entry.GetAttributeValue("cn"),
			SN:        entry.GetAttributeValue("sn"),
			GivenName: entry.GetAttributeValue("givenName"),
			Mail:      entry.GetAttributeValue("mail"),
			client:    client,
		}

		uidNumber, err := strconv.Atoi(entry.GetAttributeValue("uidNumber"))
		if err == nil {
			user.UIDNumber = uidNumber
		}

		users = append(users, user)
	}

	return users, nil
}

// Delete elimina el usuario de LDAP
func (u *User) Delete() error {
	if u.DN == "" {
		return fmt.Errorf("DN is required for deletion")
	}

	delReq := ldap.NewDelRequest(u.DN, []ldap.Control{})

	err := u.client.conn.Del(delReq)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	return nil
}
