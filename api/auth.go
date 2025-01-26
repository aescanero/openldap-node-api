package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Config holds the configuration for OAuth2 authentication
type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
}

// Token represents an OAuth2 token with expiry
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// NewOAuth2Config creates a new OAuth2 configuration
func NewOAuth2Config(config OAuth2Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
	}
}

// GetAuthURL returns the authorization URL for OAuth2
func GetAuthURL(config *oauth2.Config, state string) string {
	return config.AuthCodeURL(state)
}

// ExchangeCodeForToken exchanges an authorization code for an access token
func ExchangeCodeForToken(config *oauth2.Config, code string) (*Token, error) {
	token, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	return &Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}, nil
}

// RefreshAccessToken refreshes an expired access token using the refresh token
func RefreshAccessToken(config *oauth2.Config, refreshToken string) (*Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	newToken, err := config.TokenSource(oauth2.NoContext, token).Token()
	if err != nil {
		return nil, err
	}

	return &Token{
		AccessToken:  newToken.AccessToken,
		TokenType:    newToken.TokenType,
		RefreshToken: newToken.RefreshToken,
		Expiry:       newToken.Expiry,
	}, nil
}

// ValidateToken validates if a token is still valid
func ValidateToken(token *Token) error {
	if token == nil {
		return errors.New("token is nil")
	}

	if token.AccessToken == "" {
		return errors.New("access token is empty")
	}

	if time.Now().After(token.Expiry) {
		return errors.New("token has expired")
	}

	return nil
}

// GetUserInfo makes an authenticated request to get user information
func GetUserInfo(token *Token, userInfoURL string) (map[string]interface{}, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get user info")
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}
