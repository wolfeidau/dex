package dynamodb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dexidp/dex/storage"
)

// Client is a mirrored struct from storage with JSON struct tags
type Client struct {
	ID           string   `json:"sk"`
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirectURIs"`
	TrustedPeers []string `json:"trustedPeers"`
	Public       bool     `json:"public"`
	Name         string   `json:"name"`
	LogoURL      string   `json:"logoURL"`
}

func fromStorageClient(a storage.Client) *Client {
	return &Client{
		ID:           a.ID,
		Secret:       a.Secret,
		RedirectURIs: a.RedirectURIs,
		TrustedPeers: a.TrustedPeers,
		Public:       a.Public,
		Name:         a.Name,
		LogoURL:      a.LogoURL,
	}
}

func toStorageClient(a Client) storage.Client {
	return storage.Client{
		ID:           a.ID,
		Secret:       a.Secret,
		RedirectURIs: a.RedirectURIs,
		TrustedPeers: a.TrustedPeers,
		Public:       a.Public,
		Name:         a.Name,
		LogoURL:      a.LogoURL,
	}
}

// Connector is a mirrored struct from storage with JSON struct tags
type Connector struct {
	ID              string `json:"sk"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion"`
	Config          []byte `json:"email"`
}

func fromStorageConnector(a storage.Connector) *Connector {
	return &Connector{
		ID:              a.ID,
		Type:            a.Type,
		Name:            a.Name,
		ResourceVersion: a.ResourceVersion,
		Config:          a.Config,
	}
}

func toStorageConnector(a Connector) storage.Connector {
	return storage.Connector{
		ID:              a.ID,
		Type:            a.Type,
		Name:            a.Name,
		ResourceVersion: a.ResourceVersion,
		Config:          a.Config,
	}
}

// AuthCode is a mirrored struct from storage with JSON struct tags
type AuthCode struct {
	ID          string   `json:"sk"`
	ClientID    string   `json:"clientID"`
	RedirectURI string   `json:"redirectURI"`
	Nonce       string   `json:"nonce,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`

	ConnectorID   string `json:"connectorID,omitempty"`
	ConnectorData []byte `json:"connectorData,omitempty"`
	Claims        Claims `json:"claims,omitempty"`

	Expiry time.Time `json:"expiry"`
}

func fromStorageAuthCode(a storage.AuthCode) *AuthCode {
	return &AuthCode{
		ID:            a.ID,
		ClientID:      a.ClientID,
		RedirectURI:   a.RedirectURI,
		ConnectorID:   a.ConnectorID,
		ConnectorData: a.ConnectorData,
		Nonce:         a.Nonce,
		Scopes:        a.Scopes,
		Claims:        fromStorageClaims(a.Claims),
		Expiry:        a.Expiry,
	}
}

func toStorageAuthCode(a AuthCode) storage.AuthCode {
	return storage.AuthCode{
		ID:            a.ID,
		ClientID:      a.ClientID,
		RedirectURI:   a.RedirectURI,
		ConnectorID:   a.ConnectorID,
		ConnectorData: a.ConnectorData,
		Nonce:         a.Nonce,
		Scopes:        a.Scopes,
		Claims:        toStorageClaims(a.Claims),
		Expiry:        a.Expiry,
	}
}

// AuthRequest is a mirrored struct from storage with JSON struct tags
type AuthRequest struct {
	ID                  string    `json:"sk"`
	ClientID            string    `json:"client_id"`
	ResponseTypes       []string  `json:"response_types"`
	Scopes              []string  `json:"scopes"`
	RedirectURI         string    `json:"redirect_uri"`
	Nonce               string    `json:"nonce"`
	State               string    `json:"state"`
	ForceApprovalPrompt bool      `json:"force_approval_prompt"`
	Expiry              time.Time `json:"expiry"`
	LoggedIn            bool      `json:"logged_in"`
	Claims              Claims    `json:"claims"`
	ConnectorID         string    `json:"connector_id"`
	ConnectorData       []byte    `json:"connector_data"`
}

func fromStorageAuthRequest(a storage.AuthRequest) *AuthRequest {
	return &AuthRequest{
		ID:                  a.ID,
		ClientID:            a.ClientID,
		ResponseTypes:       a.ResponseTypes,
		Scopes:              a.Scopes,
		RedirectURI:         a.RedirectURI,
		Nonce:               a.Nonce,
		State:               a.State,
		ForceApprovalPrompt: a.ForceApprovalPrompt,
		Expiry:              a.Expiry,
		LoggedIn:            a.LoggedIn,
		Claims:              fromStorageClaims(a.Claims),
		ConnectorID:         a.ConnectorID,
		ConnectorData:       a.ConnectorData,
	}
}

func toStorageAuthRequest(a AuthRequest) storage.AuthRequest {
	return storage.AuthRequest{
		ID:                  a.ID,
		ClientID:            a.ClientID,
		ResponseTypes:       a.ResponseTypes,
		Scopes:              a.Scopes,
		RedirectURI:         a.RedirectURI,
		Nonce:               a.Nonce,
		State:               a.State,
		ForceApprovalPrompt: a.ForceApprovalPrompt,
		LoggedIn:            a.LoggedIn,
		ConnectorID:         a.ConnectorID,
		ConnectorData:       a.ConnectorData,
		Expiry:              a.Expiry,
		Claims:              toStorageClaims(a.Claims),
	}
}

// RefreshToken is a mirrored struct from storage with JSON struct tags
type RefreshToken struct {
	ID            string    `json:"sk"`
	Token         string    `json:"token"`
	CreatedAt     time.Time `json:"created_at"`
	LastUsed      time.Time `json:"last_used"`
	ClientID      string    `json:"client_id"`
	ConnectorID   string    `json:"connector_id"`
	ConnectorData []byte    `json:"connector_data"`
	Claims        Claims    `json:"claims"`
	Scopes        []string  `json:"scopes"`
	Nonce         string    `json:"nonce"`
}

func toStorageRefreshToken(r RefreshToken) storage.RefreshToken {
	return storage.RefreshToken{
		ID:            r.ID,
		Token:         r.Token,
		CreatedAt:     r.CreatedAt,
		LastUsed:      r.LastUsed,
		ClientID:      r.ClientID,
		ConnectorID:   r.ConnectorID,
		ConnectorData: r.ConnectorData,
		Scopes:        r.Scopes,
		Nonce:         r.Nonce,
		Claims:        toStorageClaims(r.Claims),
	}
}

func fromStorageRefreshToken(r storage.RefreshToken) *RefreshToken {
	return &RefreshToken{
		ID:            r.ID,
		Token:         r.Token,
		CreatedAt:     r.CreatedAt,
		LastUsed:      r.LastUsed,
		ClientID:      r.ClientID,
		ConnectorID:   r.ConnectorID,
		ConnectorData: r.ConnectorData,
		Scopes:        r.Scopes,
		Nonce:         r.Nonce,
		Claims:        fromStorageClaims(r.Claims),
	}
}

// Claims is a mirrored struct from storage with JSON struct tags.
type Claims struct {
	UserID            string   `json:"userID"`
	Username          string   `json:"username"`
	PreferredUsername string   `json:"preferredUsername"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"emailVerified"`
	Groups            []string `json:"groups,omitempty"`
}

func fromStorageClaims(i storage.Claims) Claims {
	return Claims{
		UserID:            i.UserID,
		Username:          i.Username,
		PreferredUsername: i.PreferredUsername,
		Email:             i.Email,
		EmailVerified:     i.EmailVerified,
		Groups:            i.Groups,
	}
}

func toStorageClaims(i Claims) storage.Claims {
	return storage.Claims{
		UserID:            i.UserID,
		Username:          i.Username,
		PreferredUsername: i.PreferredUsername,
		Email:             i.Email,
		EmailVerified:     i.EmailVerified,
		Groups:            i.Groups,
	}
}

// Keys is a mirrored struct from storage with JSON struct tags
type Keys struct {
	ID               string    `json:"sk"`
	SigningKey       string    `json:"signing_key"`
	SigningKeyPub    string    `json:"signing_key_pub"`
	VerificationKeys string    `json:"verification_keys"`
	NextRotation     time.Time `json:"next_rotation"`
}

func fromStorageKeys(o storage.Keys) *Keys {
	return &Keys{
		ID:               keysID, // Uses a static id for this as it is a list of one
		SigningKey:       encodeBase64(o.SigningKey),
		SigningKeyPub:    encodeBase64(o.SigningKeyPub),
		VerificationKeys: encodeBase64(o.VerificationKeys),
		NextRotation:     o.NextRotation,
	}
}

func toStorageKeys(o Keys) (storage.Keys, error) {
	keys := storage.Keys{
		NextRotation: o.NextRotation,
	}

	err := decodeBase64(o.SigningKey, &keys.SigningKey)
	if err != nil {
		return keys, err
	}

	err = decodeBase64(o.SigningKeyPub, &keys.SigningKeyPub)
	if err != nil {
		return keys, err
	}

	err = decodeBase64(o.VerificationKeys, &keys.VerificationKeys)
	if err != nil {
		return keys, err
	}

	return keys, nil
}

func encodeBase64(rec interface{}) string {
	data, _ := json.Marshal(rec)
	return base64.RawStdEncoding.EncodeToString(data)
}

func decodeBase64(data string, rec interface{}) error {
	if data == "" {
		return nil
	}

	buf, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return err
	}

	err = json.Unmarshal(buf, rec)
	if err != nil {
		return err
	}

	return nil
}

// OfflineSessions is a mirrored struct from storage with JSON struct tags
type OfflineSessions struct {
	ID            string                              `json:"sk"`
	UserID        string                              `json:"user_id,omitempty"`
	ConnID        string                              `json:"conn_id,omitempty"`
	Refresh       map[string]*storage.RefreshTokenRef `json:"refresh,omitempty"`
	ConnectorData []byte                              `json:"connectorData,omitempty"`
}

func fromStorageOfflineSessions(o storage.OfflineSessions) *OfflineSessions {
	return &OfflineSessions{
		ID:            fmt.Sprintf("%s/%s", o.UserID, o.ConnID),
		UserID:        o.UserID,
		ConnID:        o.ConnID,
		Refresh:       o.Refresh,
		ConnectorData: o.ConnectorData,
	}
}

func toStorageOfflineSessions(o OfflineSessions) storage.OfflineSessions {
	s := storage.OfflineSessions{
		UserID:        o.UserID,
		ConnID:        o.ConnID,
		Refresh:       o.Refresh,
		ConnectorData: o.ConnectorData,
	}
	if s.Refresh == nil {
		// Server code assumes this will be non-nil.
		s.Refresh = make(map[string]*storage.RefreshTokenRef)
	}
	return s
}

type Password struct {
	ID          string `json:"sk"`
	Email       string `json:"email"`
	Hash        []byte `json:"hash"`
	HashFromEnv string `json:"hashFromEnv"`
	Username    string `json:"username"`
	UserID      string `json:"userID"`
}

func fromStoragePassword(o storage.Password) *Password {
	return &Password{
		ID:          strings.ToLower(o.Email), // make all email id values the same
		Email:       o.Email,
		Hash:        o.Hash,
		HashFromEnv: o.HashFromEnv,
		Username:    o.Username,
		UserID:      o.UserID,
	}
}

func toStoragePassword(o Password) storage.Password {
	return storage.Password{
		Email:       o.Email,
		Hash:        o.Hash,
		HashFromEnv: o.HashFromEnv,
		Username:    o.Username,
		UserID:      o.UserID,
	}
}

// DeviceRequest is a mirrored struct from storage with JSON struct tags
type DeviceRequest struct {
	UserCode     string    `json:"user_code"`
	DeviceCode   string    `json:"device_code"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Scopes       []string  `json:"scopes"`
	Expiry       time.Time `json:"expiry"`
}

func fromStorageDeviceRequest(d storage.DeviceRequest) DeviceRequest {
	return DeviceRequest{
		UserCode:     d.UserCode,
		DeviceCode:   d.DeviceCode,
		ClientID:     d.ClientID,
		ClientSecret: d.ClientSecret,
		Scopes:       d.Scopes,
		Expiry:       d.Expiry,
	}
}

// DeviceToken is a mirrored struct from storage with JSON struct tags
type DeviceToken struct {
	DeviceCode          string    `json:"device_code"`
	Status              string    `json:"status"`
	Token               string    `json:"token"`
	Expiry              time.Time `json:"expiry"`
	LastRequestTime     time.Time `json:"last_request"`
	PollIntervalSeconds int       `json:"poll_interval"`
}

func fromStorageDeviceToken(t storage.DeviceToken) DeviceToken {
	return DeviceToken{
		DeviceCode:          t.DeviceCode,
		Status:              t.Status,
		Token:               t.Token,
		Expiry:              t.Expiry,
		LastRequestTime:     t.LastRequestTime,
		PollIntervalSeconds: t.PollIntervalSeconds,
	}
}

func toStorageDeviceToken(t DeviceToken) storage.DeviceToken {
	return storage.DeviceToken{
		DeviceCode:          t.DeviceCode,
		Status:              t.Status,
		Token:               t.Token,
		Expiry:              t.Expiry,
		LastRequestTime:     t.LastRequestTime,
		PollIntervalSeconds: t.PollIntervalSeconds,
	}
}

func toStorageDeviceRequest(d DeviceRequest) storage.DeviceRequest {
	return storage.DeviceRequest{
		UserCode:     d.UserCode,
		DeviceCode:   d.DeviceCode,
		ClientID:     d.ClientID,
		ClientSecret: d.ClientSecret,
		Scopes:       d.Scopes,
		Expiry:       d.Expiry,
	}
}
