package dynamodb

import (
	"github.com/dexidp/dex/storage"
)

type PasswordWrapper struct {
	ID string `json:"id"`
	storage.Password
}

type OfflineSessionsWrapper struct {
	ID string `json:"id"`
	storage.OfflineSessions
}

type AuthCodeWrapper struct {
	ID string `json:"id"`
	storage.AuthCode
}

type AuthRequestWrapper struct {
	ID string `json:"id"`
	storage.AuthRequest
}