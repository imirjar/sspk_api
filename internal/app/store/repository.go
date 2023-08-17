package store

import "github.com/imirjar/api-service/internal/app/model"

// UserRepository
type UserRepository interface {
	Create(*model.User) error
	FindByEmail(string) (*model.User, error)
}
