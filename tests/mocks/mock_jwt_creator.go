package mocks

import (
	"PartAuthService/types"
	"time"

	"github.com/stretchr/testify/mock"
)

type MockJwtCreator struct {
	mock.Mock
}

func (m *MockJwtCreator) CreateToken(id string, ip string, duration time.Duration, tokenId string) (string, *types.UserClaims, error) {
	args := m.Called(id, ip, duration, tokenId)
	token := args.String(0)
	claims := args.Get(1)
	if claims == nil {
		return token, nil, args.Error(2)
	}
	return token, claims.(*types.UserClaims), args.Error(2)
}

func (m *MockJwtCreator) VerifyToken(tokenString string) (*types.UserClaims, error) {
	args := m.Called(tokenString)
	claims := args.Get(0)
	if claims == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.UserClaims), args.Error(1)
}
