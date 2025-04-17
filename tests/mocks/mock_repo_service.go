package mocks

import (
	"PartAuthService/types"

	"github.com/stretchr/testify/mock"
)

type MockRepoService struct {
	mock.Mock
}

func (m *MockRepoService) CreateSession(session *types.Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockRepoService) GetSessionById(id string) (*types.Session, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Session), args.Error(1)
}

func (m *MockRepoService) UpdateSession(session *types.Session) error {
	args := m.Called(session)
	return args.Error(0)
}
