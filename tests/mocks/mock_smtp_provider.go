package mocks

import "github.com/stretchr/testify/mock"

type MockSmtpProvider struct {
	mock.Mock
}

func (m *MockSmtpProvider) SendMail(message string) error {
	args := m.Called(message)
	return args.Error(0)
}
