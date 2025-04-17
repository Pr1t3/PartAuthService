package tests

import (
	"PartAuthService/types"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestGetTokens_CreateSessionAndJwtCreatorCall(t *testing.T) {
	setup := NewTestSetup(t)

	accessToken := "access_token"
	refreshToken := "refresh_token"
	refreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "session_id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	refreshTokenSha256 := sha256.Sum256([]byte(refreshToken))

	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 30*time.Minute, "").Return(accessToken, nil, nil)
	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 24*time.Hour, "").Return(refreshToken, refreshClaims, nil)

	setup.MockRepo.On("CreateSession", mock.MatchedBy(func(session *types.Session) bool {
		return session.Id == refreshClaims.ID &&
			session.IpAddress == setup.Ip &&
			bcrypt.CompareHashAndPassword([]byte(session.RefreshToken), refreshTokenSha256[:]) == nil &&
			session.ExpiresAt.Equal(refreshClaims.ExpiresAt.Time)
	})).Return(nil)

	setup.Router.ServeHTTP(setup.Rr, setup.Req)

	setup.MockJwt.AssertExpectations(t)
	setup.MockRepo.AssertExpectations(t)
}

func TestGetTokens_JsonResponse(t *testing.T) {
	setup := NewTestSetup(t)

	accessToken := "access_token"
	refreshToken := "refresh_token"
	refreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "session_id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	refreshTokenSha256 := sha256.Sum256([]byte(refreshToken))

	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 30*time.Minute, "").Return(accessToken, nil, nil)
	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 24*time.Hour, "").Return(refreshToken, refreshClaims, nil)

	setup.MockRepo.On("CreateSession", mock.MatchedBy(func(session *types.Session) bool {
		return session.Id == refreshClaims.ID &&
			session.IpAddress == setup.Ip &&
			bcrypt.CompareHashAndPassword([]byte(session.RefreshToken), refreshTokenSha256[:]) == nil &&
			session.ExpiresAt.Equal(refreshClaims.ExpiresAt.Time)
	})).Return(nil)

	setup.Router.ServeHTTP(setup.Rr, setup.Req)

	assert.Equal(t, http.StatusOK, setup.Rr.Code)

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.Unmarshal(setup.Rr.Body.Bytes(), &response)

	assert.Equal(t, accessToken, response.AccessToken)
	assert.Equal(t, refreshToken, response.RefreshToken)
}

func TestGetTokens_CreateTokenError(t *testing.T) {
	setup := NewTestSetup(t)

	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 30*time.Minute, "").Return("", nil, fmt.Errorf("token creation error"))

	setup.Router.ServeHTTP(setup.Rr, setup.Req)

	assert.Equal(t, http.StatusInternalServerError, setup.Rr.Code)
}

func TestGetTokens_CreateSessionError(t *testing.T) {
	setup := NewTestSetup(t)

	accessToken := "access_token"
	refreshToken := "refresh_token"
	refreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "session_id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 30*time.Minute, "").Return(accessToken, nil, nil)
	setup.MockJwt.On("CreateToken", setup.UserId, setup.Ip, 24*time.Hour, "").Return(refreshToken, refreshClaims, nil)

	setup.MockRepo.On("CreateSession", mock.Anything).Return(fmt.Errorf("session creation error"))

	setup.Router.ServeHTTP(setup.Rr, setup.Req)

	assert.Equal(t, http.StatusInternalServerError, setup.Rr.Code)
}
