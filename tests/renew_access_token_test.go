package tests

import (
	"PartAuthService/types"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestRenewAccessToken_Success(t *testing.T) {
	setup := NewTestSetup(t)

	refreshToken := "valid_refresh_token"
	newAccessToken := "new_access_token"
	newRefreshToken := "new_refresh_token"
	sessionId := "session_id"
	ip := setup.Ip

	existingSha256 := sha256.Sum256([]byte(refreshToken))
	existingBcryptHash, _ := bcrypt.GenerateFromPassword(existingSha256[:], bcrypt.DefaultCost)

	refreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: sessionId,
		},
	}
	setup.MockJwt.On("VerifyToken", refreshToken).Return(refreshClaims, nil)

	session := &types.Session{
		Id:           sessionId,
		RefreshToken: string(existingBcryptHash),
		IpAddress:    ip,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	setup.MockRepo.On("GetSessionById", sessionId).Return(session, nil)

	newRefreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionId,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	setup.MockJwt.On("CreateToken", sessionId, ip, 30*time.Minute, "").Return(newAccessToken, nil, nil)
	setup.MockJwt.On("CreateToken", sessionId, ip, 24*time.Hour, sessionId).Return(newRefreshToken, newRefreshClaims, nil)

	newRefreshSha256 := sha256.Sum256([]byte(newRefreshToken))

	setup.MockRepo.On("UpdateSession", mock.MatchedBy(func(updatedSession *types.Session) bool {
		return updatedSession.Id == sessionId &&
			bcrypt.CompareHashAndPassword([]byte(updatedSession.RefreshToken), newRefreshSha256[:]) == nil &&
			updatedSession.IpAddress == ip &&
			updatedSession.ExpiresAt.Equal(newRefreshClaims.ExpiresAt.Time)
	})).Return(nil)

	payload := map[string]string{"refresh_token": refreshToken}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/tokens/renew", bytes.NewReader(body))
	req.RemoteAddr = ip
	setup.Rr = httptest.NewRecorder()

	setup.Router.ServeHTTP(setup.Rr, req)

	assert.Equal(t, http.StatusOK, setup.Rr.Code)

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.Unmarshal(setup.Rr.Body.Bytes(), &response)
	assert.Equal(t, newAccessToken, response.AccessToken)
	assert.Equal(t, newRefreshToken, response.RefreshToken)

	setup.MockJwt.AssertExpectations(t)
	setup.MockRepo.AssertExpectations(t)
}

func TestRenewAccessToken_InvalidRefreshToken(t *testing.T) {
	setup := NewTestSetup(t)

	refreshToken := "invalid_refresh_token"

	setup.MockJwt.On("VerifyToken", refreshToken).Return(nil, fmt.Errorf("invalid token"))

	payload := map[string]string{"refresh_token": refreshToken}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/tokens/renew", bytes.NewReader(body))
	req.RemoteAddr = setup.Ip
	setup.Rr = httptest.NewRecorder()

	setup.Router.ServeHTTP(setup.Rr, req)

	assert.Equal(t, http.StatusUnauthorized, setup.Rr.Code)

	setup.MockJwt.AssertExpectations(t)
}

func TestRenewAccessToken_ExpiredSession(t *testing.T) {
	setup := NewTestSetup(t)

	refreshToken := "expired_refresh_token"
	sessionId := "session_id"

	existingSha256 := sha256.Sum256([]byte(refreshToken))
	existingBcryptHash, _ := bcrypt.GenerateFromPassword(existingSha256[:], bcrypt.DefaultCost)

	refreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: sessionId,
		},
	}
	setup.MockJwt.On("VerifyToken", refreshToken).Return(refreshClaims, nil)

	session := &types.Session{
		Id:           sessionId,
		RefreshToken: string(existingBcryptHash),
		IpAddress:    setup.Ip,
		ExpiresAt:    time.Now().Add(-time.Hour),
	}
	setup.MockRepo.On("GetSessionById", sessionId).Return(session, nil)

	payload := map[string]string{"refresh_token": refreshToken}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/tokens/renew", bytes.NewReader(body))
	req.RemoteAddr = setup.Ip
	setup.Rr = httptest.NewRecorder()

	setup.Router.ServeHTTP(setup.Rr, req)

	assert.Equal(t, http.StatusUnauthorized, setup.Rr.Code)

	setup.MockJwt.AssertExpectations(t)
	setup.MockRepo.AssertExpectations(t)
}

func TestRenewAccessToken_IPChange(t *testing.T) {
	setup := NewTestSetup(t)

	refreshToken := "valid_refresh_token"
	sessionId := "session_id"
	ip := "128.0.0.1"

	existingSha256 := sha256.Sum256([]byte(refreshToken))
	existingBcryptHash, _ := bcrypt.GenerateFromPassword(existingSha256[:], bcrypt.DefaultCost)

	refreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID: sessionId,
		},
	}
	setup.MockJwt.On("VerifyToken", refreshToken).Return(refreshClaims, nil)

	session := &types.Session{
		Id:           sessionId,
		RefreshToken: string(existingBcryptHash),
		IpAddress:    "127.0.0.1",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	setup.MockRepo.On("GetSessionById", sessionId).Return(session, nil)

	newAccessToken := "new_access_token"
	newRefreshToken := "new_refresh_token"
	newRefreshClaims := &types.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionId,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	setup.MockJwt.On("CreateToken", sessionId, ip, 30*time.Minute, "").Return(newAccessToken, nil, nil)
	setup.MockJwt.On("CreateToken", sessionId, ip, 24*time.Hour, sessionId).Return(newRefreshToken, newRefreshClaims, nil)

	newRefreshSha256 := sha256.Sum256([]byte(newRefreshToken))

	setup.MockRepo.On("UpdateSession", mock.MatchedBy(func(updatedSession *types.Session) bool {
		return updatedSession.Id == sessionId &&
			bcrypt.CompareHashAndPassword([]byte(updatedSession.RefreshToken), newRefreshSha256[:]) == nil &&
			updatedSession.IpAddress == ip &&
			updatedSession.ExpiresAt.Equal(newRefreshClaims.ExpiresAt.Time)
	})).Return(nil)

	setup.MockSmtp.On("SendMail", mock.Anything).Return(nil)

	payload := map[string]string{"refresh_token": refreshToken}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/tokens/renew", bytes.NewReader(body))
	req.RemoteAddr = ip
	setup.Rr = httptest.NewRecorder()

	setup.Router.ServeHTTP(setup.Rr, req)

	assert.Equal(t, http.StatusOK, setup.Rr.Code)

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.Unmarshal(setup.Rr.Body.Bytes(), &response)
	assert.Equal(t, newAccessToken, response.AccessToken)
	assert.Equal(t, newRefreshToken, response.RefreshToken)

	setup.MockJwt.AssertExpectations(t)
	setup.MockRepo.AssertExpectations(t)
	setup.MockSmtp.AssertExpectations(t)
}
