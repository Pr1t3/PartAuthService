package handler

import (
	"PartAuthService/service"
	"PartAuthService/types"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	jwtCreator   service.JwtCreatorInterface
	repoService  service.RepoServiceInterface
	smtpProvider service.SmtpProviderInterface
}

func NewHandler(jwtCreator service.JwtCreatorInterface, repoService service.RepoServiceInterface, smtpProvider service.SmtpProviderInterface) *Handler {
	return &Handler{
		jwtCreator:   jwtCreator,
		repoService:  repoService,
		smtpProvider: smtpProvider,
	}
}

func (h *Handler) GetTokens(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	userId := chi.URLParam(r, "userId")
	accessToken, _, err := h.jwtCreator.CreateToken(userId, ip, 30*time.Minute, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshToken, refreshClaims, err := h.jwtCreator.CreateToken(userId, ip, 24*time.Hour, "")
	if err != nil {
		http.Error(w, "error creating token", http.StatusInternalServerError)
		return
	}

	refreshTokenSha256 := sha256.Sum256([]byte(refreshToken))

	refreshTokenHash, err := bcrypt.GenerateFromPassword(refreshTokenSha256[:], bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "error hashing refresh token: "+fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	err = h.repoService.CreateSession(&types.Session{
		Id:           refreshClaims.RegisteredClaims.ID,
		RefreshToken: string(refreshTokenHash),
		IpAddress:    ip,
		ExpiresAt:    refreshClaims.RegisteredClaims.ExpiresAt.Time,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating session: %s, %s", err, refreshToken), http.StatusInternalServerError)
		return
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	result.AccessToken = accessToken
	result.RefreshToken = refreshToken

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) RenewAccessToken(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "error decoding request body", http.StatusBadRequest)
		return
	}

	refreshTokenSha256 := sha256.Sum256([]byte(request.RefreshToken))

	refreshClaims, err := h.jwtCreator.VerifyToken(string(request.RefreshToken))
	if err != nil {
		http.Error(w, "error verifying token", http.StatusUnauthorized)
		return
	}

	session, err := h.repoService.GetSessionById(refreshClaims.RegisteredClaims.ID)
	if err != nil {
		http.Error(w, "error getting session", http.StatusInternalServerError)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(session.RefreshToken), refreshTokenSha256[:]) != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	if session.ExpiresAt.Before(time.Now()) {
		http.Error(w, "refresh token expired", http.StatusUnauthorized)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	if session.IpAddress != ip {
		err = h.smtpProvider.SendMail(fmt.Sprintf("Your address has changed: was %s, now %s", session.IpAddress, ip))
		if err != nil {
			http.Error(w, "error sending email", http.StatusInternalServerError)
			return
		}
	}

	newAccessToken, _, err := h.jwtCreator.CreateToken(refreshClaims.ID, ip, 30*time.Minute, "")
	if err != nil {
		http.Error(w, "error creating token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newRefreshClaims, err := h.jwtCreator.CreateToken(refreshClaims.ID, ip, 24*time.Hour, refreshClaims.RegisteredClaims.ID)
	if err != nil {
		http.Error(w, "error creating token", http.StatusInternalServerError)
		return
	}

	newRefreshTokenSha256 := sha256.Sum256([]byte(newRefreshToken))
	newRefreshTokenHash, err := bcrypt.GenerateFromPassword(newRefreshTokenSha256[:], bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "error hashing refresh token", http.StatusInternalServerError)
		return
	}

	err = h.repoService.UpdateSession(&types.Session{
		Id:           refreshClaims.RegisteredClaims.ID,
		RefreshToken: string(newRefreshTokenHash),
		IpAddress:    ip,
		ExpiresAt:    newRefreshClaims.RegisteredClaims.ExpiresAt.Time,
	})
	if err != nil {
		http.Error(w, "error updating session", http.StatusInternalServerError)
		return
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	result.AccessToken = newAccessToken
	result.RefreshToken = newRefreshToken

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}
