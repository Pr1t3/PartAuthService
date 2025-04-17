package types

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaims struct {
	Id        string `json:"id"`
	IpAddress string `json:"ip_address"`
	jwt.RegisteredClaims
}

func NewUserClaims(id string, ip string, duration time.Duration, tokenId string) (*UserClaims, error) {
	if tokenId == "" {
		tokenUUID, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("error generating token ID: %w", err)
		}
		tokenId = tokenUUID.String()
	}

	return &UserClaims{
		Id:        id,
		IpAddress: ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenId,
			Subject:   id,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}, nil
}
