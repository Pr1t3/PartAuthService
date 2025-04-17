package service

import (
	"PartAuthService/types"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtCreatorInterface interface {
	CreateToken(id string, ip string, duration time.Duration, tokenId string) (string, *types.UserClaims, error)
	VerifyToken(tokenString string) (*types.UserClaims, error)
}

type JwtCreator struct {
	secretKey string
}

func NewJwtCreator(secretKey string) *JwtCreator {
	return &JwtCreator{secretKey}
}

func (creator *JwtCreator) CreateToken(id string, ip string, duration time.Duration, tokenId string) (string, *types.UserClaims, error) {
	claims, err := types.NewUserClaims(id, ip, duration, tokenId)
	if err != nil {
		return "", nil, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenStr, err := token.SignedString([]byte(creator.secretKey))
	if err != nil {
		return "", nil, fmt.Errorf("error signing token: %w", err)
	}

	return tokenStr, claims, nil
}

func (creator *JwtCreator) VerifyToken(tokenStr string) (*types.UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &types.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("invalid token signing method")
		}

		return []byte(creator.secretKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	claims, ok := token.Claims.(*types.UserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
