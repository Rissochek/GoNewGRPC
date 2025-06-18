package auth

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"

	"AuthProject/model"
	"AuthProject/utils"
)

type JWTCustomClaims struct {
	Username string
	UserId   uint
	jwt.StandardClaims
}

type JWTManager struct {
	SecretKey     string
	TokenDuration time.Duration
}

func NewJWTManager(token_duration time.Duration) *JWTManager {
	secret := utils.GetSecretKeyFromEnv()
	return &JWTManager{TokenDuration: token_duration, SecretKey: secret}
}

func (manager *JWTManager) GenerateJWT(user *model.User) (string, error) {
	claims := JWTCustomClaims{
		Username: user.Usermame,
		UserId:   user.UserId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.TokenDuration).Unix()},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(manager.SecretKey))
}

func (manager *JWTManager) VerifyJWT(user_token string) (*JWTCustomClaims, error) {
	user_token, err := ExtractToken(user_token)
	if err != nil{
		return nil, err
	}
	token, err := jwt.ParseWithClaims(
		user_token,
		&JWTCustomClaims{},
		func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("wrong jwt encrypting method")
			}

			return []byte(manager.SecretKey), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTCustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}

func (manager *JWTManager) ValidateToken(ctx context.Context, token string) error {
	_, err := manager.VerifyJWT(token)
	log.Printf("invalid token: %v", err)
	if err != nil {
		return err
	}
	return nil
}

func ExtractToken(bearerToken string) (string, error) {
	if !strings.HasPrefix(bearerToken, "Bearer ") {
		return "", fmt.Errorf("invalid token format")
	}

	token := strings.TrimPrefix(bearerToken, "Bearer ")
	return token, nil
}
