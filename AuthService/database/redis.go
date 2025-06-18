package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"AuthProject/auth"
)
type redis_manager struct{
	RedisClient *redis.Client
}

func NewRedisManager() *redis_manager{
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6380",
		Password: "123",
		DB: 0,
	})
	
	return &redis_manager{RedisClient: client}
}

func (redis_manager *redis_manager) AddToBlacklist(token string, expiry int64, ctx context.Context) error {
	exparation_time := time.Duration(expiry - time.Now().Unix()) * time.Second
	if err := redis_manager.RedisClient.Set(ctx, token, "revoked", exparation_time); err != nil{
		return err.Err()
	}

	return nil
}

func (redis_manager *redis_manager) BlacklistCkeck(ctx context.Context, token string) error{
	user_token, err := auth.ExtractToken(token)
	if err != nil{
		return err
	}
	result, err := redis_manager.RedisClient.Get(ctx, user_token).Result()

	if result == "revoked" {
        return fmt.Errorf("token is revoked")
    }

	return nil
}