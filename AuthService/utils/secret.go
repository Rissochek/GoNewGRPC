package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func GetSecretKeyFromEnv() string{
	if err := godotenv.Load(); err != nil {
		log.Fatalf("no .env file found") //if u have this error, but .env file is existing then try to execute with this command go run .\cmd\server\main.go
	}

	secret, exists := os.LookupEnv("SECRET_KEY")
	if !exists {
		log.Fatalf("secret key value is not set in .env file.")
	}

	return secret
}