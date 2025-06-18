package interceptors

import (
	"context"
	"errors"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type (
	Validator interface {
		ValidateToken(ctx context.Context, token string) error
	}

	BlacklistChecker interface{
		BlacklistCkeck(ctx context.Context, token string) error
	}

	auth_interceptor struct {
		Validator Validator
		Checker BlacklistChecker
	}
)

func NewAuthInterceptor(validator Validator, checker BlacklistChecker) (*auth_interceptor, error) {
	if validator == nil {
		return nil, errors.New("validator cannot be nil")
	}
	if checker == nil {
		return nil, errors.New("checker cannot be nil")
	}
	return &auth_interceptor{Validator: validator, Checker: checker}, nil
}

func (i *auth_interceptor) UnaryTokenValidationMiddleware(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error){
	log.Printf("%v", info.FullMethod)
	publicMethods := map[string]bool{
        "/proto.Auth/Registration":    true,
        "/proto.Auth/Login": true,
    }
    
    // Пропускаем аутентификацию для публичных методов
    if publicMethods[info.FullMethod] {
        return handler(ctx, req)
    }
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	bearer_token := md.Get("authorization")
	log.Printf("bearer token: %v", bearer_token)
	if len(bearer_token) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization token is not provided")
	}
	
	if err := i.Validator.ValidateToken(ctx, bearer_token[0]); err != nil{
		log.Printf("error: %v", err)
		return nil, err
	}

	if err := i.Checker.BlacklistCkeck(ctx, bearer_token[0]); err != nil{
		return nil, status.Error(codes.Unauthenticated, "token is blacklisted")
	}

	return handler(ctx, req)
}