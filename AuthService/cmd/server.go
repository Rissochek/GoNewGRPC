package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"AuthProject/auth"
	"AuthProject/database"
	"AuthProject/interceptors"
	"AuthProject/model"
	pb "Proto"
)

var (
	port			= flag.Int("port", 8888, "server port")
	pgdb			= database.InitDataBase()
	rdb				= database.NewRedisManager()
	exparation_time = time.Minute * 15
	manager			= auth.NewJWTManager(exparation_time)
)

type server struct {
	pb.UnimplementedAuthServer
}

func (s *server) Login(ctx context.Context, login_req *pb.LoginMsg) (*pb.LoginReply, error) {
	user := model.User{Usermame: login_req.Username, Password: login_req.Password}
	pgdb_user, err := database.SearchUserInDB(pgdb, &user)
	if err != nil {
		return &pb.LoginReply{Status: err.Error()}, err
	}

	token, err := manager.GenerateJWT(&pgdb_user)
	if err != nil {
		return &pb.LoginReply{Status: err.Error()}, err
	}
	bearer_token := fmt.Sprintf("%s %s", "Bearer", token)
	return &pb.LoginReply{Status: "Success", Token: bearer_token}, nil
}

func (s *server) Registration(ctx context.Context, reg_req *pb.RegMsg) (*pb.RegReply, error) {
	user := model.User{Usermame: reg_req.Username, Password: reg_req.Password}
	err := database.AddUserToDataBase(pgdb, &user)
	if err != nil {
		return &pb.RegReply{Status: err.Error()}, err
	}
	return &pb.RegReply{Status: "Success"}, nil
}

func (s *server) Logout(ctx context.Context, logout_req *pb.LogoutMsg) (*pb.LogoutReply, error){
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	bearer_token := md.Get("authorization")[0]
	claims, err := manager.VerifyJWT(bearer_token)
	if err != nil {
		return &pb.LogoutReply{Status: "Failed"}, status.Error(codes.Unauthenticated, "invalid token")
	}
	token, _ := auth.ExtractToken(bearer_token)
	if err := rdb.AddToBlacklist(token, claims.ExpiresAt, ctx); err != nil {
		return &pb.LogoutReply{Status: "Failed"}, err
	}
	return &pb.LogoutReply{Status: "Success"}, nil
}
func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen %v", err)
	}

	var opts []grpc.ServerOption
	auth_interceptor, err := interceptors.NewAuthInterceptor(manager, rdb)
	if err != nil {
		log.Fatalf("failed to initialize interceptor: %v", err)
	}
	opts = append(opts, grpc.UnaryInterceptor(auth_interceptor.UnaryTokenValidationMiddleware))
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthServer(grpcServer, &server{})
	log.Printf("Server listening on: %v", lis.Addr())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
