package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"

	"AuthProject/auth"
	"AuthProject/database"
	"AuthProject/model"
	pb "Proto"
)

var (
	port    = flag.Int("port", 8888, "server port")
	db      = database.InitDataBase()
	manager = auth.JWTManager{TokenDuration: time.Minute * 10}
)

type server struct {
	pb.UnimplementedAuthServer
}

func (s *server) Login(ctx context.Context, login_req *pb.LoginMsg) (*pb.LoginReply, error) {
	user := model.User{Usermame: login_req.Username, Password: login_req.Password}
	db_user, err := database.SearchUserInDB(db, &user)
	if err != nil {
		return &pb.LoginReply{Status: err.Error()}, err
	}

	token, err := manager.GenerateJWT(&db_user)
	if err != nil {
		return &pb.LoginReply{Status: err.Error()}, err
	}
	bearer_token := fmt.Sprintf("%s %s", "Bearer", token)
	return &pb.LoginReply{Status: "Success", Token: bearer_token}, nil
}

func (s *server) Registration(ctx context.Context, reg_req *pb.RegMsg) (*pb.RegReply, error) {
	user := model.User{Usermame: reg_req.Username, Password: reg_req.Password}
	err := database.AddUserToDataBase(db, &user)
	if err != nil {
		return &pb.RegReply{Status: err.Error()}, err
	}
	return &pb.RegReply{Status: "Success"}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen %v", err)
	}

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAuthServer(grpcServer, &server{})
	log.Printf("Server listening on: %v", lis.Addr())

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
