package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "Proto"
)

var (
	grpc_auth_address = flag.String("grpc-auth_addr", "localhost:8888", "this is address of grpc server that handles reg and login functions")
	http_address = flag.String("http-addr", "localhost:8880", "this is address of http handler that responsible for interacting with api of project")
)

func main(){
	flag.Parse()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err := pb.RegisterAuthHandlerFromEndpoint(ctx, mux, *grpc_auth_address, opts)
	if err != nil{
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
	
	log.Printf("HTTP server listening on %s", *http_address)
    log.Fatal(http.ListenAndServe(*http_address, mux))
}