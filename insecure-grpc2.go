package insecuregrpc

import (
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httptest"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// cf. https://blog.gopheracademy.com/advent-2019/go-grps-and-tls/#connection-without-encryption
func unsafe() {
	// Server


	// ... register gRPC services ...
	if err = s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}