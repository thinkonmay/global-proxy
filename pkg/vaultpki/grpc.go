package vaultpki

import (
	"fmt"
	"math"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// GrpcDialOptions returns client options for virtdaemon↔virtdaemon gRPC.
// Pass nil to use plaintext (no mTLS).
func GrpcDialOptions(r *Reloadable) ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
	}
	if r == nil || r.Material() == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		return opts, nil
	}
	cfg, err := r.ClientTLSConfig()
	if err != nil {
		return nil, err
	}
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	return opts, nil
}

// GrpcServerCreds returns server transport credentials for mTLS, or nil when disabled.
func GrpcServerCreds(r *Reloadable) (grpc.ServerOption, error) {
	if r == nil || r.Material() == nil {
		return nil, nil
	}
	cfg, err := r.ServerTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("vault mTLS server: %w", err)
	}
	return grpc.Creds(credentials.NewTLS(cfg)), nil
}
