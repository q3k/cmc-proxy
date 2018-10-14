package main

import (
	"context"
	"flag"

	"code.hackerspace.pl/q3k/mirko"
	"github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "code.hackerspace.pl/q3k/cmc-proxy/proto"
)

var (
	flagCMCAddress  string
	flagCMCUsername string
	flagCMCPassword string
)

const (
	pathLogin    = "cgi-bin/webcgi/login"
	pathLogout   = "cgi-bin/webcgi/logout"
	pathiDRACURL = "cgi-bin/webcgi/blade_iDRAC_url"
)

func init() {
	flag.Set("logtostderr", "true")
}

type service struct {
	cmc *cmcClient
}

func (s *service) GetKVMData(ctx context.Context, req *pb.GetKVMDataRequest) (*pb.GetKVMDataResponse, error) {
	if req.BladeNum < 1 || req.BladeNum > 16 {
		return nil, status.Error(codes.InvalidArgument, "blade_num must be [1,16]")
	}

	details, err := s.cmc.RequestKVMDetails(ctx, int(req.BladeNum))
	if err != nil {
		glog.Errorf("RequestKVMDetails(_, %d): %v", req.BladeNum, err)
		return nil, status.Error(codes.Unavailable, "CMC unavailable")
	}

	return &pb.GetKVMDataResponse{
		Arguments: details.arguments,
	}, nil
}

func main() {
	flag.StringVar(&flagCMCAddress, "cmc_address", "https://10.10.10.10", "URL of Dell M1000e CMC")
	flag.StringVar(&flagCMCUsername, "cmc_username", "root", "Login username for CMC")
	flag.StringVar(&flagCMCPassword, "cmc_password", "", "Login password for CMC")
	flag.Parse()

	m := mirko.New()
	if err := m.Listen(); err != nil {
		glog.Exitf("Could not listen: %v", err)
	}

	s := &service{
		cmc: NewCMCClient(),
	}
	pb.RegisterCMCProxyServer(m.GRPC(), s)

	if err := m.Serve(); err != nil {
		glog.Exitf("Could not run: %v", err)
	}

	go s.cmc.Run(m.Context())
	glog.Info("Running.")

	<-m.Done()
}
