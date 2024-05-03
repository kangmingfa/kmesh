package maglev

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/suite"
	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/endpoint"
)


func TestMaglevTestSuite(t *testing.T)  {
	suite.Run(t, new(MaglevTestSuite))
}

type MaglevTestSuite struct{
	suite.Suite
}

func (suite *MaglevTestSuite) SetupSuite()  {
	InitMaglevMap()
}

func (suite *MaglevTestSuite) TearDownSuite()  {
	fmt.Println(">>> From TearDownSuite")
}

func (suite *MaglevTestSuite) TestCreateLB() {
	lbEndpoints := make([]*endpoint.Endpoint, 0)
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port: 0,
			Ipv4: 4369,
		},
	})
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port: 1,
			Ipv4: 4369,
		},
	})
	lbEndpoints = append(lbEndpoints, &endpoint.Endpoint{
		Address: &core.SocketAddress{
			Protocol: 0,
			Port: 1,
			Ipv4: 4369,
		},
	})
	localityLbEndpoints := make([]*endpoint.LocalityLbEndpoints, 0)
	llbep := &endpoint.LocalityLbEndpoints{
		LbEndpoints: lbEndpoints,
	}
	localityLbEndpoints = append(localityLbEndpoints, llbep)
	cluster := &cluster_v2.Cluster{
		Name: "cluser1",
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "cluster1",
			Endpoints: localityLbEndpoints,
		},
	}
	err := CreateLB(cluster)
	if err != nil {
		fmt.Println(err)
	}
}

