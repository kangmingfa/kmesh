package maglev

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
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
	dummyInnerMapSpec := newMaglevInnerMapSpec(uint32(DefaultTableSize))
	_, err := NewMaglevOuterMap(MaglevOuterMapName, MaglevMapMaxEntries, uint32(DefaultTableSize), dummyInnerMapSpec)
	if err != nil {
		fmt.Printf("NewMaglevOuterMap err: %v\n",err)
	}
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
		Name: "cluser2",
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "cluster2",
			Endpoints: localityLbEndpoints,
		},
	}
	err := CreateLB(cluster)
	if err != nil {
		fmt.Println(err)
	}
}

// newMaglevInnerMapSpec returns the spec for a maglev inner map.
func newMaglevInnerMapSpec(tableSize uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "cilium_maglev_inner",
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))) * tableSize,
		MaxEntries: 1,
	}
}

// NewMaglevOuterMap returns a new object representing a maglev outer map.
func NewMaglevOuterMap(name string, maxEntries int, tableSize uint32, innerMap *ebpf.MapSpec) (*ebpf.Map, error) {
	m ,err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    ClusterNameMaxLen,
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
		Pinning:    ebpf.PinByName,
	},ebpf.MapOptions{
		PinPath: "/sys/fs/bpf",
	})
	// if err := m.Pin(name); err != nil {
	// 	return nil, err
	// }

	if err != nil {
		return nil, err
	}

	return m, nil
}
