// Code generated by bpf2go; DO NOT EDIT.
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadCluster returns the embedded CollectionSpec for Cluster.
func LoadCluster() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ClusterBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Cluster: %w", err)
	}

	return spec, err
}

// LoadClusterObjects loads Cluster and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *ClusterObjects
//     *ClusterPrograms
//     *ClusterMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadClusterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadCluster()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// ClusterSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ClusterSpecs struct {
	ClusterProgramSpecs
	ClusterMapSpecs
}

// ClusterSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ClusterProgramSpecs struct {
	ClusterManager *ebpf.ProgramSpec `ebpf:"cluster_manager"`
}

// ClusterMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ClusterMapSpecs struct {
	Cluster      *ebpf.MapSpec `ebpf:"cluster"`
	Endpoint     *ebpf.MapSpec `ebpf:"endpoint"`
	TailCallCtx  *ebpf.MapSpec `ebpf:"tail_call_ctx"`
	TailCallProg *ebpf.MapSpec `ebpf:"tail_call_prog"`
}

// ClusterObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadClusterObjects or ebpf.CollectionSpec.LoadAndAssign.
type ClusterObjects struct {
	ClusterPrograms
	ClusterMaps
}

func (o *ClusterObjects) Close() error {
	return _ClusterClose(
		&o.ClusterPrograms,
		&o.ClusterMaps,
	)
}

// ClusterMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadClusterObjects or ebpf.CollectionSpec.LoadAndAssign.
type ClusterMaps struct {
	Cluster      *ebpf.Map `ebpf:"cluster"`
	Endpoint     *ebpf.Map `ebpf:"endpoint"`
	TailCallCtx  *ebpf.Map `ebpf:"tail_call_ctx"`
	TailCallProg *ebpf.Map `ebpf:"tail_call_prog"`
}

func (m *ClusterMaps) Close() error {
	return _ClusterClose(
		m.Cluster,
		m.Endpoint,
		m.TailCallCtx,
		m.TailCallProg,
	)
}

// ClusterPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadClusterObjects or ebpf.CollectionSpec.LoadAndAssign.
type ClusterPrograms struct {
	ClusterManager *ebpf.Program `ebpf:"cluster_manager"`
}

func (p *ClusterPrograms) Close() error {
	return _ClusterClose(
		p.ClusterManager,
	)
}

func _ClusterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed cluster_bpfeb.o
var _ClusterBytes []byte
