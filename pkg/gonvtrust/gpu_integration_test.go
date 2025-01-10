//go:build gpu_integration

package gonvtrust_test

import (
	"crypto/rand"
	"testing"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/stretchr/testify/assert"
)

func TestGpuAttester_GetRemoteEvidence(t *testing.T) {
	// Test that GetRemoteEvidence returns RemoteEvidence for each device
	// and that the RemoteEvidence is valid.
	// This test requires a GPU to be present.
	// To run this test, use the following command:
	// go test -tags=gpu_integration -v -run TestGpuAttester_GetRemoteEvidence
	// This test will fail if no GPU is present.
	attester := gonvtrust.NewGpuAttester(nil)
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}
	evidence, err := attester.GetRemoteEvidence(nonce)
	assert.NoError(t, err)
	assert.NotEmpty(t, evidence)
	for _, remoteEvidence := range evidence {
		assert.NotEmpty(t, remoteEvidence.Certificate)
		assert.NotEmpty(t, remoteEvidence.Evidence)
	}
}
