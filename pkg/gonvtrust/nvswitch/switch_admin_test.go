// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nvswitch_test

import (
	"errors"
	"testing"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/mocks"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvswitch"
	"github.com/stretchr/testify/require"
)

type MockNvSwitchHandler struct {
	openFunc                                 func() error
	getAllSwitchUUIDsFunc                    func() ([]string, error)
	isSwitchTnvlModeFunc                     func(device string) (bool, error)
	isSwitchLockModeFunc                     func(device string) (bool, error)
	getSwitchArchitectureFunc                func() (gonscq.Arch, error)
	getSwitchAttestationReportFunc           func(device string, nonce []byte) ([]byte, error)
	getSwitchAttestationCertificateChainFunc func(device string) ([]byte, error)
	closeFunc                                func()
}

func (m *MockNvSwitchHandler) Open() error {
	if m.openFunc != nil {
		return m.openFunc()
	}
	return nil
}

func (m *MockNvSwitchHandler) GetAllSwitchUUIDs() ([]string, error) {
	if m.getAllSwitchUUIDsFunc != nil {
		return m.getAllSwitchUUIDsFunc()
	}
	return []string{"test-uuid-1"}, nil
}

func (m *MockNvSwitchHandler) IsSwitchTnvlMode(device string) (bool, error) {
	if m.isSwitchTnvlModeFunc != nil {
		return m.isSwitchTnvlModeFunc(device)
	}
	return true, nil
}

func (m *MockNvSwitchHandler) IsSwitchLockMode(device string) (bool, error) {
	if m.isSwitchLockModeFunc != nil {
		return m.isSwitchLockModeFunc(device)
	}
	return true, nil
}

func (m *MockNvSwitchHandler) GetSwitchArchitecture() (gonscq.Arch, error) {
	if m.getSwitchArchitectureFunc != nil {
		return m.getSwitchArchitectureFunc()
	}
	return gonscq.ArchLS10, nil
}

func (m *MockNvSwitchHandler) GetSwitchAttestationReport(device string, nonce []byte) ([]byte, error) {
	if m.getSwitchAttestationReportFunc != nil {
		return m.getSwitchAttestationReportFunc(device, nonce)
	}
	return []byte("mock-attestation-report"), nil
}

func (m *MockNvSwitchHandler) GetSwitchAttestationCertificateChain(device string) ([]byte, error) {
	if m.getSwitchAttestationCertificateChainFunc != nil {
		return m.getSwitchAttestationCertificateChainFunc(device)
	}
	return mocks.ValidCertChainData, nil
}

func (m *MockNvSwitchHandler) Close() {
	if m.closeFunc != nil {
		m.closeFunc()
	}
}

func TestNewNscqSwitchAdmin(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)

		require.NoError(t, err)
		require.NotNil(t, admin)
	})

	t.Run("NilHandler", func(t *testing.T) {
		admin, err := nvswitch.NewNscqSwitchAdmin(nil)

		require.Error(t, err)
		require.Nil(t, admin)
		require.Contains(t, err.Error(), "missing nvswitch handler")
	})

	t.Run("OpenFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			openFunc: func() error {
				return errors.New("open failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)

		require.Error(t, err)
		require.Nil(t, admin)
		require.Contains(t, err.Error(), "failed to open NSCQ handler")
	})
}

func TestCollectEvidence(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		nonce := []byte("test-nonce")
		switchInfos, err := admin.CollectEvidence(nonce)

		require.NoError(t, err)
		require.Len(t, switchInfos, 1)
		require.Equal(t, "test-uuid-1", switchInfos[0].UUID())
		require.Equal(t, "LS10", switchInfos[0].Arch())
		require.NotNil(t, switchInfos[0].AttestationReport())
		require.NotNil(t, switchInfos[0].Certificate())
	})

	t.Run("NoSwitchesFound", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getAllSwitchUUIDsFunc: func() ([]string, error) {
				return []string{}, nil
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "no NVSwitch devices found")
	})

	t.Run("GetUUIDsFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getAllSwitchUUIDsFunc: func() ([]string, error) {
				return nil, errors.New("get UUIDs failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to get switch UUIDs")
	})

	t.Run("NotInTnvlMode", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			isSwitchTnvlModeFunc: func(_ string) (bool, error) {
				return false, nil
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "is not in TNVL mode")
	})

	t.Run("TnvlModeCheckFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			isSwitchTnvlModeFunc: func(_ string) (bool, error) {
				return false, errors.New("TNVL check failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to check TNVL mode")
	})

	t.Run("NotInLockMode", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			isSwitchLockModeFunc: func(_ string) (bool, error) {
				return false, nil
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "is not in lock mode")
	})

	t.Run("LockModeCheckFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			isSwitchLockModeFunc: func(_ string) (bool, error) {
				return false, errors.New("lock check failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to check lock mode")
	})

	t.Run("ArchitectureFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getSwitchArchitectureFunc: func() (gonscq.Arch, error) {
				return gonscq.ArchLS10, errors.New("architecture check failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to get switch architecture")
	})

	t.Run("AttestationReportFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getSwitchAttestationReportFunc: func(_ string, _ []byte) ([]byte, error) {
				return nil, errors.New("get report failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to get attestation report")
	})

	t.Run("CertificateChainFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getSwitchAttestationCertificateChainFunc: func(_ string) ([]byte, error) {
				return nil, errors.New("get cert chain failed")
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to get certificate chain")
	})

	t.Run("InvalidCertificateFailure", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getSwitchAttestationCertificateChainFunc: func(_ string) ([]byte, error) {
				return mocks.InvalidCertChainData, nil
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.Error(t, err)
		require.Nil(t, switchInfos)
		require.Contains(t, err.Error(), "failed to verify certificate chain")
	})

	t.Run("MultipleSwitches", func(t *testing.T) {
		mockHandler := &MockNvSwitchHandler{
			getAllSwitchUUIDsFunc: func() ([]string, error) {
				return []string{"uuid-1", "uuid-2", "uuid-3"}, nil
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		switchInfos, err := admin.CollectEvidence([]byte("nonce"))

		require.NoError(t, err)
		require.Len(t, switchInfos, 3)
		require.Equal(t, "uuid-1", switchInfos[0].UUID())
		require.Equal(t, "uuid-2", switchInfos[1].UUID())
		require.Equal(t, "uuid-3", switchInfos[2].UUID())
	})

	t.Run("NonceValidation", func(t *testing.T) {
		expectedNonce := []byte("expected-nonce-value")
		nonceCaptured := false

		mockHandler := &MockNvSwitchHandler{
			getSwitchAttestationReportFunc: func(_ string, nonce []byte) ([]byte, error) {
				require.Equal(t, expectedNonce, nonce)
				nonceCaptured = true
				return []byte("mock-report"), nil
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		_, err = admin.CollectEvidence(expectedNonce)

		require.NoError(t, err)
		require.True(t, nonceCaptured)
	})
}

func TestShutdown(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		closeCalled := false
		mockHandler := &MockNvSwitchHandler{
			closeFunc: func() {
				closeCalled = true
			},
		}
		admin, err := nvswitch.NewNscqSwitchAdmin(mockHandler)
		require.NoError(t, err)
		require.NotNil(t, admin)

		err = admin.Shutdown()

		require.NoError(t, err)
		require.True(t, closeCalled)
	})
}
