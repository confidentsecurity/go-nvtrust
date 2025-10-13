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

package nvswitch

import (
	"errors"
	"fmt"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
)

type NscqSwitchAdmin struct {
	handler NvSwitchHandler
}

type NvSwitchHandler interface {
	Open() error
	GetAllSwitchUUIDs() ([]string, error)
	IsSwitchTnvlMode(device string) (bool, error)
	IsSwitchLockMode(device string) (bool, error)
	GetSwitchArchitecture() (gonscq.Arch, error)
	GetSwitchAttestationReport(device string, nonce []byte) ([]byte, error)
	GetSwitchAttestationCertificateChain(device string) ([]byte, error)
	Close()
}

type SwitchDevice struct {
	uuid                  string
	arch                  gonscq.Arch
	attestationReportData []byte
	certificateData       *certs.CertChain
}

func (d SwitchDevice) UUID() string {
	return d.uuid
}

func (d SwitchDevice) Arch() string {
	return d.arch.String()
}

func (d SwitchDevice) AttestationReport() []byte {
	return d.attestationReportData
}

func (d SwitchDevice) Certificate() *certs.CertChain {
	return d.certificateData
}

func NewNscqSwitchAdmin(h NvSwitchHandler) (*NscqSwitchAdmin, error) {
	if h == nil {
		return nil, errors.New("failed to create NSCQ admin: missing nvswitch handler")
	}

	if err := h.Open(); err != nil {
		return nil, fmt.Errorf("failed to open NSCQ handler: %w", err)
	}

	return &NscqSwitchAdmin{
		handler: h,
	}, nil
}

func (s *NscqSwitchAdmin) CollectEvidence(nonce []byte) ([]SwitchDevice, error) {
	uuids, err := s.handler.GetAllSwitchUUIDs()
	if err != nil {
		return nil, fmt.Errorf("failed to get switch UUIDs: %w", err)
	}

	if len(uuids) == 0 {
		return nil, errors.New("no NVSwitch devices found")
	}

	for _, uuid := range uuids {
		isTnvl, err := s.handler.IsSwitchTnvlMode(uuid)
		if err != nil {
			return nil, fmt.Errorf("failed to check TNVL mode for switch %s: %w", uuid, err)
		}
		if !isTnvl {
			return nil, fmt.Errorf("switch %s is not in TNVL mode", uuid)
		}

		isLocked, err := s.handler.IsSwitchLockMode(uuid)
		if err != nil {
			return nil, fmt.Errorf("failed to check lock mode for switch %s: %w", uuid, err)
		}
		if !isLocked {
			return nil, fmt.Errorf("switch %s is not in lock mode", uuid)
		}
	}

	arch, err := s.handler.GetSwitchArchitecture()
	if err != nil {
		return nil, fmt.Errorf("failed to get switch architecture: %w", err)
	}

	var switchInfos []SwitchDevice

	for _, uuid := range uuids {
		report, err := s.handler.GetSwitchAttestationReport(uuid, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation report for switch %s: %w", uuid, err)
		}

		certChainData, err := s.handler.GetSwitchAttestationCertificateChain(uuid)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate chain for switch %s: %w", uuid, err)
		}

		certChain := certs.NewCertChainFromData(certChainData)
		err = certChain.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain for switch %s: %w", uuid, err)
		}

		switchInfos = append(switchInfos, SwitchDevice{
			uuid:                  uuid,
			arch:                  arch,
			attestationReportData: report,
			certificateData:       certChain,
		})
	}

	return switchInfos, nil
}

func (s *NscqSwitchAdmin) Shutdown() error {
	s.handler.Close()
	return nil
}
