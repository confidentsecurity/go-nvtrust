package gonvtrust

import (
	_ "embed"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

//go:embed mocks/gpuAkCertChain.txt
var validCertChainData []byte

//go:embed mocks/attestationReport.txt
var attestationReportData []byte

type NvmlHandler interface {
	Init() nvml.Return
	DeviceGetCount() (int, nvml.Return)
	DeviceGetHandleByIndex(i int) (NVMLDevice, nvml.Return)
	SystemGetDriverVersion() (string, nvml.Return)
	SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return)
}

type DefaultNVMLHandler struct {
}

func (*DefaultNVMLHandler) Init() nvml.Return {
	return nvml.Init()
}

func (*DefaultNVMLHandler) SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return) {
	computeState, ret := nvml.SystemGetConfComputeState()
	return computeState, ret
}

func (*DefaultNVMLHandler) DeviceGetCount() (int, nvml.Return) {
	return nvml.DeviceGetCount()
}

func (*DefaultNVMLHandler) DeviceGetHandleByIndex(i int) (NVMLDevice, nvml.Return) {
	d, ret := nvml.DeviceGetHandleByIndex(i)
	if ret != nvml.SUCCESS {
		return nil, ret
	}
	return &DefaultNVMLDevice{
		device: d,
	}, nvml.SUCCESS
}

func (*DefaultNVMLHandler) SystemGetDriverVersion() (string, nvml.Return) {
	return nvml.SystemGetDriverVersion()
}

type NVMLDevice interface {
	GetDevice() nvml.Device
	GetUUID() (string, nvml.Return)
	GetBoardID() (uint32, nvml.Return)
	GetArchitecture() (nvml.DeviceArchitecture, nvml.Return)
	GetVbiosVersion() (string, nvml.Return)
	GetConfComputeGpuAttestationReport(nonce []byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return)
	GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return)
}

type DefaultNVMLDevice struct {
	device nvml.Device
}

func (n *DefaultNVMLDevice) GetDevice() nvml.Device {
	return n.device
}

func (n *DefaultNVMLDevice) GetUUID() (string, nvml.Return) {
	return n.device.GetUUID()
}

func (n *DefaultNVMLDevice) GetBoardID() (uint32, nvml.Return) {
	return nvml.DeviceGetBoardId(n.device)
}

func (n *DefaultNVMLDevice) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	return nvml.DeviceGetArchitecture(n.device)
}

func (n *DefaultNVMLDevice) GetVbiosVersion() (string, nvml.Return) {
	return nvml.DeviceGetVbiosVersion(n.device)
}

func (n *DefaultNVMLDevice) GetConfComputeGpuAttestationReport(nonce []byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
	return nvml.DeviceGetConfComputeGpuAttestationReportWithNonce(n.device, nonce)
}

func (n *DefaultNVMLDevice) GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	return nvml.DeviceGetConfComputeGpuCertificate(n.device)
}

type NVMLHandlerMock struct {
}

func (*NVMLHandlerMock) Init() nvml.Return {
	return nvml.SUCCESS
}

func (*NVMLHandlerMock) SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return) {
	return nvml.ConfComputeSystemState{
		CcFeature: 1,
	}, nvml.SUCCESS
}

func (*NVMLHandlerMock) DeviceGetCount() (int, nvml.Return) {
	return 1, nvml.SUCCESS
}

func (*NVMLHandlerMock) DeviceGetHandleByIndex(int) (NVMLDevice, nvml.Return) {
	return &NVMLDeviceMock{}, nvml.SUCCESS
}

func (*NVMLHandlerMock) SystemGetDriverVersion() (string, nvml.Return) {
	return "fake-driver-version", nvml.SUCCESS
}

type NVMLDeviceMock struct {
}

func (*NVMLDeviceMock) GetDevice() nvml.Device {
	return nil
}

func (*NVMLDeviceMock) GetUUID() (string, nvml.Return) {
	return "fake-uuid", nvml.SUCCESS
}

func (*NVMLDeviceMock) GetBoardID() (uint32, nvml.Return) {
	return 1234, nvml.SUCCESS
}

func (*NVMLDeviceMock) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	return nvml.DEVICE_ARCH_HOPPER, nvml.SUCCESS
}

func (*NVMLDeviceMock) GetVbiosVersion() (string, nvml.Return) {
	return "fake-vbios-version", nvml.SUCCESS
}

func (*NVMLDeviceMock) GetConfComputeGpuAttestationReport([]byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
	var reportArray [8192]uint8
	copy(reportArray[:], attestationReportData)

	attestationReport := nvml.ConfComputeGpuAttestationReport{
		AttestationReport:     reportArray,
		AttestationReportSize: uint32(len(attestationReportData)),
	}
	return attestationReport, nvml.SUCCESS
}

func (*NVMLDeviceMock) GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	var certArray [5120]uint8
	copy(certArray[:], validCertChainData)

	certificate := nvml.ConfComputeGpuCertificate{
		AttestationCertChain:     certArray,
		AttestationCertChainSize: uint32(len(validCertChainData)),
	}
	return certificate, nvml.SUCCESS
}
