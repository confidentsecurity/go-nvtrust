package gonvtrust

import (
	_ "embed"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

//go:embed mocks/gpuAkCertChain.txt
var certChainData []byte

//go:embed mocks/attestationReport.txt
var attestationReportData []byte

type NvmlHandler interface {
	Init() nvml.Return
	DeviceGetCount() (int, nvml.Return)
	DeviceGetHandleByIndex(i int) (NvmlDevice, nvml.Return)
	SystemGetDriverVersion() (string, nvml.Return)
	SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return)
}

type NvmlHandlerImpl struct {
}

func (n *NvmlHandlerImpl) Init() (ret nvml.Return) {
	return nvml.Init()
}

func (n *NvmlHandlerImpl) SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return) {
	computeState, ret := nvml.SystemGetConfComputeState()
	return computeState, ret
}

func (n *NvmlHandlerImpl) DeviceGetCount() (int, nvml.Return) {
	return nvml.DeviceGetCount()
}

func (n *NvmlHandlerImpl) DeviceGetHandleByIndex(i int) (NvmlDevice, nvml.Return) {
	d, ret := nvml.DeviceGetHandleByIndex(i)
	if ret != nvml.SUCCESS {
		return nil, ret
	}
	return &NvmlDeviceImpl{
		device: d,
	}, nvml.SUCCESS
}

func (n *NvmlHandlerImpl) SystemGetDriverVersion() (string, nvml.Return) {
	return nvml.SystemGetDriverVersion()
}

type NvmlDevice interface {
	GetDevice() nvml.Device
	GetUUID() (string, nvml.Return)
	GetBoardId() (uint32, nvml.Return)
	GetArchitecture() (nvml.DeviceArchitecture, nvml.Return)
	GetVbiosVersion() (string, nvml.Return)
	GetConfComputeGpuAttestationReport() (nvml.ConfComputeGpuAttestationReport, nvml.Return)
	GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return)
}

type NvmlDeviceImpl struct {
	device nvml.Device
}

func (n *NvmlDeviceImpl) GetDevice() nvml.Device {
	return n.device
}

func (n *NvmlDeviceImpl) GetUUID() (string, nvml.Return) {
	return n.device.GetUUID()
}

func (n *NvmlDeviceImpl) GetBoardId() (uint32, nvml.Return) {
	return nvml.DeviceGetBoardId(n.device)
}

func (n *NvmlDeviceImpl) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	return nvml.DeviceGetArchitecture(n.device)
}

func (n *NvmlDeviceImpl) GetVbiosVersion() (string, nvml.Return) {
	return nvml.DeviceGetVbiosVersion(n.device)
}

func (n *NvmlDeviceImpl) GetConfComputeGpuAttestationReport() (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
	return nvml.DeviceGetConfComputeGpuAttestationReport(n.device)
}

func (n *NvmlDeviceImpl) GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	return nvml.DeviceGetConfComputeGpuCertificate(n.device)
}

type NvmlHandlerMock struct {
}

func (n *NvmlHandlerMock) Init() nvml.Return {
	return nvml.SUCCESS
}

func (n *NvmlHandlerMock) SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return) {

	return nvml.ConfComputeSystemState{
		CcFeature: 1,
	}, nvml.SUCCESS
}

func (n *NvmlHandlerMock) DeviceGetCount() (int, nvml.Return) {
	return 1, nvml.SUCCESS
}

func (n *NvmlHandlerMock) DeviceGetHandleByIndex(i int) (NvmlDevice, nvml.Return) {
	return &NvmlDeviceMock{}, nvml.SUCCESS
}

func (n *NvmlHandlerMock) SystemGetDriverVersion() (string, nvml.Return) {
	return "fake-driver-version", nvml.SUCCESS
}

type NvmlDeviceMock struct {
}

func (n *NvmlDeviceMock) GetDevice() nvml.Device {
	return nil
}

func (n *NvmlDeviceMock) GetUUID() (string, nvml.Return) {
	return "fake-uuid", nvml.SUCCESS
}

func (n *NvmlDeviceMock) GetBoardId() (uint32, nvml.Return) {
	return 1234, nvml.SUCCESS
}

func (n *NvmlDeviceMock) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	return nvml.DEVICE_ARCH_HOPPER, nvml.SUCCESS
}

func (n *NvmlDeviceMock) GetVbiosVersion() (string, nvml.Return) {
	return "fake-vbios-version", nvml.SUCCESS
}

func (n *NvmlDeviceMock) GetConfComputeGpuAttestationReport() (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
	var reportArray [8192]uint8
	copy(reportArray[:], attestationReportData)

	attestationReport := nvml.ConfComputeGpuAttestationReport{
		AttestationReport:     reportArray,
		AttestationReportSize: uint32(len(attestationReportData)),
	}
	return attestationReport, nvml.SUCCESS
}

func (n *NvmlDeviceMock) GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	var certArray [5120]uint8
	copy(certArray[:], certChainData)

	certificate := nvml.ConfComputeGpuCertificate{
		AttestationCertChain:     certArray,
		AttestationCertChainSize: uint32(len(certChainData)),
	}
	return certificate, nvml.SUCCESS
}
