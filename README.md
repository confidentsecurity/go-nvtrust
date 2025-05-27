# go-nvtrust

WIP intended to mirror the functionality of https://github.com/nvidia/nvtrust in golang.

Relies on NVIDIA/go-nvml to retrieve GPU measurements.

## System Requirements:

- NVIDIA Hopper H100 GPU or newer

- GPU SKU with Confidential Compute(CC)

- NVIDIA GPU driver installed

## Supported features

- Retrieve attestation report from GPUs

Sample:

```
nonce := []byte("nonce_value")
attester := gonvtrust.NewRemoteGPUAttester(nil)
hash := sha256.Sum256(nonce)
evidenceList, err := attester.GetRemoteEvidence(hash[:])
```

## Tests

```
go test -v ./pkg/...
```

## Integration Tests

```
go test -tags=gpu_integration -v ./pkg/...
```
