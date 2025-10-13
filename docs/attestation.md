High level attestation flow for PPCIE https://docs.nvidia.com/attestation/attestation-client-tools-ppcie/latest-internal/ppcie_architecture.html#detailed-architecture-flow:
<img width="2390" height="906" alt="image" src="https://github.com/user-attachments/assets/bdbfa1ef-8e5f-4da1-8775-85ac1bee89c7" />

```
1) The PPCIE Verifier tool is initiated by the user, who specifies the attestation mode for both GPUs and NvSwitches.
2) The system components are enumerated (number of GPUs and NvSwitches).
3) Pre-checks are performed on each GPU to ensure it is configured for confidential computing.
4) Pre-checks are performed on each NvSwitch to ensure it is configured for confidential computing.
5) The required GPU evidence for attestation is collected from the Attestation SDK for each GPU.
6) Once the evidence is collected, the PPCIE Verifier tool initiates attestation verification based on the
 mode specified by the user.
7) GPU attestation is initiated by the Attestation SDK: NRAS (NVIDIA’s Remote Attestation Service)
is used for remote attestation.
8) The Attestation SDK provides GPU attestation results to the PPCIE Verifier.
9) If the GPU attestation is successful, the PPCIE Verifier proceeds to collect evidence
for the NvSwitches from the Attestation SDK.
10) Once all NvSwitch evidence is collected, attestation is initiated by the PPCIE Verifier.
11) NvSwitch attestation is performed by the Attestation SDK: NRAS is used for remote attestation.
12) The Attestation SDK provides NvSwitch attestation results to the PPCIE Verifier.
13) If the NvSwitch attestation is successful, the PPCIE Verifier performs a topology check to ensure the devices
are securely connected in the expected configuration.
14) The PPCIE Verifier determines the overall results and updates the status for each check it performs.
15) The GPU ready state is set.
16) The final attestation results are presented to the user, detailing the checks performed and the status
of each device in the system.
```
