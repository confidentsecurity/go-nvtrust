package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nras"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvswitch"
)

func main() {
	fmt.Println("NVSwitch Evidence Collection Sample")
	fmt.Println("====================================\n")

	// Create switch admin
	fmt.Println("Creating NVSwitch admin...")
	handler, err := gonscq.NewHandler()
	if err != nil {
		log.Fatalf("Failed to create handler: %v", err)
	}
	switchAdmin, err := nvswitch.NewNscqSwitchAdmin(handler)
	if err != nil {
		log.Fatalf("Failed to create switch admin: %v", err)
	}
	defer switchAdmin.Shutdown()
	fmt.Println("Switch admin created successfully\n")

	// Generate a random nonce (32 bytes)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("Failed to generate nonce: %v", err)
	}
	fmt.Printf("Generated nonce: %s\n\n", hex.EncodeToString(nonce))

	// Collect evidence from all switches
	fmt.Println("Collecting evidence from all NVSwitches...")
	switchInfos, err := switchAdmin.CollectEvidence(nonce)
	if err != nil {
		log.Fatalf("Failed to collect evidence: %v", err)
	}

	fmt.Printf("Successfully collected evidence from %d NVSwitch(es)\n\n", len(switchInfos))

	// Display information about each switch
	for i, info := range switchInfos {
		fmt.Printf("Switch #%d:\n", i+1)
		fmt.Printf("  UUID: %s\n", info.UUID())
		fmt.Printf("  Architecture: %s\n", info.Arch())
		fmt.Printf("  Attestation Report Size: %d bytes\n", len(info.AttestationReport()))
		fmt.Printf("  Certificate Chain: Verified\n")
		fmt.Println()
	}

	nrasClient := nras.NewNRASClient(http.DefaultClient)
	sRemoteAttester := gonvtrust.NewRemoteAttester(switchAdmin, nrasClient)
	result, err := sRemoteAttester.Attest(context.Background(), nonce)
	if err != nil {
		log.Fatalf("Failed to attest: %v", err)
	}
	fmt.Printf("Attestation result: %v\n", result.Result)
	fmt.Printf("JWT token: %v\n", result.JWTToken.Raw)
	fmt.Printf("Devices tokens: %v\n", result.DevicesTokens)

	gpuAdmin, err := gpu.NewNvmlGPUAdmin(nil)
	if err != nil {
		log.Fatalf("Failed to create GPU admin: %v", err)
	}
	defer gpuAdmin.Shutdown()
	gRemoteAttester := gonvtrust.NewRemoteAttester(gpuAdmin, nrasClient)
	result, err = gRemoteAttester.Attest(context.Background(), nonce)
	if err != nil {
		log.Fatalf("Failed to attest: %v", err)
	}
	fmt.Printf("Attestation result: %v\n", result.Result)
	fmt.Printf("JWT token: %v\n", result.JWTToken.Raw)
	fmt.Printf("Devices tokens: %v\n", result.DevicesTokens)

	fmt.Println("Evidence collection completed successfully")
}
