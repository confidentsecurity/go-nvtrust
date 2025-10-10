package main

import (
	"fmt"
	"log"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
)

func main() {
	fmt.Println("NSCQ Sample Application")
	fmt.Println("=======================\n")

	fmt.Println("Loading NSCQ library and creating session...")
	handler, err := gonscq.NewHandler()
	if err != nil {
		log.Fatalf("Failed to create handler: %v", err)
	}
	err = handler.Open()
	if err != nil {
		log.Fatalf("Failed to open handler: %v", err)
	}
	defer handler.Close()
	fmt.Println("Library loaded and session created successfully\n")

	fmt.Println("Querying all NVSwitch UUIDs...")
	uuids, err := handler.GetAllSwitchUUIDs()
	if err != nil {
		log.Fatalf("Failed to get UUIDs: %v", err)
	}
	fmt.Printf("Found %d NVSwitch device(s)\n", len(uuids))
	for i, uuid := range uuids {
		fmt.Printf("  [%d] %s\n", i+1, uuid)
	}
	fmt.Println()

	if len(uuids) == 0 {
		log.Fatalf("No NVSwitch devices found")
	}

	fmt.Println("Checking TNVL mode and lock mode for all devices...")
	allTnvlEnabled := true
	allLocked := true

	for _, deviceUUID := range uuids {
		isTnvlMode, err := handler.IsSwitchTnvlMode(deviceUUID)
		if err != nil {
			log.Fatalf("Failed to check TNVL mode for device %s: %v", deviceUUID, err)
		}
		if !isTnvlMode {
			fmt.Printf("TNVL mode is NOT enabled on device %s\n", deviceUUID)
			allTnvlEnabled = false
		} else {
			fmt.Printf("TNVL mode is enabled on device %s\n", deviceUUID)
		}

		isLockMode, err := handler.IsSwitchLockMode(deviceUUID)
		if err != nil {
			log.Fatalf("Failed to check lock mode for device %s: %v (return code: %v)", deviceUUID, err)
		}
		if !isLockMode {
			fmt.Printf("Lock mode is NOT enabled on device %s\n", deviceUUID)
			allLocked = false
		} else {
			fmt.Printf("Lock mode is enabled on device %s\n", deviceUUID)
		}
	}

	if !allTnvlEnabled {
		log.Fatalf("\nError: TNVL mode is not enabled on all devices")
	}
	if !allLocked {
		log.Fatalf("\nError: Lock mode is not enabled on all devices")
	}

	fmt.Println("\n All devices have TNVL mode and lock mode enabled\n")

	fmt.Println("Querying NVSwitch architecture...")
	arch, err := handler.GetSwitchArchitecture()
	if err != nil {
		log.Fatalf("Failed to get architecture: %v", err)
	}

	fmt.Printf("NVSwitch Architecture: %s\n", arch.String())

	fmt.Println("Cleaning up session and unloading library...")
	handler.Close()
	fmt.Println("Session destroyed and library unloaded successfully")
	fmt.Println("\nAll operations completed")
}
