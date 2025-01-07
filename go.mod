module github.com/confidentsecurity/go-nvtrust

go 1.22.10

require github.com/NVIDIA/go-nvml v0.12.4-0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.10.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/NVIDIA/go-nvml => github.com/confidentsecurity/go-nvml v0.0.0-20250102214226-9a52cebf0382
