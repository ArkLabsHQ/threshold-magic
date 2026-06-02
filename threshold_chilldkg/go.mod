module thresholdchilldkg

go 1.24.6

replace github.com/ArkLabsHQ/thresholdmagic/thresholdcore => ../threshold_core

require (
	github.com/ArkLabsHQ/thresholdmagic/thresholdcore v0.0.0-00010101000000-000000000000
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
)

require (
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
