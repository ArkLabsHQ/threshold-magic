package thresholdsdk

// ThresholdPolicy maps the current member count to the signing threshold the next
// (re-)DKG should use. It is applied by the leader as membership changes and must be
// deterministic so every party derives the same threshold for the same size.
type ThresholdPolicy func(n int) uint16

// MajorityPolicy is the default: a simple majority of the current members must sign
// (t = ⌊n/2⌋ + 1). For n = 2 this is 2 (a 2-of-2), the smallest valid threshold.
func MajorityPolicy(n int) uint16 { return uint16(n/2 + 1) }
