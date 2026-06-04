package thresholdcore

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// assertBIPError checks that err matches the BIP reference's expected_error type
// (and participant index, when present), mapped onto this package's errors.
func assertBIPError(t *testing.T, err error, etype string, participant *int, tc int, comment string) {
	t.Helper()
	require.Errorf(t, err, "tc %d: %s", tc, comment)
	switch etype {
	case "ThresholdOrCountError":
		require.ErrorIsf(t, err, ErrInvalidSessionParams, "tc %d: %s", tc, comment)
	case "InvalidHostPubkeyError":
		require.ErrorIsf(t, err, ErrInvalidHostKey, "tc %d: %s", tc, comment)
	case "DuplicateHostPubkeyError":
		require.ErrorIsf(t, err, ErrDuplicateHostKey, "tc %d: %s", tc, comment)
	case "RandomnessError":
		require.ErrorIsf(t, err, ErrInvalidRandomness, "tc %d: %s", tc, comment)
	case "UnknownFaultyParticipantOrCoordinatorError":
		require.ErrorIsf(t, err, ErrInvalidSecretShare, "tc %d: %s", tc, comment)
	case "RecoveryDataError":
		require.ErrorIsf(t, err, ErrInvalidRecoveryData, "tc %d: %s", tc, comment)
	case "ValueError":
		require.ErrorIsf(t, err, ErrIncorrectNumberOfPackages, "tc %d: %s", tc, comment)
	case "HostSeckeyError":
		ok := errors.Is(err, ErrSeckeyLen) || errors.Is(err, ErrSeckeyRange) || errors.Is(err, ErrNotInParams)
		require.Truef(t, ok, "tc %d: HostSeckeyError, got %v", tc, err)
	case "FaultyCoordinatorError":
		var fe *BIPFaultyCoordinatorError
		require.ErrorAsf(t, err, &fe, "tc %d: %s", tc, comment)
	case "FaultyParticipantError":
		var fe *BIPFaultyParticipantError
		require.ErrorAsf(t, err, &fe, "tc %d: %s", tc, comment)
		if participant != nil {
			require.Equalf(t, *participant, fe.Participant, "tc %d participant", tc)
		}
	case "FaultyParticipantOrCoordinatorError":
		var fe *BIPFaultyParticipantOrCoordinatorError
		require.ErrorAsf(t, err, &fe, "tc %d: %s", tc, comment)
		if participant != nil {
			require.Equalf(t, *participant, fe.Participant, "tc %d participant", tc)
		}
	default:
		t.Fatalf("tc %d: unhandled error type %q", tc, etype)
	}
}

// Validates the BIP-exact functions against the upstream bip-frost-dkg test vectors.
// Each vector case runs as its own t.Run subtest (named valid_tcN / error_tcN), so
// `go test -v` prints one PASS line per case — a visible coverage ledger.

func bipHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

type bipParamsJSON struct {
	Hostpubkeys []string `json:"hostpubkeys"`
	T           uint32   `json:"t"`
}

func (p bipParamsJSON) keys(t *testing.T) [][]byte {
	t.Helper()
	ks := make([][]byte, len(p.Hostpubkeys))
	for i, h := range p.Hostpubkeys {
		ks[i] = bipHexDecode(t, h)
	}
	return ks
}

// session builds a SessionParams whose participant order (IDs 1..n ascending)
// matches the vector's positional hostpubkeys list.
func (p bipParamsJSON) session(t *testing.T) SessionParams {
	t.Helper()
	hostPubs := make(map[Identifier]*secp.PublicKey, len(p.Hostpubkeys))
	for i, h := range p.Hostpubkeys {
		var x secp.ModNScalar
		x.SetInt(uint32(i + 1))
		id, err := NewIdentifier(x)
		require.NoError(t, err)
		pub, err := secp.ParsePubKey(bipHexDecode(t, h))
		require.NoError(t, err)
		hostPubs[id] = pub
	}
	params, err := NewSessionParams(uint16(p.T), hostPubs)
	require.NoError(t, err)
	return params
}

func bipLoadVectors(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, v))
}

func TestBIPParamsIDVectors(t *testing.T) {
	var dv struct {
		Valid []struct {
			TCID     int           `json:"tc_id"`
			Comment  string        `json:"comment"`
			Params   bipParamsJSON `json:"params"`
			Expected string        `json:"expected_params_id"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID     int           `json:"tc_id"`
			Comment  string        `json:"comment"`
			Params   bipParamsJSON `json:"params"`
			Expected struct {
				Type string `json:"type"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "params_id_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			got, err := BIPParamsID(c.Params.T, c.Params.keys(t))
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got[:]), "tc %d: %s", c.TCID, c.Comment)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			_, err := BIPParamsID(c.Params.T, c.Params.keys(t))
			switch c.Expected.Type {
			case "ThresholdOrCountError":
				require.ErrorIsf(t, err, ErrInvalidSessionParams, "tc %d: %s", c.TCID, c.Comment)
			case "InvalidHostPubkeyError":
				require.ErrorIsf(t, err, ErrInvalidHostKey, "tc %d: %s", c.TCID, c.Comment)
			case "DuplicateHostPubkeyError":
				require.ErrorIsf(t, err, ErrDuplicateHostKey, "tc %d: %s", c.TCID, c.Comment)
			default:
				t.Fatalf("tc %d: unhandled error type %q", c.TCID, c.Expected.Type)
			}
		})
	}
}

func TestBIPHostpubkeyGenVectors(t *testing.T) {
	var dv struct {
		Valid []struct {
			TCID       int    `json:"tc_id"`
			Comment    string `json:"comment"`
			Hostseckey string `json:"hostseckey"`
			Expected   string `json:"expected_hostpubkey"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID       int    `json:"tc_id"`
			Comment    string `json:"comment"`
			Hostseckey string `json:"hostseckey"`
			Expected   struct {
				Type string `json:"type"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "hostpubkey_gen_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			got, err := BIPHostpubkeyGen(bipHexDecode(t, c.Hostseckey))
			require.NoErrorf(t, err, "tc %d", c.TCID)
			require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			_, err := BIPHostpubkeyGen(bipHexDecode(t, c.Hostseckey))
			assertBIPError(t, err, c.Expected.Type, nil, c.TCID, c.Comment)
		})
	}
}

func TestBIPCoordinatorStep1Vectors(t *testing.T) {
	var dv struct {
		Pool  []string `json:"pmsg1_pool"`
		Valid []struct {
			TCID     int           `json:"tc_id"`
			Comment  string        `json:"comment"`
			Params   bipParamsJSON `json:"params"`
			Indices  []int         `json:"pmsg1_indices"`
			Expected string        `json:"expected_cmsg1"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID     int           `json:"tc_id"`
			Comment  string        `json:"comment"`
			Params   bipParamsJSON `json:"params"`
			Indices  []int         `json:"pmsg1_indices"`
			Expected struct {
				Type        string `json:"type"`
				Participant *int   `json:"participant"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "coordinator_step1_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			params := c.Params.session(t)
			pmsgs := make([][]byte, len(c.Indices))
			for i, idx := range c.Indices {
				pmsgs[i] = bipHexDecode(t, dv.Pool[idx])
			}
			got, err := params.BIPCoordinatorStep1(pmsgs)
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			// Invalid params are rejected at validation; a malformed participant message
			// at the (already-valid) coordinator step.
			if c.Expected.Type == "FaultyParticipantError" {
				params := c.Params.session(t)
				pmsgs := make([][]byte, len(c.Indices))
				for i, idx := range c.Indices {
					pmsgs[i] = bipHexDecode(t, dv.Pool[idx])
				}
				_, err := params.BIPCoordinatorStep1(pmsgs)
				assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
				return
			}
			err := validateBIPParams(c.Params.T, c.Params.keys(t))
			assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
		})
	}
}

func TestBIPParticipantStep2Vectors(t *testing.T) {
	var dv struct {
		Params     bipParamsJSON `json:"params"`
		Hostseckey string        `json:"hostseckey"`
		Random     string        `json:"random"`
		AuxRand    string        `json:"aux_rand"`
		Valid      []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Cmsg1    string `json:"cmsg1"`
			Expected string `json:"expected_pmsg2"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Cmsg1    string `json:"cmsg1"`
			Expected struct {
				Type        string `json:"type"`
				Participant *int   `json:"participant"`
				Message     string `json:"message"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "participant_step2_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	hostseckey := bipHexDecode(t, dv.Hostseckey)
	random := bipHexDecode(t, dv.Random)
	aux := bipHexDecode(t, dv.AuxRand)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			got, err := params.BIPParticipantStep2(hostseckey, random, bipHexDecode(t, c.Cmsg1), aux)
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			_, err := params.BIPParticipantStep2(hostseckey, random, bipHexDecode(t, c.Cmsg1), aux)
			assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
		})
	}
}

func TestBIPParticipantFinalizeVectors(t *testing.T) {
	var dv struct {
		Params     bipParamsJSON `json:"params"`
		Hostseckey string        `json:"hostseckey"`
		Cmsg1      string        `json:"cmsg1"`
		Valid      []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Cmsg2    string `json:"cmsg2"`
			Expected struct {
				DKGOutput struct {
					Pubshares       []string `json:"pubshares"`
					Secshare        string   `json:"secshare"`
					ThresholdPubkey string   `json:"threshold_pubkey"`
				} `json:"dkg_output"`
				RecoveryData string `json:"recovery_data"`
			} `json:"expected_output"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Cmsg2    string `json:"cmsg2"`
			Expected struct {
				Type        string `json:"type"`
				Participant *int   `json:"participant"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "participant_finalize_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	hostseckey := bipHexDecode(t, dv.Hostseckey)
	cmsg1 := bipHexDecode(t, dv.Cmsg1)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			out, recovery, err := params.BIPParticipantFinalize(hostseckey, cmsg1, bipHexDecode(t, c.Cmsg2))
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.ThresholdPubkey), hex.EncodeToString(out.ThresholdPubkey), "tc %d threshold_pubkey", c.TCID)
			require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.Secshare), hex.EncodeToString(out.Secshare), "tc %d secshare", c.TCID)
			require.Lenf(t, out.Pubshares, len(c.Expected.DKGOutput.Pubshares), "tc %d pubshares count", c.TCID)
			for i, ps := range c.Expected.DKGOutput.Pubshares {
				require.Equalf(t, strings.ToLower(ps), hex.EncodeToString(out.Pubshares[i]), "tc %d pubshare %d", c.TCID, i)
			}
			require.Equalf(t, strings.ToLower(c.Expected.RecoveryData), hex.EncodeToString(recovery), "tc %d recovery_data", c.TCID)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			_, _, err := params.BIPParticipantFinalize(hostseckey, cmsg1, bipHexDecode(t, c.Cmsg2))
			assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
		})
	}
}

func TestBIPCoordinatorFinalizeVectors(t *testing.T) {
	var dv struct {
		Params    bipParamsJSON `json:"params"`
		Cmsg1     string        `json:"cmsg1"`
		Pmsg2Pool []string      `json:"pmsg2_pool"`
		Valid     []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Indices  []int  `json:"pmsg2_indices"`
			Expected struct {
				DKGOutput struct {
					Pubshares       []string `json:"pubshares"`
					Secshare        string   `json:"secshare"`
					ThresholdPubkey string   `json:"threshold_pubkey"`
				} `json:"dkg_output"`
				RecoveryData string `json:"recovery_data"`
			} `json:"expected_output"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Indices  []int  `json:"pmsg2_indices"`
			Expected struct {
				Type        string `json:"type"`
				Participant *int   `json:"participant"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "coordinator_finalize_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	cmsg1 := bipHexDecode(t, dv.Cmsg1)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			pmsg2s := make([][]byte, len(c.Indices))
			for i, idx := range c.Indices {
				pmsg2s[i] = bipHexDecode(t, dv.Pmsg2Pool[idx])
			}
			out, recovery, err := params.BIPCoordinatorFinalize(cmsg1, pmsg2s)
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.ThresholdPubkey), hex.EncodeToString(out.ThresholdPubkey), "tc %d threshold_pubkey", c.TCID)
			require.Empty(t, out.Secshare, "tc %d coordinator secshare", c.TCID)
			for i, ps := range c.Expected.DKGOutput.Pubshares {
				require.Equalf(t, strings.ToLower(ps), hex.EncodeToString(out.Pubshares[i]), "tc %d pubshare %d", c.TCID, i)
			}
			require.Equalf(t, strings.ToLower(c.Expected.RecoveryData), hex.EncodeToString(recovery), "tc %d recovery_data", c.TCID)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			pmsg2s := make([][]byte, len(c.Indices))
			for i, idx := range c.Indices {
				pmsg2s[i] = bipHexDecode(t, dv.Pmsg2Pool[idx])
			}
			_, _, err := params.BIPCoordinatorFinalize(cmsg1, pmsg2s)
			assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
		})
	}
}

func TestBIPRecoverVectors(t *testing.T) {
	var dv struct {
		Valid []struct {
			TCID       int    `json:"tc_id"`
			Comment    string `json:"comment"`
			Hostseckey string `json:"hostseckey"`
			Recovery   string `json:"recovery_data"`
			Expected   struct {
				DKGOutput struct {
					Pubshares       []string `json:"pubshares"`
					Secshare        string   `json:"secshare"`
					ThresholdPubkey string   `json:"threshold_pubkey"`
				} `json:"dkg_output"`
				Params bipParamsJSON `json:"params"`
			} `json:"expected_output"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID       int    `json:"tc_id"`
			Comment    string `json:"comment"`
			Hostseckey string `json:"hostseckey"`
			Recovery   string `json:"recovery_data"`
			Expected   struct {
				Type string `json:"type"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "recover_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			// An empty hostseckey ("") decodes to empty bytes = coordinator recovery.
			out, hostpubkeys, tt, err := BIPRecover(bipHexDecode(t, c.Hostseckey), bipHexDecode(t, c.Recovery))
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, c.Expected.Params.T, tt, "tc %d t", c.TCID)
			require.Lenf(t, hostpubkeys, len(c.Expected.Params.Hostpubkeys), "tc %d n", c.TCID)
			for i, hp := range c.Expected.Params.Hostpubkeys {
				require.Equalf(t, strings.ToLower(hp), hex.EncodeToString(hostpubkeys[i]), "tc %d hostpubkey %d", c.TCID, i)
			}
			require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.ThresholdPubkey), hex.EncodeToString(out.ThresholdPubkey), "tc %d threshold_pubkey", c.TCID)
			require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.Secshare), hex.EncodeToString(out.Secshare), "tc %d secshare", c.TCID)
			for i, ps := range c.Expected.DKGOutput.Pubshares {
				require.Equalf(t, strings.ToLower(ps), hex.EncodeToString(out.Pubshares[i]), "tc %d pubshare %d", c.TCID, i)
			}
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			// Both HostSeckeyError variants are now representable: a wrong-length key
			// → ErrSeckeyLen, a valid key not among the params → ErrNotInParams.
			_, _, _, err := BIPRecover(bipHexDecode(t, c.Hostseckey), bipHexDecode(t, c.Recovery))
			assertBIPError(t, err, c.Expected.Type, nil, c.TCID, c.Comment)
		})
	}
}

func TestBIPCoordinatorInvestigateVectors(t *testing.T) {
	var dv struct {
		Params bipParamsJSON `json:"params"`
		Pmsgs1 []string      `json:"pmsgs1"`
		Valid  []struct {
			TCID     int      `json:"tc_id"`
			Comment  string   `json:"comment"`
			Expected []string `json:"expected_cinv_msgs"`
		} `json:"valid_test_cases"`
	}
	bipLoadVectors(t, "coordinator_investigate_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	pmsgs := make([][]byte, len(dv.Pmsgs1))
	for i, m := range dv.Pmsgs1 {
		pmsgs[i] = bipHexDecode(t, m)
	}
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			cinvs, err := params.BIPCoordinatorInvestigate(pmsgs)
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Lenf(t, cinvs, len(c.Expected), "tc %d cinv count", c.TCID)
			for i, e := range c.Expected {
				require.Equalf(t, strings.ToLower(e), hex.EncodeToString(cinvs[i]), "tc %d cinv %d", c.TCID, i)
			}
		})
	}
}

func TestBIPParticipantInvestigateVectors(t *testing.T) {
	var dv struct {
		Params     bipParamsJSON `json:"params"`
		Hostseckey string        `json:"hostseckey"`
		Cmsg1Pool  []string      `json:"cmsg1_pool"`
		Errors     []struct {
			TCID       int    `json:"tc_id"`
			Comment    string `json:"comment"`
			Cinv       string `json:"cinv_msg"`
			Cmsg1Index int    `json:"cmsg1_index"`
			Expected   struct {
				Type        string `json:"type"`
				Participant *int   `json:"participant"`
				Message     string `json:"message"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "participant_investigate_vectors.json", &dv)
	require.NotEmpty(t, dv.Errors)
	params := dv.Params.session(t)
	hostseckey := bipHexDecode(t, dv.Hostseckey)
	for _, c := range dv.Errors {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			cmsg1 := bipHexDecode(t, dv.Cmsg1Pool[c.Cmsg1Index])
			err := params.BIPParticipantInvestigate(hostseckey, cmsg1, bipHexDecode(t, c.Cinv))
			require.Errorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			switch c.Expected.Type {
			case "FaultyParticipantOrCoordinatorError":
				var fe *BIPFaultyParticipantOrCoordinatorError
				require.ErrorAsf(t, err, &fe, "tc %d type (got %v)", c.TCID, err)
				require.NotNil(t, c.Expected.Participant, "tc %d expected participant", c.TCID)
				require.Equalf(t, *c.Expected.Participant, fe.Participant, "tc %d participant", c.TCID)
				require.Equalf(t, c.Expected.Message, fe.Reason, "tc %d message", c.TCID)
			case "FaultyCoordinatorError":
				var fe *BIPFaultyCoordinatorError
				require.ErrorAsf(t, err, &fe, "tc %d type (got %v)", c.TCID, err)
				require.Equalf(t, c.Expected.Message, fe.Reason, "tc %d message", c.TCID)
			default:
				t.Fatalf("tc %d unexpected error type %q", c.TCID, c.Expected.Type)
			}
		})
	}
}

func TestBIPParticipantStep1Vectors(t *testing.T) {
	var dv struct {
		Valid []struct {
			TCID       int           `json:"tc_id"`
			Comment    string        `json:"comment"`
			Hostseckey string        `json:"hostseckey"`
			Params     bipParamsJSON `json:"params"`
			Random     string        `json:"random"`
			Expected   string        `json:"expected_pmsg1"`
		} `json:"valid_test_cases"`
		Error []struct {
			TCID       int           `json:"tc_id"`
			Comment    string        `json:"comment"`
			Hostseckey string        `json:"hostseckey"`
			Params     bipParamsJSON `json:"params"`
			Random     string        `json:"random"`
			Expected   struct {
				Type        string `json:"type"`
				Participant *int   `json:"participant"`
			} `json:"expected_error"`
		} `json:"error_test_cases"`
	}
	bipLoadVectors(t, "participant_step1_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		t.Run(fmt.Sprintf("valid_tc%d", c.TCID), func(t *testing.T) {
			params := c.Params.session(t)
			got, err := params.BIPParticipantStep1(bipHexDecode(t, c.Hostseckey), bipHexDecode(t, c.Random))
			require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
			require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
		})
	}
	for _, c := range dv.Error {
		t.Run(fmt.Sprintf("error_tc%d", c.TCID), func(t *testing.T) {
			switch c.Expected.Type {
			case "ThresholdOrCountError", "InvalidHostPubkeyError", "DuplicateHostPubkeyError":
				// Invalid params are rejected at SessionParams construction (validateBIPParams).
				err := validateBIPParams(c.Params.T, c.Params.keys(t))
				assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
			case "HostSeckeyError":
				// Now representable: wrong-length → ErrSeckeyLen; a valid key not among
				// the params → ErrNotInParams (both map to HostSeckeyError).
				_, err := c.Params.session(t).BIPParticipantStep1(bipHexDecode(t, c.Hostseckey), bipHexDecode(t, c.Random))
				assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
			case "RandomnessError":
				_, err := c.Params.session(t).BIPParticipantStep1(bipHexDecode(t, c.Hostseckey), bipHexDecode(t, c.Random))
				assertBIPError(t, err, c.Expected.Type, c.Expected.Participant, c.TCID, c.Comment)
			default:
				t.Fatalf("tc %d: unhandled error type %q", c.TCID, c.Expected.Type)
			}
		})
	}
}
