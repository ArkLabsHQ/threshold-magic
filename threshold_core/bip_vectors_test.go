package thresholdcore

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// Validates the BIP-exact functions against the upstream bip-frost-dkg test vectors

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
	}
	bipLoadVectors(t, "params_id_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		got := BIPParamsID(c.Params.T, c.Params.keys(t))
		require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got[:]), "tc %d: %s", c.TCID, c.Comment)
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
	}
	bipLoadVectors(t, "hostpubkey_gen_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		got, err := BIPHostpubkeyGen(bipHexDecode(t, c.Hostseckey))
		require.NoErrorf(t, err, "tc %d", c.TCID)
		require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
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
	}
	bipLoadVectors(t, "coordinator_step1_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		params := c.Params.session(t)
		pmsgs := make([][]byte, len(c.Indices))
		for i, idx := range c.Indices {
			pmsgs[i] = bipHexDecode(t, dv.Pool[idx])
		}
		got, err := params.BIPCoordinatorStep1(pmsgs)
		require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
		require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
	}
}

func TestBIPParticipantStep2Vectors(t *testing.T) {
	var dv struct {
		Params     bipParamsJSON `json:"params"`
		Hostseckey string        `json:"hostseckey"`
		AuxRand    string        `json:"aux_rand"`
		Valid      []struct {
			TCID     int    `json:"tc_id"`
			Comment  string `json:"comment"`
			Cmsg1    string `json:"cmsg1"`
			Expected string `json:"expected_pmsg2"`
		} `json:"valid_test_cases"`
	}
	bipLoadVectors(t, "participant_step2_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	hostSk := secp.PrivKeyFromBytes(bipHexDecode(t, dv.Hostseckey))
	aux := bipHexDecode(t, dv.AuxRand)
	for _, c := range dv.Valid {
		got, err := params.BIPParticipantStep2(hostSk, bipHexDecode(t, c.Cmsg1), aux)
		require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
		require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
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
	}
	bipLoadVectors(t, "participant_finalize_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	hostSk := secp.PrivKeyFromBytes(bipHexDecode(t, dv.Hostseckey))
	cmsg1 := bipHexDecode(t, dv.Cmsg1)
	for _, c := range dv.Valid {
		out, recovery, err := params.BIPParticipantFinalize(hostSk, cmsg1, bipHexDecode(t, c.Cmsg2))
		require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
		require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.ThresholdPubkey), hex.EncodeToString(out.ThresholdPubkey), "tc %d threshold_pubkey", c.TCID)
		require.Equalf(t, strings.ToLower(c.Expected.DKGOutput.Secshare), hex.EncodeToString(out.Secshare), "tc %d secshare", c.TCID)
		require.Lenf(t, out.Pubshares, len(c.Expected.DKGOutput.Pubshares), "tc %d pubshares count", c.TCID)
		for i, ps := range c.Expected.DKGOutput.Pubshares {
			require.Equalf(t, strings.ToLower(ps), hex.EncodeToString(out.Pubshares[i]), "tc %d pubshare %d", c.TCID, i)
		}
		require.Equalf(t, strings.ToLower(c.Expected.RecoveryData), hex.EncodeToString(recovery), "tc %d recovery_data", c.TCID)
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
	}
	bipLoadVectors(t, "coordinator_finalize_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	params := dv.Params.session(t)
	cmsg1 := bipHexDecode(t, dv.Cmsg1)
	for _, c := range dv.Valid {
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
	}
	bipLoadVectors(t, "recover_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		var hostSk *secp.PrivateKey // nil = coordinator recovery
		if c.Hostseckey != "" {
			hostSk = secp.PrivKeyFromBytes(bipHexDecode(t, c.Hostseckey))
		}
		out, hostpubkeys, tt, err := BIPRecover(hostSk, bipHexDecode(t, c.Recovery))
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
		cinvs, err := params.BIPCoordinatorInvestigate(pmsgs)
		require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
		require.Lenf(t, cinvs, len(c.Expected), "tc %d cinv count", c.TCID)
		for i, e := range c.Expected {
			require.Equalf(t, strings.ToLower(e), hex.EncodeToString(cinvs[i]), "tc %d cinv %d", c.TCID, i)
		}
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
	hostSk := secp.PrivKeyFromBytes(bipHexDecode(t, dv.Hostseckey))
	for _, c := range dv.Errors {
		cmsg1 := bipHexDecode(t, dv.Cmsg1Pool[c.Cmsg1Index])
		err := params.BIPParticipantInvestigate(hostSk, cmsg1, bipHexDecode(t, c.Cinv))
		require.Errorf(t, err, "tc %d: %s", c.TCID, c.Comment)
		switch c.Expected.Type {
		case "FaultyParticipantOrCoordinatorError":
			var fe *BIPFaultyParticipantError
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
	}
	bipLoadVectors(t, "participant_step1_vectors.json", &dv)
	require.NotEmpty(t, dv.Valid)
	for _, c := range dv.Valid {
		params := c.Params.session(t)
		hostSk := secp.PrivKeyFromBytes(bipHexDecode(t, c.Hostseckey))
		got, err := params.BIPParticipantStep1(hostSk, bipHexDecode(t, c.Random))
		require.NoErrorf(t, err, "tc %d: %s", c.TCID, c.Comment)
		require.Equalf(t, strings.ToLower(c.Expected), hex.EncodeToString(got), "tc %d: %s", c.TCID, c.Comment)
	}
}
