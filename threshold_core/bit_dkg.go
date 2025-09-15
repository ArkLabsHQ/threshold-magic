package thresholdcore

import (
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Round1BitSecretPackage struct {
	Identifier   Identifier
	Bitlength    uint16
	Coefficients [][]secp.ModNScalar
	Commitments  []VerifiableSecretSharingCommitment
	MinSigners   uint16
	MaxSigners   uint16
}

type Round1BitPackage struct {
	CommitmentList   []VerifiableSecretSharingCommitment
	ProofOfKnowledge []Signature
}

type BeeverTriple struct {
	X, Y, Z SecretShare
}

// This is for 16 bit random number
func BitDKGPart1(
	identifier Identifier,
	minSigners uint16,
	maxSigners uint16,
	bitLength uint16,
	secretBits []byte,
	cofficients [][]secp.ModNScalar,
	r io.Reader,
) (Round1BitSecretPackage, Round1BitPackage, error) {

	if err := validateNumOfSigners(minSigners, maxSigners); err != nil {
		return Round1BitSecretPackage{}, Round1BitPackage{}, err
	}

	cofficientList := make([][]secp.ModNScalar, bitLength)
	commitmentList := make([]VerifiableSecretSharingCommitment, bitLength)

	signatureList := make([]Signature, bitLength)

	for i, bit := range secretBits {
		secretScalar := secp.ModNScalar{}
		secretScalar.SetByteSlice([]byte{bit})

		coeffs, commitment, err := generateSecretPolynomial(&secretScalar, maxSigners, minSigners, cofficients[i])
		if err != nil {
			return Round1BitSecretPackage{}, Round1BitPackage{}, err
		}

		verifyingCommit := VerifiableSecretSharingCommitment{commitment}
		verifyingKey, err := verifyingCommit.ToVerifyingKey()
		if err != nil {
			return Round1BitSecretPackage{}, Round1BitPackage{}, err
		}

		// σ_i = PoK for a_{i0}
		sig, err := computeProofOfKnowledge(identifier, coeffs, verifyingKey, r)
		if err != nil {
			return Round1BitSecretPackage{}, Round1BitPackage{}, err
		}

		cofficientList[i] = coeffs
		commitmentList[i] = VerifiableSecretSharingCommitment{commitment}
		signatureList[i] = sig
	}

	secretPackage := Round1BitSecretPackage{
		Identifier:   identifier,
		Bitlength:    bitLength,
		Coefficients: cofficientList,
		Commitments:  commitmentList,
		MinSigners:   minSigners,
		MaxSigners:   maxSigners,
	}

	publicPackage := Round1BitPackage{
		CommitmentList:   commitmentList,
		ProofOfKnowledge: signatureList,
	}

	return secretPackage, publicPackage, nil
}

type RoundBit2Package struct {
	SecretShareList []SecretShare `json:"-"`
}

type Round2SecretBitPackage struct {
	Identifier   Identifier
	Commitment   []VerifiableSecretSharingCommitment
	SecretShare  []secp.ModNScalar
	BeeverTriple BeeverTriple
	MinSigners   uint16
	MaxSigners   uint16
}

func BitDKGPart2(secretPkg Round1BitSecretPackage, round1Pkgs map[Identifier]Round1BitPackage) (Round2SecretBitPackage, map[Identifier]RoundBit2Package, error) {

	if len(round1Pkgs) != int(secretPkg.MaxSigners-1) {
		return Round2SecretBitPackage{}, nil, ErrIncorrectNumberOfPackages
	}

	for _, p := range round1Pkgs {
		if len(p.CommitmentList) != int(secretPkg.Bitlength) || len(p.ProofOfKnowledge) != int(secretPkg.Bitlength) {
			return Round2SecretBitPackage{}, nil, ErrIncorrectNumberOfCommitments
		}
	}

	out := make(map[Identifier]RoundBit2Package, len(round1Pkgs))
	for senderID, pkg := range round1Pkgs {

		senderShareList := make([]SecretShare, secretPkg.Bitlength)
		for i, comm := range pkg.CommitmentList {
			verifyingKey, err := comm.ToVerifyingKey()
			if err != nil {
				return Round2SecretBitPackage{}, nil, err
			}

			if err := verifyProofOfKnowledge(senderID, verifyingKey, &pkg.ProofOfKnowledge[i]); err != nil {
				return Round2SecretBitPackage{}, nil, err
			}

			share := secretShareFromCoefficients(secretPkg.Coefficients[i], senderID)

			senderShareList[i] = share
		}
		out[senderID] = RoundBit2Package{SecretShareList: senderShareList}
	}

	ownShareList := make([]secp.ModNScalar, secretPkg.Bitlength)
	for i := range secretPkg.Coefficients {
		share := secretShareFromCoefficients(secretPkg.Coefficients[i], secretPkg.Identifier)
		ownShareList[i] = secp.ModNScalar(share)
	}

	round2Pkg := Round2SecretBitPackage{
		Identifier:  secretPkg.Identifier,
		Commitment:  secretPkg.Commitments,
		SecretShare: ownShareList,
		MinSigners:  secretPkg.MinSigners,
		MaxSigners:  secretPkg.MaxSigners,
	}

	return round2Pkg, out, nil

}

func BitDKGPart3(r1Secret *Round1BitSecretPackage, r2Secret *Round2SecretBitPackage,
	round1Pkgs map[Identifier]Round1BitPackage, round2Pkgs map[Identifier]RoundBit2Package) (BitKeyPackage, error) {

	for id := range round1Pkgs {
		if _, ok := round2Pkgs[id]; !ok {
		}
	}

	si_list := make([]secp.ModNScalar, r1Secret.Bitlength)
	for i := range si_list {
		si_list[i] = modNZero()
	}

	x_share := r2Secret.BeeverTriple.X
	y_share := r2Secret.BeeverTriple.Y
	z_share := r2Secret.BeeverTriple.Z

	for _, pkg2 := range round2Pkgs {
		for i, share := range pkg2.SecretShareList {
			temp := XORShared(&si_list[i], (*secp.ModNScalar)(&share), (*secp.ModNScalar)(&x_share), (*secp.ModNScalar)(&y_share), (*secp.ModNScalar)(&z_share))
			si_list[i] = temp
		}
	}

	for i, share := range r2Secret.SecretShare {
		temp := XORShared(&si_list[i], &share, (*secp.ModNScalar)(&x_share), (*secp.ModNScalar)(&y_share), (*secp.ModNScalar)(&z_share))
		si_list[i] = temp
	}

	verifyingShareList := make([]secp.JacobianPoint, r1Secret.Bitlength)
	for i, sh := range si_list {
		verifyingShareList[i] = elemBaseMul((*secp.ModNScalar)(&sh))
	}

	// Convert si_list ([]secp.ModNScalar) to []SecretShare
	secretKeyShareList := make([]SecretShare, len(si_list))
	for i, v := range si_list {
		secretKeyShareList[i] = SecretShare(v)
	}

	arithmeticRandom := ConvertBitToArithmetic(si_list)

	return BitKeyPackage{
		Identifier:         r1Secret.Identifier,
		SecretKeyShareList: secretKeyShareList,
		VerifyingShareList: verifyingShareList,
		ArithemticRandom:   arithmeticRandom,
	}, nil

}

type BitKeyPackage struct {
	Identifier         Identifier
	SecretKeyShareList []SecretShare
	VerifyingShareList []VerifyingShare
	ArithemticRandom   secp.ModNScalar
}

// TODO: Verify, might be wrong
func pow2Scalar(k int) secp.ModNScalar {
	var out secp.ModNScalar
	out.SetInt(1)
	var two secp.ModNScalar
	two.SetInt(2)
	for i := 1; i < k; i++ {
		out.Mul(&two)
	}
	return out
}

//	// Given ⟦r_k⟧ (k=0..L-1), compute the arithmetic share [r] by linearity:
//
// For each party P: [r]_P = sum_k (2^k) * ⟦r_k⟧_P
func ConvertBitToArithmetic(bitshare []secp.ModNScalar) secp.ModNScalar {
	sum := modNZero()
	for i, sh := range bitshare {
		twoExp := pow2Scalar(i)
		temp := twoExp.Mul(&sh)
		sum.Add(temp)
	}
	return sum
}

func ConvertArithmeticToBit(arithmeticShare secp.ModNScalar, bitlenght uint16) []secp256k1.ModNScalar {
	remainder := secp256k1.ModNScalar{}
	remainder.Set(&arithmeticShare)
	bitShareList := make([]secp256k1.ModNScalar, bitlenght)

	for i := (bitlenght - 1); i >= 0; i-- {
		powerOfTwo := pow2Scalar(int(i))
		temp := secp256k1.ModNScalar{}
		temp.SetInt(1)
		temp.Add(&remainder)
		if temp.Equals(&powerOfTwo) {
			bitShareList[i].SetInt(0)
			continue
		}

		remainder.Add(powerOfTwo.Negate())

		bitShareList[i].SetInt(1)
	}

	reversedShareList := make([]secp256k1.ModNScalar, bitlenght)
	for i := uint16(0); i < bitlenght; i++ {
		reversedShareList[i] = bitShareList[bitlenght-1-i]
	}

	return reversedShareList
}
