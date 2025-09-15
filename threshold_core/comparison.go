package thresholdcore

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// [u] = [a] - [b] + [r], r is the random share
func DeriveRemainderShare(aShare, bShare, rShare SecretShare) secp256k1.ModNScalar {
	// [a] - [b]
	a := (*secp256k1.ModNScalar)(&aShare)
	b := (*secp256k1.ModNScalar)(&bShare)
	random := (*secp256k1.ModNScalar)(&rShare)
	temp := secp256k1.ModNScalar{}

	temp.Add2(a, b) // a - b

	// [u] := [d] + [r]
	res := secp256k1.ModNScalar{}
	res.Add2(&temp, random) // a - b + e

	return res
}

// derive u from [u_1], [u_2], ..., [u_n] using Lagrange interpolation
func ReconstructMaskedReminderArithmetic(minParticipants uint16, participants map[Identifier]secp256k1.ModNScalar) (secp.ModNScalar, error) {

	ids := make([]Identifier, 0, len(participants))
	for id := range participants {
		ids = append(ids, id)
	}

	var secret secp.ModNScalar // zero scalar by default

	for i, k := range participants {
		l := LagrangeCoeffAtZero(i, ids)      // returns ModNScalar
		part := l.Mul((*secp.ModNScalar)(&k)) // convert SecretShare to *secp.ModNScalar
		secret.Add(part)                      // secret += part
	}

	return secret, nil
}

// ⟦d_k⟧ = u_k xor [[r_k]] xor [[c_k]], c_k+1 = maj(u_k, r_k, d_k)
func ComputeRemainderShares(maskedRem []secp.ModNScalar, randomShares []secp.ModNScalar, beeverTriples BeeverTriple, bitlen uint16) []secp256k1.ModNScalar {
	carry_acc := secp.ModNScalar{}

	x_share := (*secp.ModNScalar)(&beeverTriples.X)
	y_share := (*secp.ModNScalar)(&beeverTriples.Y)
	z_share := (*secp.ModNScalar)(&beeverTriples.Z)

	maskedRemBit := make([]secp256k1.ModNScalar, bitlen)

	for i := uint16(0); i < bitlen; i++ {
		u_k := (*secp256k1.ModNScalar)(&maskedRem[i])
		r_k := (*secp256k1.ModNScalar)(&randomShares[i])

		temp := XORShared(u_k, r_k, x_share, y_share, z_share)
		d_k := XORShared(&temp, &carry_acc, x_share, y_share, z_share)

		carry_acc = ComputeMajority(u_k, r_k, &d_k, x_share, y_share, z_share)

		maskedRemBit[i] = d_k
	}

	return maskedRemBit
}

// referee Bit Share [[m_k]]
// participants compute [[z_k]] = [[d_k]] xor [[m_k]]
// reconstruct z_k from [[z_k]]
// referee computes d_k = z_k xor m_k
func ReconstructUnmaskedReminderBit(minParticipants uint16, masked_remainder_bits_map []map[Identifier]secp256k1.ModNScalar, masks []secp.ModNScalar, beeverTriple BeeverTriple) ([]secp.ModNScalar, error) {

	ids := make([]Identifier, 0, len(masked_remainder_bits_map))
	for id := range masked_remainder_bits_map[0] {
		ids = append(ids, id)
	}

	z := make([]secp.ModNScalar, len(masks))

	for i, k := range masked_remainder_bits_map {
		for j, v := range k {
			l := LagrangeCoeffAtZero(j, ids)      // returns ModNScalar
			part := l.Mul((*secp.ModNScalar)(&v)) // convert SecretShare to *secp.ModNScalar
			z[i].Add(part)                        // secret += part
		}
	}

	x_share := (*secp.ModNScalar)(&beeverTriple.X)
	y_share := (*secp.ModNScalar)(&beeverTriple.Y)
	z_share := (*secp.ModNScalar)(&beeverTriple.Z)

	// unmask
	d := make([]secp.ModNScalar, len(masks))

	for i, z_k := range z {
		d[i] = XORShared(&z_k, &masks[i], x_share, y_share, z_share) // unmask
	}
	return z, nil
}

func isZero(d []secp.ModNScalar, beeverTriples BeeverTriple) secp.ModNScalar {
	var res secp.ModNScalar

	var one secp.ModNScalar
	one.SetInt(1)

	x_share := (*secp.ModNScalar)(&beeverTriples.X)
	y_share := (*secp.ModNScalar)(&beeverTriples.Y)
	z_share := (*secp.ModNScalar)(&beeverTriples.Z)

	for _, d_k := range d {
		temp := secp.ModNScalar{}
		temp.Add2(&one, d_k.Negate()) // 1 - d_k

		temp_2 := ANDShared(&res, &temp, x_share, y_share, z_share)
		res = temp_2
	}

	return res
}

// a > b isPos(), a>= b (1 - d_l-1)
func isPos(d []secp.ModNScalar, beeverTriples BeeverTriple, isStrict bool) *secp.ModNScalar {

	var one secp.ModNScalar
	one.SetInt(1)

	isZero := isZero(d, beeverTriples)

	var res2 secp.ModNScalar
	res2.SetInt(1)
	res2.Add2(&one, d[len(d)-1].Negate()) // 1 - d_l-1

	if isStrict {
		var res secp.ModNScalar

		res.Add2(&one, isZero.Negate()) // 1 - isZero
		return res2.Mul(&res)           // (1 - d_l-1) * (1 - isZero)
	}
	return &res2 // (1 - d_l-1)
}
