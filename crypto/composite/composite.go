package composite

import (
	"bytes"
	"fmt"

	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/libs/math"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/bls"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto/tmhash"
)

// composite.PubKey and composite.PrivKey are intended to allow public key algorithms to be selected for each function.

const (
	PubKeyName  = "tendermint/PubKeyComposite"
	PrivKeyName = "tendermint/PrivKeyComposite"

	KeyType               = "composite"
	KeyTypeBlsWithEd25519 = KeyType + "(" + bls.KeyType + "," + ed25519.KeyType + ")"
)

var MaxSignatureSize = math.MaxInt(ed25519.SignatureSize, bls.SignatureSize)

func init() {
	tmjson.RegisterType(PubKey{}, PubKeyName)
	tmjson.RegisterType(PrivKey{}, PrivKeyName)
}

type PubKey struct {
	BlsKey  crypto.PubKey `json:"bls"`
	SignKey crypto.PubKey `json:"sign"`
}

func PubKeyFromBytes(bz []byte) PubKey {
	if len(bz) != bls.PubKeySize+ed25519.PubKeySize {
		panic(fmt.Sprintf("Wrong PubKey bytes size: %d", len(bz)))
	}
	blsKey := bls.PubKey{}
	copy(blsKey[:], bz[:bls.PubKeySize])
	ed25519Pubkey := ed25519.PubKey(make([]byte, ed25519.PubKeySize))
	copy(ed25519Pubkey, bz[bls.PubKeySize:])
	return PubKey{BlsKey: blsKey, SignKey: ed25519Pubkey}
}

func (pk *PubKey) Identity() crypto.PubKey {
	return pk.SignKey
}

func (pk PubKey) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(pk.Bytes()))
}

func (pk PubKey) Bytes() []byte {
	bz := bytes.NewBuffer(pk.BlsKey.Bytes())
	bz.Write(pk.SignKey.Bytes())
	return bz.Bytes()
}

func (pk PubKey) VerifySignature(msg []byte, sig []byte) bool {
	return pk.BlsKey.VerifySignature(msg, sig)
}

func (pk PubKey) Equals(key crypto.PubKey) bool {
	other, ok := key.(PubKey)
	return ok && pk.BlsKey.Equals(other.BlsKey) && pk.SignKey.Equals(other.SignKey)
}

func (pk PubKey) Type() string {
	return fmt.Sprintf("%s(%s,%s)", KeyType, pk.BlsKey.Type(), pk.SignKey.Type())
}

type PrivKey struct {
	BlsKey  crypto.PrivKey `json:"bls"`
	SignKey crypto.PrivKey `json:"sign"`
}

func GenPrivKey() *PrivKey {
	return NewPrivKeyComposite(bls.GenPrivKey(), ed25519.GenPrivKey())
}

func NewPrivKeyComposite(blsKey crypto.PrivKey, signKey crypto.PrivKey) *PrivKey {
	return &PrivKey{BlsKey: blsKey, SignKey: signKey}
}

// PrivKeyFromBytes depends on PrivKey.Bytes
// See PrivKey.Bytes
func PrivKeyFromBytes(bz []byte) *PrivKey {
	if len(bz) != bls.PrivKeySize+ed25519.PrivateKeySize {
		panic(fmt.Sprintf("Wrong PrivKey bytes size: %d", len(bz)))
	}
	blsKey := bls.PrivKey{}
	copy(blsKey[:], bz[:bls.PrivKeySize])
	ed25519Key := ed25519.PrivKey(make([]byte, ed25519.PrivateKeySize))
	copy(ed25519Key, bz[bls.PrivKeySize:])
	return &PrivKey{BlsKey: blsKey, SignKey: ed25519Key}
}

func (sk PrivKey) Identity() crypto.PrivKey {
	return sk.SignKey
}

func (sk PrivKey) Bytes() []byte {
	bz := bytes.NewBuffer(sk.BlsKey.Bytes())
	bz.Write(sk.SignKey.Bytes())
	return bz.Bytes()
}

func (sk PrivKey) Sign(msg []byte) ([]byte, error) {
	return sk.BlsKey.Sign(msg)
}

func (sk PrivKey) PubKey() crypto.PubKey {
	return PubKey{sk.BlsKey.PubKey(), sk.SignKey.PubKey()}
}

func (sk PrivKey) Equals(key crypto.PrivKey) bool {
	switch other := key.(type) {
	case *PrivKey:
		return sk.BlsKey.Equals(other.BlsKey) && sk.SignKey.Equals(other.SignKey)
	default:
		return false
	}
}

func (sk PrivKey) Type() string {
	return fmt.Sprintf("%s(%s,%s)", KeyType, sk.BlsKey.Type(), sk.SignKey.Type())
}
