package client

import (
	"bytes"
	owcrypt "github.com/blocktree/go-owcrypt"
	"github.com/novifinancial/serde-reflection/serde-generate/runtime/golang/bcs"
	"github.com/novifinancial/serde-reflection/serde-generate/runtime/golang/serde"

	"github.com/pkg/errors"
	"github.com/starcoinorg/starcoin-go/types"
	"golang.org/x/crypto/sha3"
)

func hash(prefix, data []byte) []byte {
	concatData := bytes.Buffer{}
	concatData.Write(prefix)
	concatData.Write(data)
	hashData := sha3.Sum256(concatData.Bytes())
	return hashData[:]
}

func prefixHash(name string) []byte {
	return hash([]byte("STARCOIN::"), []byte(name))
}

func signTxn(privateKey types.Ed25519PrivateKey, rawUserTransaction *types.RawUserTransaction) (*types.SignedUserTransaction, error) {
	data := bytes.Buffer{}

	data.Write(prefixHash("RawUserTransaction"))

	rawTxnBytes, err := rawUserTransaction.BcsSerialize()
	if err != nil {
		return nil, errors.Wrap(err, "RawUserTransaction BcsSerialize failed ")
	}
	data.Write(rawTxnBytes)

	signBytes, _, _ := owcrypt.Signature(privateKey, nil, data.Bytes(), owcrypt.ECC_CURVE_ED25519_NORMAL)
	sign := types.Ed25519Signature(signBytes)

	publicKey, _ := owcrypt.GenPubkey(privateKey, owcrypt.ECC_CURVE_ED25519_NORMAL)
	transactionAuthenticator := types.TransactionAuthenticator__Ed25519{
		types.Ed25519PublicKey(publicKey),
		sign,
	}

	return &types.SignedUserTransaction{
		*rawUserTransaction,
		&transactionAuthenticator,
	}, nil
}

func encode_peer_to_peer_v2_script_function(currency types.TypeTag, payee types.AccountAddress, amount serde.Uint128) types.TransactionPayload {
	return &types.TransactionPayload__ScriptFunction{
		types.ScriptFunction{
			Module:   types.ModuleId{Address: [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Name: "TransferScripts"},
			Function: "peer_to_peer_v2",
			TyArgs:   []types.TypeTag{currency},
			Args:     [][]byte{encode_address_argument(payee), encode_u128_argument(amount)},
		},
	}
}

func encode_u128_argument(arg serde.Uint128) []byte {

	s := bcs.NewSerializer()
	if err := s.SerializeU128(arg); err == nil {
		return s.GetBytes()
	}

	panic("Unable to serialize argument of type u64")
}

func encode_address_argument(arg types.AccountAddress) []byte {

	if val, err := arg.BcsSerialize(); err == nil {
		{
			return val
		}
	}

	panic("Unable to serialize argument of type address")
}