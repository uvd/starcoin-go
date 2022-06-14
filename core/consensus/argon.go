package consensus

import (
	"fmt"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/argon2"
)

type ArgonConsensus struct{}

func (ArgonConsensus) CalculateNextDifficulty() {
	//argon2
}

func (ArgonConsensus) CalculatePowHash(headBlob []byte, nonce uint32, extra []byte) ([]byte, error) {
	headerBytes, err := SetHeaderNonce(headBlob, nonce, extra)
	if err != nil {
		return nil, err
	}
	var res = argon2.Key(headerBytes, headerBytes, 3, 1024, 1, 32)
	return res, nil
}

func (c ArgonConsensus)VerifyHeaderDifficulty(difficulty uint256.Int, headerDifficulty uint256.Int, headerBlob []byte, nonce uint32, extra []byte) (bool, error) {
	if difficulty != headerDifficulty {
		return false, fmt.Errorf("verify header difficulty failure, difficulty: %v, headerDifficulty: %v", difficulty, headerDifficulty)
	}
	//calculate_pow_hash
	powHash, err := c.CalculatePowHash(headerBlob, nonce, extra)

	if err != nil {
		return false, err
	}

	//hash to u256
	powValue := new(uint256.Int).SetBytes(powHash)
	target, err := TargetToDiff(&difficulty)
	if err != nil {
		return false, err
	}
	if powValue.Gt(target) {
		return false, fmt.Errorf("verify header difficulty failure, powValue: %v, target: %v", powValue, target)
	}
	return true, nil
}