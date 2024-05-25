package openai

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

type SM2Algorithm struct {
	privateKey *sm2.PrivateKey
	publicKey  *sm2.PublicKey
}

func NewSM2Algorithm() *SM2Algorithm {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate SM2 key: %v", err)
	}
	return &SM2Algorithm{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}
}

func NewSM2AlgorithmByPrivateKey(privateKeyHex string) *SM2Algorithm {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		log.Fatalf("Failed to decode private key hex: %v", err)
	}
	privateKey := new(sm2.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(privateKeyBytes)
	privateKey.Curve = sm2.P256Sm2()
	privateKey.PublicKey.Curve = sm2.P256Sm2()
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.ScalarBaseMult(privateKeyBytes)
	return &SM2Algorithm{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}
}

func NewSM2AlgorithmByPublicKey(publicKeyHex string) (*SM2Algorithm, error) {
	if len(publicKeyHex) == 130 {
		publicKeyHex = publicKeyHex[2:]
	}
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(publicKeyBytes[:len(publicKeyBytes)/2])
	y := new(big.Int).SetBytes(publicKeyBytes[len(publicKeyBytes)/2:])
	publicKey := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}
	return &SM2Algorithm{
		publicKey: publicKey,
	}, nil
}

func (s *SM2Algorithm) PrivateKey() string {
	privateKeyBytes := s.privateKey.D.Bytes()
	return hex.EncodeToString(privateKeyBytes)
}

func (s *SM2Algorithm) PublicKey() string {
	publicKeyBytes := append(s.publicKey.X.Bytes(), s.publicKey.Y.Bytes()...)
	return hex.EncodeToString(publicKeyBytes)
}

func (s *SM2Algorithm) Sign(data []byte) string {
	signature, err := s.privateKey.Sign(rand.Reader, data, nil)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	return hex.EncodeToString(signature)
}

func (s *SM2Algorithm) SignString(data string) string {
	return s.Sign([]byte(data))
}

func (s *SM2Algorithm) SignObject(data interface{}) string {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal data: %v", err)
	}
	return s.Sign(dataBytes)
}

func (s *SM2Algorithm) Encrypt(data []byte) string {
	encryptedData, err := sm2.Encrypt(s.publicKey, data, rand.Reader, 1)
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}
	return hex.EncodeToString(encryptedData)
}

func (s *SM2Algorithm) EncryptString(data string) string {
	return s.Encrypt([]byte(data))
}

func (s *SM2Algorithm) EncryptObject(data interface{}) string {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal data: %v", err)
	}
	return s.Encrypt(dataBytes)
}

func (s *SM2Algorithm) Decrypt(encryptedHex string) []byte {
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}
	decryptedData, err := sm2.Decrypt(s.privateKey, encryptedData, 1)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v", err)
	}
	return decryptedData
}

func (s *SM2Algorithm) DecryptString(encryptedHex string) string {
	decryptedData := s.Decrypt(encryptedHex)
	return string(decryptedData)
}

func (s *SM2Algorithm) DecryptObject(encryptedHex string, data interface{}) {
	decryptedData := s.DecryptString(encryptedHex)
	err := json.Unmarshal([]byte(decryptedData), data)
	if err != nil {
		log.Fatalf("Failed to unmarshal decrypted data: %v", err)
	}
}

func (s *SM2Algorithm) VerifySign(signatureHex string, data []byte) bool {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		panic(err)
	}
	return s.publicKey.Verify(data, signature)
}

func (s *SM2Algorithm) VerifySignString(signatureHex string, data string) bool {
	return s.VerifySign(signatureHex, []byte(data))
}

func (s *SM2Algorithm) VerifySignObject(signatureHex string, data interface{}) bool {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal data: %v", err)
	}
	return s.VerifySign(signatureHex, dataBytes)
}
