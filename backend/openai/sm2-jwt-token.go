package openai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

type SM2JWTToken[T any] struct {
	SM2       *SM2Algorithm
	Header    Header
	Payload   *T
	Signature string
}

type Header struct {
	Algorithm string `json:"algorithm"`
	TokenType string `json:"tokenTyp"`
}

func NewSM2JWTToken[T any](sm2 *SM2Algorithm, payload *T) *SM2JWTToken[T] {
	return &SM2JWTToken[T]{
		SM2:     sm2,
		Header:  Header{Algorithm: "SM2", TokenType: "JWT"},
		Payload: payload,
	}
}

func InitSM2JWTToken[T any](sm2 *SM2Algorithm, payload *T) *SM2JWTToken[T] {
	return NewSM2JWTToken(sm2, payload)
}

func InitSM2JWTTokenByToken[T any](tokenString string, payload *T, sm2 *SM2Algorithm) (*SM2JWTToken[T], error) {
	items, err := validTokenFormat(tokenString)
	if err != nil {
		return nil, err
	}
	headerStr, err := base64.StdEncoding.DecodeString(items[0])
	if err != nil {
		return nil, err
	}
	var header Header
	if err = json.Unmarshal(headerStr, &header); err != nil {
		return nil, err
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(items[1])
	payloadStr := string(payloadBytes)
	fmt.Println("payloadStr:" + payloadStr)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payloadBytes, payload); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(items[2])
	if err != nil {
		return nil, err
	}
	//dataString := string(headerStr) + "_" + payloadStr
	//success := sm2.VerifySign(string(signature), []byte(dataString))
	//if !success {
	//	panic("token 签名验证失败")
	//}
	return &SM2JWTToken[T]{SM2: sm2, Header: header, Payload: payload, Signature: string(signature)}, nil
}

func validTokenFormat(tokenString string) ([]string, error) {
	if tokenString == "" {
		return nil, errors.New("token不能为空")
	}
	items := bytes.Split([]byte(tokenString), []byte("."))
	if len(items) < 3 {
		return nil, errors.New("token 不是jwt格式")
	}
	var header Header
	headerBytes, err := base64.StdEncoding.DecodeString(string(items[0]))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	needHeader := Header{Algorithm: "SM2", TokenType: "JWT"}
	if !reflect.DeepEqual(header, needHeader) {
		return nil, errors.New("token加密算法不正确")
	}
	return []string{string(items[0]), string(items[1]), string(items[2])}, nil
}

func ParsePayload[T any](tokenString string) (*T, error) {
	items, err := validTokenFormat(tokenString)
	if err != nil {
		return nil, err
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(items[1])
	if err != nil {
		return nil, err
	}
	var payload T
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (t *SM2JWTToken[T]) GetTokenString() (string, error) {
	if err := t.validHeader(); err != nil {
		return "", err
	}
	if err := t.validPayload(); err != nil {
		return "", err
	}
	signatureData, err := t.getSignatureData()
	if err != nil {
		return "", err
	}
	tokenSignature := t.SM2.Sign([]byte(signatureData))

	t.Signature = tokenSignature
	headerBytes, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(t.Payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(headerBytes) + "." + base64.StdEncoding.EncodeToString(payloadBytes) + "." + base64.StdEncoding.EncodeToString([]byte(tokenSignature)), nil
}

func (t *SM2JWTToken[T]) validPayload() error {
	if reflect.ValueOf(t.Payload).IsZero() {
		return errors.New("payload不能为空")
	}
	return nil
}

func (t *SM2JWTToken[T]) validHeader() error {
	if reflect.ValueOf(t.Header).IsZero() {
		return errors.New("header不能为空")
	}
	if t.Header.Algorithm != "SM2" || t.Header.TokenType != "JWT" {
		return errors.New("header非法")
	}
	return nil
}

func (t *SM2JWTToken[T]) getSignatureData() (string, error) {
	if err := t.validPayload(); err != nil {
		return "", err
	}
	headerBytes, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}
	payloadBytes, err := json.Marshal(t.Payload)
	if err != nil {
		return "", err
	}
	var headerMap sortedMap
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		return "", err
	}
	headerBytes, _ = headerMap.MarshalJSON()
	var payloadMap sortedMap
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return "", err
	}
	payloadBytes, _ = payloadMap.MarshalJSON()
	return string(headerBytes) + "_" + string(payloadBytes), nil
}
