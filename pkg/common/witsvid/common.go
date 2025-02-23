package witsvid

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateJTI() (string, error) {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
