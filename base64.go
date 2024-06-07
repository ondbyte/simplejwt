package simplejwt

import (
	"encoding/base64"
	"strings"
)

// Function to encode a string to Base64Url
func base64UrlEncode(input string) string {
	encoded := base64.URLEncoding.EncodeToString([]byte(input))
	// remove padding
	return strings.TrimRight(encoded, "=")
}

// function to decode base64 string
func base64UrlDecode(input string) (string, error) {
	input = addPadding(input)
	decoded, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func addPadding(encoded string) string {
	// Determine the required padding length
	paddingLength := len(encoded) % 4
	if paddingLength == 0 {
		return encoded // No padding needed
	}

	// Add padding characters
	padding := strings.Repeat("=", 4-paddingLength)
	return encoded + padding
}
