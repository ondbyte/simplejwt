package simplejwt

type Signer interface {
	// Method to create a HMAC SHA256 signature
	// returned signature will be raw/un encoded
	Sign(data string) (sign string, err error)

	Verify(data string, sign string) (bool, error)

	// returns the header string
	Header() string
}
