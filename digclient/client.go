package digclient

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
)

var (
	MsgPad = []byte("padding for encrypting msg")
)

// sign implements the signer and decryter interface of the crypto package.
type Client struct {
	prikey *rsa.PrivateKey
}

// implements the crypto.SignerOpts and crypto.DecrypterOpts interfaces.
// helper to aid OAEP enc/dec and PSS sign/verify.
type DigOpts struct{}

func (DigOpts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

func (DigOpts) Hash() hash.Hash {
	return sha256.New()
}

func New() *Client {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return &Client{pk}
}

func (cl *Client) Public() rsa.PublicKey {
	return cl.prikey.PublicKey
}

func (cl *Client) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digOpts, ok := (opts).(*DigOpts)
	if !ok {
		digOpts = &DigOpts{}
	}

	// hash msg before signing
	msgHash := digOpts.Hash()
	if _, err := msgHash.Write(digest); err != nil {
		fmt.Fprintln(os.Stdout, err)
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	return rsa.SignPSS(r, cl.prikey, digOpts.HashFunc(), msgHashSum, nil)
}

func (cl *Client) Verify(msg []byte, signature []byte, key *rsa.PublicKey, opts crypto.SignerOpts) error {
	digOpts, ok := (opts).(*DigOpts)
	if !ok {
		digOpts = &DigOpts{}
	}

	msgHash := digOpts.Hash()
	if _, err := msgHash.Write(msg); err != nil {
		// TODO -> better error handling next time.
		fmt.Fprintln(os.Stdout, err)
		return err
	}
	msgHashSum := msgHash.Sum(nil)

	return rsa.VerifyPSS(key, digOpts.HashFunc(), msgHashSum, signature, nil)
}

// encrypt uses the OAEP(i dont know what it means) to sign stuff.
func (cl *Client) Encrypt(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digOpts, ok := (opts).(*DigOpts)
	if !ok {
		digOpts = &DigOpts{}
	}

	// a more secure signature
	pk := cl.Public()
	return rsa.EncryptOAEP(digOpts.Hash(), r, &pk, digest, MsgPad)
}

// decrypt a message to plaintext to know whats up.
func (cl *Client) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	digOpts, ok := (opts).(*DigOpts)
	if !ok {
		digOpts = &DigOpts{}
	}
	return rsa.DecryptOAEP(digOpts.Hash(), r, cl.prikey, msg, MsgPad)
}

func (cl *Client) DigVerify(msg string, signature string, key *rsa.PublicKey) bool {
	err := cl.Verify([]byte(msg), []byte(signature), key, &DigOpts{})
	if err != nil {
		return false
	}
	return true
}

func (cl *Client) DigEncrypt(digest string) string {
	ciphertext, err := cl.Encrypt(rand.Reader, []byte(digest), &DigOpts{})
	if err != nil {
		// TODO -> better error checking next time
		fmt.Fprintln(os.Stdout, err)
		return ""
	}
	return string(ciphertext)
}

// standard Sign implememts the crypto.Signer interface.
// for quick signing of messages digests use this function.
func (cl *Client) DigSign(msg string) string {
	signature, err := cl.Sign(rand.Reader, []byte(msg), &DigOpts{})
	if err != nil {
		fmt.Fprintln(os.Stdout, err)
		return ""
	}
	return string(signature)
}

// Sign implements the crypto.Decrypter interface.
// for unstressful decryption just use this function.
func (cl *Client) DigDecrypt(ciphertext string) string {
	digest, err := cl.Decrypt(rand.Reader, []byte(ciphertext), &DigOpts{})
	if err != nil {
		// TODO -> better error checking next time
		fmt.Fprintln(os.Stdout, err)
		return ""
	}
	return string(digest)
}
