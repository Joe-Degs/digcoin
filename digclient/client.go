/*
   Package digclient implements a simple client with methods to do basic
   cryptographic stuff to message digests.

   All methods with "Dig" prefix, are totally just for convinience.
   They are supposed to make it easier to do the cryptographic stuff.
   If you want to do cryptographic things with a client without reading
   blogposts and documentation on anything cryptography, use them.

   If you want to do it the hard way, go in for the methods without the prefix
   but make sure to read through the rsa, hash and crypto packages before using them.
*/
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
	// MsgLabel serves as label for encrypting/decrypting OAEP.
	// TODO -> this label should be set by the client or something.
	// i'll try and figure it out.
	MsgLabel = []byte("a message label")
)

// Client is a digcoin user, it implements the crypto.Signer and
// crypto.Decrypter interfaces.
type Client struct {
	prikey *rsa.PrivateKey
}

// DigOpts is a  tweak of the crypto.SignerOpts interface, in addition
// to HashFunc there's another method Hash that's supposed to represent
// the hashing algorithm itself. To satisfy the crypto.SignerOpts or
// crypto.DecrypterOpts make sure the struct has both methods on it.
type DigOpts struct{}

// HashFunc represents the id of the hashing algorithm.
func (DigOpts) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// Hash represents the hashing algorithm.
func (DigOpts) Hash() hash.Hash {
	return sha256.New()
}

// New returns a new Client
func New() *Client {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return &Client{pk}
}

// Public represents the rsa public key of the a Client.
func (cl *Client) Public() rsa.PublicKey {
	return cl.prikey.PublicKey
}

// Sign retuns the cryptographic signature of a message digest using a clients rsa private
// key
func (cl *Client) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
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

	return rsa.SignPSS(rand, cl.prikey, digOpts.HashFunc(), msgHashSum, nil)
}

// Verify checks the make sure the cryptographic signature of a message digest is right using PSS.
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

// Encrypt uses OAEP(i dont know what it means) to encipher message digests.
func (cl *Client) Encrypt(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digOpts, ok := (opts).(*DigOpts)
	if !ok {
		digOpts = &DigOpts{}
	}

	// a more secure signature
	pk := cl.Public()
	return rsa.EncryptOAEP(digOpts.Hash(), rand, &pk, digest, MsgLabel)
}

// Decrypt, deciphers a message digest using the clients rsa private key.
func (cl *Client) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	digOpts, ok := (opts).(*DigOpts)
	if !ok {
		digOpts = &DigOpts{}
	}
	return rsa.DecryptOAEP(digOpts.Hash(), rand, cl.prikey, msg, MsgLabel)
}

// DigVerify checks the authenticity of a cryptographic signature.
func (cl *Client) DigVerify(msg string, signature string, key *rsa.PublicKey) bool {
	err := cl.Verify([]byte(msg), []byte(signature), key, &DigOpts{})
	if err != nil {
		return false
	}
	return true
}

// DigEncrypt encrypts any message digest string passed to it.
func (cl *Client) DigEncrypt(digest string) string {
	ciphertext, err := cl.Encrypt(rand.Reader, []byte(digest), &DigOpts{})
	if err != nil {
		// TODO -> better error checking next time
		fmt.Fprintln(os.Stdout, err)
		return ""
	}
	return string(ciphertext)
}

// DigSign returns the cryptographic signature of a message digest.
func (cl *Client) DigSign(msg string) string {
	signature, err := cl.Sign(rand.Reader, []byte(msg), &DigOpts{})
	if err != nil {
		// TODO -> better error checking next time
		fmt.Fprintln(os.Stdout, err)
		return ""
	}
	return string(signature)
}

// DigDecrypt tries to decipher any ciphertext string passed to it.
func (cl *Client) DigDecrypt(ciphertext string) string {
	digest, err := cl.Decrypt(rand.Reader, []byte(ciphertext), &DigOpts{})
	if err != nil {
		// TODO -> better error checking next time
		fmt.Fprintln(os.Stdout, err)
		return ""
	}
	return string(digest)
}
