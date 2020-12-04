### The digcoin Client package

*   ##### importing?
```go
package digclient // import "github.com/Joe-Degs/digcoin/digclient"
```

*  ##### Overview of package digclient
```go
/*
Package digclient implements a simple client with methods to do basic
cryptographic stuff to message digests.

All methods with "Dig" prefix, are totally just for convinience. They are
supposed to make it easier to do the cryptographic stuff. If you want to do
cryptographic things with a client without reading blogposts and
documentation on anything cryptography, use them.

If you want to do it the hard way, go in for the methods without the prefix
but make sure to read through the rsa, hash and crypto packages before using
them.
*/

var MsgLabel = []byte("a message label")
type Client struct{ ... }
    func New() *Client
type DigOpts struct{}
```

*   ##### the Client struct
```go
type Client struct {
	// Has unexported fields.
}
    // Client is a digcoin user, it implements the crypto.Signer and
    // crypto.Decrypter interfaces.

func New() *Client
func (cl *Client) Decrypt(r io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error)
func (cl *Client) DigDecrypt(ciphertext string) string
func (cl *Client) DigEncrypt(digest string) string
func (cl *Client) DigSign(msg string) string
func (cl *Client) DigVerify(msg string, signature string, key *rsa.PublicKey) bool
func (cl *Client) Encrypt(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
func (cl *Client) Public() rsa.PublicKey
func (cl *Client) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
func (cl *Client) Verify(msg []byte, signature []byte, key *rsa.PublicKey, opts crypto.SignerOpts) error
```

* ##### the DigOpts struct
```go
type DigOpts struct{}
    // DigOpts is a tweak of the crypto.SignerOpts interface, in addition to
    // HashFunc there's another method Hash that's supposed to represent the
    // hashing algorithm itself. To satisfy the crypto.SignerOpts or
    // crypto.DecrypterOpts make sure the struct has both methods on it.

func (DigOpts) Hash() hash.Hash
func (DigOpts) HashFunc() crypto.Hash
```
