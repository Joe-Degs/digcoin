### The digcoin Client package
--------

*   ##### the package
```go
package digclient // import "github.com/Joe-Degs/digcoin/digclient"
```

*  ##### Overview of types in the package
```go
var MsgPad = []byte("padding for encrypting msg")
type Client struct{ ... }
    func New() *Client
type DigOpts struct{}
```

*   ##### the Client struct
```go
type Client struct {
	// Has unexported fields.
}
    sign implements the signer and decryter interface of the crypto package.

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
    implements the crypto.SignerOpts and crypto.DecrypterOpts interfaces. helper
    to aid OAEP encryption/decryption and PSS signing/verification.

func (DigOpts) Hash() hash.Hash
func (DigOpts) HashFunc() crypto.Hash
```
