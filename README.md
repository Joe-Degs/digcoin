# DigCoin

I am trying to learn how bitcoin works, so I'm using my little knowledge of go to try and write a sample program of how I think it works. Everything I write is how I think bitcoin works. It will definitely not be accurate because there is lots of cryptography involved that I won't understand because I'm not good at maths. Digcoin just came to me when I was trying to figure which name to give the project folder. LOL!
Arggh before I forget, there are too many concepts on networking and distributed computing bitcoin implements that I won't understand for the next 5 years soo yah. I think I should name it errcoin.

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
