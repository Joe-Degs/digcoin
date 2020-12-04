package digclient

import (
	"crypto/rsa"
	"testing"
)

var (
	client1 = New()
	client2 = New()
	client3 = New()
)

func TestClientsCapabilities(t *testing.T) {
	tt := []struct {
		name, text string
	}{
		{"One", "Joe is a bitch"},
		{"Two", "Its working now!"},
		{"Three", "Third time is a charm"},
	}

	for i, tc := range tt {

		// test
		t.Run(tc.name+" encryption and decryption", func(t *testing.T) {
			ciphertext := client1.DigEncrypt(tc.text)
			if tc.text != client1.DigDecrypt(ciphertext) {
				t.Fatal("something is wrong")
			}
		})

		// this bunch of tests should result in errors that will be taken care some way.
		// if a client signs a message it can only be decrypted with their private key.
		// the recieving client can verify with the sender's public key or something.
		t.Run(tc.name+" decryption without  right private key must fail and result in error", func(t *testing.T) {
			switch i {
			case 0:
				ciphertext := client2.DigEncrypt(tc.text)
				if tc.text == client1.DigDecrypt(ciphertext) {
					t.Fatal("client1 cannot decrypt ciphertext from client2")
				}
				break
			case 1:
				ciphertext := client1.DigEncrypt(tc.text)
				if tc.text == client3.DigDecrypt(ciphertext) {
					t.Fatal("client3 cannot decrypt ciphertext from client1")
				}
				break
			default:
				ciphertext := client3.DigEncrypt(tc.text)
				if tc.text == client1.DigDecrypt(ciphertext) {
					t.Fatal("client1 cannot decrypt ciphertext from client3")
				}
			}
		})

		// this one will leave their public key and cipher text behind for verification processes.
		// this looks like the legit way to do this.
		// so lets test this and see if it works.
		t.Run(tc.name+" verify signature from public and a message digest", func(t *testing.T) {

			// cipher contains a cipher text and the public related with the signing
			type cipher struct {
				key       rsa.PublicKey
				signature string
				text      string
			}

			// returns a new cipher with a public key for verification.
			newCipher := func(cl *Client, msg string) *cipher {
				return &cipher{
					key:       cl.Public(),
					signature: cl.DigSign(msg),
					text:      msg,
				}
			}

			verify := func(cl *Client, ci *cipher) bool {
				return cl.DigVerify(ci.text, ci.signature, &ci.key)
			}

			switch i {
			case 0:
				ciph := newCipher(client1, tc.text)
				if !verify(client2, ciph) {
					t.Fatal("Client2 could not verify client1 signature")
				}
				break
			case 1:
				ciph := newCipher(client2, tc.text)
				if !verify(client3, ciph) {
					t.Fatal("Client3 could not verify Client2 signature")
				}
				break
			default:
				ciph := newCipher(client3, tc.text)
				if !verify(client1, ciph) {
					t.Fatal("Client1 could not verify client3 signature")
				}
			}

		})
	}
}
