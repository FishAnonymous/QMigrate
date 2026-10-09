
package main
import ("crypto/rsa"; "crypto/rand"; "crypto/sha256"; "crypto")
func main() {
 key, err := rsa.GenerateKey(rand.Reader, 2048); if err != nil { panic(err) }
 hash := sha256.Sum256([]byte("controlled signature unit 2"))
 sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], nil); if err != nil { panic(err) }
 if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, hash[:], sig, nil); err != nil { panic(err) }
}
