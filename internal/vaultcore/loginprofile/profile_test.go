package loginprofile

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/txchen/govault/internal/vaultcore/crypto"
)

func TestEncryptDecryptRoundTrip_Argon2idAndPBKDF2(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		kdf     crypto.KDFConfig
		wantKDF string
		profile Profile
	}{
		{
			name:    "argon2id-apikey",
			kdf:     crypto.KDFConfig{Type: crypto.KDFArgon2id, Iterations: 2, MemoryMB: 16, Parallelism: 1},
			wantKDF: KDFArgon2id,
			profile: Profile{
				ServerURL:    "https://vault.example.com/",
				Email:        "alice@example.com",
				AuthMode:     AuthModeAPIKey,
				ClientID:     "user.1234",
				ClientSecret: "secret-abcd",
				CreatedAt:    now,
			},
		},
		{
			name:    "pbkdf2-password",
			kdf:     crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000},
			wantKDF: KDFPBKDF2,
			profile: Profile{
				ServerURL: "https://vault.example.eu",
				Email:     "bob@example.com",
				AuthMode:  AuthModePassword,
				CreatedAt: now,
			},
		},
	}

	passphrase := []byte("correct-horse-passphrase")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := Encrypt(tc.profile, passphrase, tc.kdf)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if len(enc) > MaxFileSize {
				t.Fatalf("encoded size %d > %d", len(enc), MaxFileSize)
			}
			if err := ValidateContainer(enc); err != nil {
				t.Fatalf("ValidateContainer: %v", err)
			}

			var raw container
			if err := json.Unmarshal(enc, &raw); err != nil {
				t.Fatalf("Unmarshal container: %v", err)
			}
			if raw.Format != FormatName || raw.Version != FormatVersion || raw.KDF != tc.wantKDF {
				t.Fatalf("unexpected container header: %+v", raw)
			}
			if strings.Contains(string(enc), tc.profile.ServerURL) ||
				strings.Contains(string(enc), tc.profile.Email) ||
				(tc.profile.ClientSecret != "" && strings.Contains(string(enc), tc.profile.ClientSecret)) {
				t.Fatal("plaintext secret or metadata leaked into encrypted container")
			}

			got, err := Decrypt(enc, passphrase)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if got.ServerURL != strings.TrimRight(tc.profile.ServerURL, "/") ||
				got.Email != tc.profile.Email ||
				got.AuthMode != tc.profile.AuthMode ||
				got.ClientID != tc.profile.ClientID ||
				got.ClientSecret != tc.profile.ClientSecret ||
				!got.CreatedAt.Equal(now) {
				t.Fatalf("decrypted profile = %+v, want %+v", got, tc.profile)
			}
		})
	}
}

func TestEncrypt_MinimumPassphraseAndRandomSaltNonce(t *testing.T) {
	p := Profile{ServerURL: "https://vault.example.com", Email: "a@b.com", AuthMode: AuthModePassword}
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}

	for _, short := range [][]byte{nil, []byte("1234567"), []byte("一二三四五六七")} {
		if _, err := Encrypt(p, short, kdf); !errors.Is(err, ErrPassphraseTooShort) {
			t.Fatalf("short passphrase %q = %v, want ErrPassphraseTooShort", short, err)
		}
	}
	// Exactly 8 multi-byte runes is accepted.
	if _, err := Encrypt(p, []byte("一二三四五六七八"), kdf); err != nil {
		t.Fatalf("8-rune UTF-8 passphrase failed: %v", err)
	}

	a, err := Encrypt(p, []byte("passphrase-1"), kdf)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(p, []byte("passphrase-1"), kdf)
	if err != nil {
		t.Fatal(err)
	}
	var ca, cb container
	_ = json.Unmarshal(a, &ca)
	_ = json.Unmarshal(b, &cb)
	if ca.Salt == cb.Salt || ca.Nonce == cb.Nonce || ca.Ciphertext == cb.Ciphertext {
		t.Fatal("re-encryption reused salt, nonce, or ciphertext")
	}
}

func TestDecrypt_WrongPassphraseAndAADTampProof(t *testing.T) {
	p := Profile{
		ServerURL:    "https://vault.example.com",
		Email:        "alice@example.com",
		AuthMode:     AuthModeAPIKey,
		ClientID:     "user.1",
		ClientSecret: "sec-1",
	}
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}
	passphrase := []byte("valid-passphrase-1")
	enc, err := Encrypt(p, passphrase, kdf)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Decrypt(enc, []byte("wrong-passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
	if _, err := Decrypt(enc, nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("empty passphrase = %v, want ErrWrongPassphrase", err)
	}

	// Tamper ciphertext byte.
	var c container
	_ = json.Unmarshal(enc, &c)
	ct, _ := base64.StdEncoding.DecodeString(c.Ciphertext)
	ct[0] ^= 0xff
	c.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(c)
	if _, err := Decrypt(tampered, passphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("tampered ciphertext = %v, want ErrWrongPassphrase", err)
	}

	// Re-encrypt with wrong AAD to prove AAD binding is enforced.
	var c2 container
	_ = json.Unmarshal(enc, &c2)
	salt, _ := base64.StdEncoding.DecodeString(c2.Salt)
	nonce, _ := base64.StdEncoding.DecodeString(c2.Nonce)
	key, err := deriveKey(passphrase, salt, kdf)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	pt, _ := json.Marshal(p)
	c2.Ciphertext = base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, pt, []byte("wrong-aad")))
	wrongAAD, _ := json.Marshal(c2)
	if _, err := Decrypt(wrongAAD, passphrase); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong AAD = %v, want ErrWrongPassphrase", err)
	}
}

func TestDecrypt_RejectsLegacyOrUnknownMasterPasswordFields(t *testing.T) {
	kdf := crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: 5000}
	passphrase := []byte("valid-passphrase-1")
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(nonce)
	key, err := deriveKey(passphrase, salt, kdf)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)

	for _, payload := range []string{
		`{"serverUrl":"https://vault.example.com","email":"a@b.com","authMode":"password","masterPassword":"leaked-secret","createdAt":"2026-11-22T00:00:00Z"}`,
		`{"serverUrl":"https://vault.example.com","email":"a@b.com","authMode":"apikey","clientId":"user.1","clientSecret":"sec","password":"leaked","createdAt":"2026-11-22T00:00:00Z"}`,
		`{"serverUrl":"https://vault.example.com","email":"a@b.com","authMode":"apikey","clientId":"user.1","clientSecret":"sec","unknownField":true,"createdAt":"2026-11-22T00:00:00Z"}`,
		`{"serverUrl":"https://vault.example.com","email":"a@b.com","authMode":"password","clientId":"user.1","clientSecret":"sec","createdAt":"2026-11-22T00:00:00Z"}`,
		`{"serverUrl":"javascript:alert(1)","email":"a@b.com","authMode":"password","createdAt":"2026-11-22T00:00:00Z"}`,
	} {
		ct := gcm.Seal(nil, nonce, []byte(payload), []byte(AAD))
		raw, _ := json.Marshal(container{
			Format:        FormatName,
			Version:       FormatVersion,
			KDF:           KDFPBKDF2,
			KDFIterations: kdf.Iterations,
			Salt:          base64.StdEncoding.EncodeToString(salt),
			Nonce:         base64.StdEncoding.EncodeToString(nonce),
			Ciphertext:    base64.StdEncoding.EncodeToString(ct),
		})
		if _, err := Decrypt(raw, passphrase); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("payload %s decrypted unexpectedly: %v", payload, err)
		}
	}
}

func TestContainerBoundsAndValidation(t *testing.T) {
	oversize := make([]byte, MaxFileSize+1)
	if err := ValidateContainer(oversize); !errors.Is(err, ErrProfileTooLarge) {
		t.Fatalf("oversize ValidateContainer = %v, want ErrProfileTooLarge", err)
	}
	if _, err := Decrypt(oversize, []byte("passphrase-1")); !errors.Is(err, ErrProfileTooLarge) {
		t.Fatalf("oversize Decrypt = %v, want ErrProfileTooLarge", err)
	}

	for _, bad := range []string{
		`not json`,
		`{"format":"other","version":1}`,
		`{"format":"govault-login-profile","version":2}`,
		`{"format":"govault-login-profile","version":1,"kdf":"pbkdf2-sha256","kdfIterations":100,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		`{"format":"govault-login-profile","version":1,"kdf":"argon2id","kdfIterations":3,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
		`{"format":"govault-login-profile","version":1,"kdf":"pbkdf2-sha256","kdfIterations":5000,"salt":"AAAA","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
	} {
		if err := ValidateContainer([]byte(bad)); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("ValidateContainer(%s) = %v, want ErrInvalidProfile", bad, err)
		}
	}
}
