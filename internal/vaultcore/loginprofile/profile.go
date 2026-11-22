// Package loginprofile reads and writes encrypted .gvprofile login profile
// containers. Login profiles carry connection metadata and optional API key
// credentials, and strictly never store a master password.
package loginprofile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/txchen/govault/internal/vaultcore/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	FormatName         = "govault-login-profile"
	FormatVersion      = 1
	MaxFileSize        = 64 << 10 // 64 KiB
	MinPassphraseRunes = 8
	AAD                = "govault-login-profile-v1"

	KDFPBKDF2   = "pbkdf2-sha256"
	KDFArgon2id = "argon2id"

	AuthModePassword = "password"
	AuthModeAPIKey   = "apikey"

	saltLen  = 16
	nonceLen = 12
)

var (
	ErrInvalidProfile     = errors.New("loginprofile: invalid encrypted login profile")
	ErrWrongPassphrase    = errors.New("loginprofile: incorrect profile passphrase")
	ErrPassphraseTooShort = fmt.Errorf("loginprofile: passphrase must be at least %d characters", MinPassphraseRunes)
	ErrProfileTooLarge    = fmt.Errorf("loginprofile: profile exceeds %d KiB limit", MaxFileSize>>10)
)

// DefaultKDF is the KDF used when exporting new login profiles.
var DefaultKDF = crypto.KDFConfig{
	Type:        crypto.KDFArgon2id,
	Iterations:  3,
	MemoryMB:    64,
	Parallelism: 4,
}

// Profile is the plaintext payload encrypted inside a .gvprofile container.
// By design it has no master password field and unknown JSON fields are
// rejected during decoding.
type Profile struct {
	ServerURL    string    `json:"serverUrl"`
	Email        string    `json:"email"`
	AuthMode     string    `json:"authMode"`
	ClientID     string    `json:"clientId,omitempty"`
	ClientSecret string    `json:"clientSecret,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
}

type container struct {
	Format         string  `json:"format"`
	Version        int     `json:"version"`
	KDF            string  `json:"kdf"`
	KDFIterations  uint32  `json:"kdfIterations"`
	KDFMemory      *uint32 `json:"kdfMemory,omitempty"`
	KDFParallelism *uint32 `json:"kdfParallelism,omitempty"`
	Salt           string  `json:"salt"`
	Nonce          string  `json:"nonce"`
	Ciphertext     string  `json:"ciphertext"`
}

// Validate checks that p contains valid, self-consistent login profile fields.
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil profile", ErrInvalidProfile)
	}
	server := strings.TrimRight(strings.TrimSpace(p.ServerURL), "/")
	u, err := url.Parse(server)
	if server == "" || err != nil || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: invalid serverUrl", ErrInvalidProfile)
	}
	email := strings.TrimSpace(p.Email)
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidProfile)
	}
	switch p.AuthMode {
	case AuthModePassword:
		if strings.TrimSpace(p.ClientID) != "" || strings.TrimSpace(p.ClientSecret) != "" {
			return fmt.Errorf("%w: password profile must not contain API credentials", ErrInvalidProfile)
		}
	case AuthModeAPIKey:
		if strings.TrimSpace(p.ClientID) == "" || strings.TrimSpace(p.ClientSecret) == "" {
			return fmt.Errorf("%w: apikey profile requires clientId and clientSecret", ErrInvalidProfile)
		}
	default:
		return fmt.Errorf("%w: unsupported authMode %q", ErrInvalidProfile, p.AuthMode)
	}
	return nil
}

// Encrypt serializes p into an encrypted .gvprofile JSON container protected
// with passphrase using AES-256-GCM and the configured KDF.
func Encrypt(p Profile, passphrase []byte, cfg crypto.KDFConfig) ([]byte, error) {
	if utf8.RuneCount(passphrase) < MinPassphraseRunes {
		return nil, ErrPassphraseTooShort
	}
	p.ServerURL = strings.TrimRight(strings.TrimSpace(p.ServerURL), "/")
	p.Email = strings.TrimSpace(p.Email)
	p.ClientID = strings.TrimSpace(p.ClientID)
	p.ClientSecret = strings.TrimSpace(p.ClientSecret)
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	} else {
		p.CreatedAt = p.CreatedAt.UTC()
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := crypto.ValidateKDF(cfg); err != nil {
		return nil, err
	}

	var salt [saltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	key, err := deriveKey(passphrase, salt[:], cfg)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key[:])

	plaintext, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(plaintext)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce[:], plaintext, []byte(AAD))

	c := container{
		Format:        FormatName,
		Version:       FormatVersion,
		KDFIterations: cfg.Iterations,
		Salt:          base64.StdEncoding.EncodeToString(salt[:]),
		Nonce:         base64.StdEncoding.EncodeToString(nonce[:]),
		Ciphertext:    base64.StdEncoding.EncodeToString(ct),
	}
	switch cfg.Type {
	case crypto.KDFPBKDF2:
		c.KDF = KDFPBKDF2
	case crypto.KDFArgon2id:
		c.KDF = KDFArgon2id
		mem, par := cfg.MemoryMB, cfg.Parallelism
		c.KDFMemory, c.KDFParallelism = &mem, &par
	default:
		return nil, crypto.ErrInvalidKDF
	}

	out, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(out) > MaxFileSize {
		crypto.ZeroBytes(out)
		return nil, ErrProfileTooLarge
	}
	return out, nil
}

// ValidateContainer verifies the unencrypted outer .gvprofile metadata and
// bounding constraints before asking the user for a passphrase.
func ValidateContainer(data []byte) error {
	_, _, _, _, _, err := parseContainer(data)
	return err
}

// Decrypt authenticates and decrypts a .gvprofile container using passphrase.
// Decrypted payloads containing unknown or disallowed fields (such as a
// masterPassword field) are strictly rejected.
func Decrypt(data, passphrase []byte) (*Profile, error) {
	if len(passphrase) == 0 {
		return nil, ErrWrongPassphrase
	}
	cfg, salt, nonce, ciphertext, _, err := parseContainer(data)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(ciphertext)

	key, err := deriveKey(passphrase, salt, cfg)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key[:])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.Overhead() {
		return nil, ErrInvalidProfile
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(AAD))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer crypto.ZeroBytes(plaintext)

	var p Profile
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected trailing data", ErrInvalidProfile)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func parseContainer(data []byte) (crypto.KDFConfig, []byte, []byte, []byte, *container, error) {
	if len(data) > MaxFileSize {
		return crypto.KDFConfig{}, nil, nil, nil, nil, ErrProfileTooLarge
	}
	var c container
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: trailing data", ErrInvalidProfile)
	}
	if c.Format != FormatName || c.Version != FormatVersion {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: unsupported format or version", ErrInvalidProfile)
	}

	var cfg crypto.KDFConfig
	switch c.KDF {
	case KDFPBKDF2:
		if c.KDFMemory != nil || c.KDFParallelism != nil {
			return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: unexpected argon2 fields for pbkdf2", ErrInvalidProfile)
		}
		cfg = crypto.KDFConfig{Type: crypto.KDFPBKDF2, Iterations: c.KDFIterations}
	case KDFArgon2id:
		if c.KDFMemory == nil || c.KDFParallelism == nil {
			return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: missing argon2 parameters", ErrInvalidProfile)
		}
		cfg = crypto.KDFConfig{
			Type:        crypto.KDFArgon2id,
			Iterations:  c.KDFIterations,
			MemoryMB:    *c.KDFMemory,
			Parallelism: *c.KDFParallelism,
		}
	default:
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: unsupported kdf %q", ErrInvalidProfile, c.KDF)
	}
	if err := crypto.ValidateKDF(cfg); err != nil {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}

	salt, err := base64.StdEncoding.DecodeString(c.Salt)
	if err != nil || len(salt) != saltLen {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: invalid salt", ErrInvalidProfile)
	}
	nonce, err := base64.StdEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: invalid nonce", ErrInvalidProfile)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(c.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return crypto.KDFConfig{}, nil, nil, nil, nil, fmt.Errorf("%w: invalid ciphertext", ErrInvalidProfile)
	}
	return cfg, salt, nonce, ciphertext, &c, nil
}

func deriveKey(passphrase, salt []byte, cfg crypto.KDFConfig) ([32]byte, error) {
	var key [32]byte
	if err := crypto.ValidateKDF(cfg); err != nil {
		return key, err
	}
	switch cfg.Type {
	case crypto.KDFPBKDF2:
		raw := pbkdf2.Key(passphrase, salt, int(cfg.Iterations), 32, sha256.New)
		copy(key[:], raw)
		crypto.ZeroBytes(raw)
		return key, nil
	case crypto.KDFArgon2id:
		raw := argon2.IDKey(passphrase, salt, cfg.Iterations, cfg.MemoryMB*1024, uint8(cfg.Parallelism), 32)
		copy(key[:], raw)
		crypto.ZeroBytes(raw)
		debug.FreeOSMemory()
		return key, nil
	default:
		return key, crypto.ErrInvalidKDF
	}
}
