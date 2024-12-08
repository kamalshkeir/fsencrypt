package fsencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

var (
	secretInit string
	salt       []byte
)

func SetSecret(secret string) {
	secretInit = secret
	salt = make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("failed to generate salt: %v", err))
	}
}

func EncryptDir(dir_name string, pass ...string) error {
	var password string
	if len(pass) > 0 {
		password = pass[0]
	} else if secretInit != "" {
		password = secretInit
	} else if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		password = v
	} else {
		return errors.New("secret is not set")
	}

	err := filepath.Walk(dir_name, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			err := EncryptFile(path, path+".encrypted", password)
			if err != nil {
				fmt.Println("error encrypting ", path, ":", err)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func DecryptDir(dir_name string, pass ...string) error {
	var password string
	if len(pass) > 0 {
		password = pass[0]
	} else if secretInit != "" {
		password = secretInit
	} else if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		password = v
	} else {
		return errors.New("secret is not set")
	}

	err := filepath.Walk(dir_name, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			err := DecryptFile(path, path[:len(path)-10], password)
			if err != nil {
				fmt.Println("error decrypting ", path, ":", err)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func EncryptFile(inputfile string, outputfile string, pass ...string) error {
	var password string
	if len(pass) > 0 {
		password = pass[0]
	} else if secretInit != "" {
		password = secretInit
	} else if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		password = v
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			fmt.Printf("failed to generate salt EncryptFile: %v\n", err)
		}
	} else {
		return errors.New("secret is not set")
	}

	// Generate a new salt for each encryption
	salt = make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}

	key, _, err := deriveKey([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("error deriving key: %w", err)
	}

	b, err := os.ReadFile(inputfile)
	if err != nil {
		return fmt.Errorf("unable to open the input file: %w", err)
	}

	ciphertext := encrypt(key, b)
	err = os.WriteFile(outputfile, ciphertext, 0644)
	if err != nil {
		return fmt.Errorf("unable to create encrypted file: %w", err)
	}

	if err := os.Remove(inputfile); err != nil {
		return fmt.Errorf("error removing file %s: %w", inputfile, err)
	}
	return nil
}

func DecryptFile(inputfile string, outputfile string, pass ...string) error {
	var password string
	if len(pass) > 0 {
		password = pass[0]
	} else if secretInit != "" {
		password = secretInit
	} else if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		password = v
	} else {
		return errors.New("secret is not set")
	}

	z, err := os.ReadFile(inputfile)
	if err != nil {
		return fmt.Errorf("unable to read encrypted file: %w", err)
	}

	// Extract salt from encrypted data
	if len(z) < 32 {
		return errors.New("encrypted file is too short")
	}
	salt = z[:32]

	key, _, err := deriveKey([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("error deriving key: %w", err)
	}

	result, err := decrypt(z, key)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	err = os.WriteFile(outputfile, result, 0644)
	if err != nil {
		return fmt.Errorf("unable to create decrypted file: %w", err)
	}

	if err := os.Remove(inputfile); err != nil {
		return fmt.Errorf("error removing file %s: %w", inputfile, err)
	}
	return nil
}

func encrypt(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// Prepend salt to the ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	result := make([]byte, len(salt)+len(ciphertext))
	copy(result, salt)
	copy(result[len(salt):], ciphertext)

	return result
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	if len(data) < len(salt) {
		return nil, errors.New("data too short")
	}

	// Get the ciphertext after the salt
	ciphertext := data[len(salt):]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key(password, salt, 1<<12, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func EncryptData(inp []byte, pass ...string) ([]byte, error) {
	var password string
	if len(pass) > 0 {
		password = pass[0]
	} else if secretInit != "" {
		password = secretInit
	} else if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		password = v
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %v", err)
		}
	} else {
		return nil, errors.New("secret is not set")
	}

	// Generate a new salt for each encryption
	salt = make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	key, _, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}

	ciphertext := encrypt(key, inp)
	return ciphertext, nil
}

func DecryptData(inp []byte, pass ...string) ([]byte, error) {
	var password string
	if len(pass) > 0 {
		password = pass[0]
	} else if secretInit != "" {
		password = secretInit
	} else if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		password = v
	} else {
		return nil, errors.New("secret is not set")
	}

	if len(inp) < 32 {
		return nil, errors.New("encrypted data is too short")
	}
	salt = inp[:32]

	key, _, err := deriveKey([]byte(password), salt)
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}

	result, err := decrypt(inp, key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return result, nil
}

// func randomString(length int) string {
// 	b, _ := randomBytes(length)
// 	return base64.URLEncoding.EncodeToString(b)
// }

// func randomBytes(length int) ([]byte, error) {
// 	b := make([]byte, length)
// 	if _, err := rand.Read(b); err != nil {
// 		return nil, err
// 	}

// 	return b, nil
// }
