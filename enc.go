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

func init() {
	if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
		secretInit = v
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			fmt.Printf("failed to generate salt: %v\n", err)
			return
		}
	}
}

func SetSecret(secret string) {
	secretInit = secret
	salt = make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		panic(fmt.Sprintf("failed to generate salt: %v", err))
	}
}

func EncryptDir(dir_name string) error {
	err := filepath.Walk(dir_name, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			err := EncryptFile(path, path+".encrypted")
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

func DecryptDir(dir_name string) error {
	err := filepath.Walk(dir_name, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			err := DecryptFile(path, path[:len(path)-10])
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
	var key []byte
	var err error
	if len(pass) > 0 {
		key, _, err = deriveKey([]byte(pass[0]), salt)
	} else if secretInit != "" {
		key, _, err = deriveKey([]byte(secretInit), salt)
	}
	if err != nil {
		return fmt.Errorf("error deriving key: %w", err)
	}
	if key == nil {
		return errors.New("secret is not set")
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
	var key []byte
	var err error
	if len(pass) > 0 {
		key, _, err = deriveKey([]byte(pass[0]), salt)
	} else if secretInit != "" {
		key, _, err = deriveKey([]byte(secretInit), salt)
	}
	if err != nil {
		return fmt.Errorf("error deriving key: %w", err)
	}
	if key == nil {
		return errors.New("secret is not set")
	}

	z, err := os.ReadFile(inputfile)
	if err != nil {
		return fmt.Errorf("unable to read encrypted file: %w", err)
	}

	result, err := decrypt(z)
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

func decrypt(data []byte) ([]byte, error) {
	if len(data) < len(salt) {
		return nil, errors.New("data too short")
	}

	// Extract salt and use it to derive the key
	dataSalt := data[:len(salt)]
	ciphertext := data[len(salt):]

	key, _, err := deriveKey([]byte(secretInit), dataSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

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
	var key []byte
	var err error
	if len(pass) > 0 {
		key, _, err = deriveKey([]byte(pass[0]), salt)
	} else if secretInit != "" {
		key, _, err = deriveKey([]byte(secretInit), salt)
	} else {
		if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
			key, _, err = deriveKey([]byte(v), salt)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}
	if key == nil {
		return nil, errors.New("secret is not set")
	}

	ciphertext := encrypt(key, inp)
	return ciphertext, nil
}

func DecryptData(inp []byte, pass ...string) ([]byte, error) {
	var key []byte
	var err error
	if len(pass) > 0 {
		key, _, err = deriveKey([]byte(pass[0]), salt)
	} else if secretInit != "" {
		key, _, err = deriveKey([]byte(secretInit), salt)
	} else {
		if v := os.Getenv("FSENCRYPT_SECRET"); v != "" {
			key, _, err = deriveKey([]byte(v), salt)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}
	if key == nil {
		return nil, errors.New("secret is not set")
	}

	result, err := decrypt(inp)
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
