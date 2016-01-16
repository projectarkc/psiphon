package crypto

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"time"
)

const OBFUSCATE_SEED_LENGTH = 16
const OBFUSCATE_KEY_LENGTH = 16
const OBFUSCATE_HASH_ITERATIONS = 6000
const OBFUSCATE_MAGIC_VALUE uint32 = 0x0BF5CA7E
const OBFUSCATE_MAX_PADDING = 32
const CLIENT_TO_SERVER_IV = "client_to_server"

type Crypto struct {
	publicKey          [32]byte
	privateKey         [32]byte
	nonce              [24]byte
}

func (cr *Crypto) generateKey(seed []byte, keyword []byte, iv []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(seed)
	h.Write(keyword)
	h.Write(iv)
	digest := h.Sum(nil)

	for i := 0; i < 6000; i++ {
		h.Reset()
		h.Write(digest)
		digest = h.Sum(nil)
	}

	if len(digest) < OBFUSCATE_KEY_LENGTH {
		return nil, errors.New("generateKey: SHA1 digest is too short")
	}

	digest = digest[0:OBFUSCATE_KEY_LENGTH]
	return digest, nil
}

func (cr *Crypto) Obfuscate(data []byte, obfuscationKeyword string) ([]byte, error) {
	seed := make([]byte, OBFUSCATE_SEED_LENGTH)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}

	key, err := cr.generateKey(seed, []byte(obfuscationKeyword), []byte(CLIENT_TO_SERVER_IV))
	if err != nil {
		return nil, err
	}

	mrand.Seed(time.Now().UTC().UnixNano())
	plength := mrand.Intn(OBFUSCATE_MAX_PADDING)

	padding := make([]byte, plength)
	_, err = rand.Read(padding)
	if err != nil {
		return nil, err
	}

	output := make([]byte, OBFUSCATE_SEED_LENGTH+4+4+plength+len(data))

	offset := 0
	copy(output[offset:offset+OBFUSCATE_SEED_LENGTH], seed)

	offset += OBFUSCATE_SEED_LENGTH
	binary.BigEndian.PutUint32(output[offset:offset+4], OBFUSCATE_MAGIC_VALUE)

	offset += 4
	binary.BigEndian.PutUint32(output[offset:offset+4], uint32(plength))

	offset += 4
	copy(output[offset:offset+plength], padding)

	offset += plength
	copy(output[offset:], data)

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, errors.New("Obfuscate: couldn't init new RC4")
	}

	cipher.XORKeyStream(output[OBFUSCATE_SEED_LENGTH:], output[OBFUSCATE_SEED_LENGTH:])
	return output, nil

}

func (cr *Crypto) Deobfuscate(data []byte, obfuscationKeyword string) ([]byte, error) {
	if len(data) < OBFUSCATE_SEED_LENGTH {
		return nil, errors.New("Deobfuscate: payload is too short")
	}

	key, err := cr.generateKey(data[0:OBFUSCATE_SEED_LENGTH], []byte(obfuscationKeyword), []byte(CLIENT_TO_SERVER_IV))
	if err != nil {
		return nil, err
	}

	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, errors.New("Deobfuscate: couldn't init new RC4")
	}

	data = data[OBFUSCATE_SEED_LENGTH:]

	cipher.XORKeyStream(data, data)

	if len(data) < 4 {
		return nil, errors.New("Deobfuscate: magic value is less than 4 bytes")
	}

	if binary.BigEndian.Uint32(data[0:4]) != OBFUSCATE_MAGIC_VALUE {
		return nil, errors.New("Deobfuscate: magic value mismatch")
	}

	data = data[4:]
	if len(data) < 4 {
		return nil, errors.New("Deobfuscate: padding length value is less than 4 bytes")
	}

	plength := int(binary.BigEndian.Uint32(data[0:4]))

	data = data[4:]
	if len(data) < plength {
		return nil, errors.New("Deobfuscate: data length is less than padding length")
	}

	data = data[plength:]

	return data, nil
}

func (cr *Crypto) Encrypt(data []byte) ([]byte, error) {
	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ciphertext := box.Seal(nil, data, &cr.nonce, &cr.publicKey, ephemeralPrivateKey)
	output := make([]byte, 32+len(ciphertext))

	copy(output[0:32], ephemeralPublicKey[0:32])
	copy(output[32:], ciphertext)

	return output, nil
}

func (cr *Crypto) Decrypt(data []byte) ([]byte, error) {
	var ephemeralPublicKey [32]byte

	if len(data) < 32 {
		return nil, errors.New("Decrypt: data length < 32")
	}

	copy(ephemeralPublicKey[0:32], data[0:32])
	data = data[32:]

	open, ok := box.Open(nil, data, &cr.nonce, &ephemeralPublicKey, &cr.privateKey)
	if !ok {
		return nil, errors.New("NaCl couldn't decrypt client's payload")
	}
	return open, nil
}

func New(pubKey, privKey [32]byte) (cr *Crypto) {
	//nonce is filled with 0s: http://golang.org/ref/spec#The_zero_value
	//we do not need to generate a new nonce b/c a new ephemeral key is
	//generated for every message
	var n [24]byte

	return &Crypto{
		publicKey:          pubKey,
		privateKey:         privKey,
		nonce:              n,
	}
}
