package ecc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type Curve struct {
	A, B, P *big.Int
	Name    string
}

var P256 = Curve{
	A: big.NewInt(-3),
	B: func() *big.Int { v, _ := new(big.Int).SetString("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 0); return v }(),
	P: big.NewInt(0).Set(curveP256),
	Name: "P-256",
}

var curveP256_str = "1155973203298637310792003228331008213875303358409947825814574905994203294059037"
var curveP256, _ = new(big.Int).SetString(curveP256_str, 10)

var Gx_str = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
var Gy_str = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
var Gx, _ = new(big.Int).SetString(Gx_str, 16)
var Gy, _ = new(big.Int).SetString(Gy_str, 16)

var G = Point{X: Gx, Y: Gy}

type KeyPair struct {
	PrivateKey *big.Int
	PublicKey  Point
}

func GenerateKeyPair(curve *Curve) (*KeyPair, error) {
	d, err := rand.Int(rand.Reader, curve.P)
	if err != nil {
		return nil, err
	}

	Q := ScalarMultiply(d, &G, curve)

	return &KeyPair{
		PrivateKey: d,
		PublicKey:  *Q,
	}, nil
}

func ScalarMultiply(k *big.Int, P *Point, curve *Curve) *Point {
	if k.Sign() == 0 {
		return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	if P.X.Sign() == 0 && P.Y.Sign() == 0 {
		return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	R := &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	S := &Point{X: new(big.Int).Set(P.X), Y: new(big.Int).Set(P.Y)}
	N := new(big.Int).Set(k)

	for N.Sign() > 0 {
		if N.Bit(0) == 1 {
			R = PointAdd(R, S, curve)
		}
		S = PointDouble(S, curve)
		N.Rsh(N, 1)
	}

	return R
}

func PointAdd(P1, P2 *Point, curve *Curve) *Point {
	if P1.X.Sign() == 0 && P1.Y.Sign() == 0 {
		return &Point{X: new(big.Int).Set(P2.X), Y: new(big.Int).Set(P2.Y)}
	}
	if P2.X.Sign() == 0 && P2.Y.Sign() == 0 {
		return &Point{X: new(big.Int).Set(P1.X), Y: new(big.Int).Set(P1.Y)}
	}

	var lambda *big.Int

	if P1.X.Cmp(P2.X) == 0 {
		if P1.Y.Cmp(P2.Y) == 0 {
			doubled := PointDouble(P1, curve)
			if doubled == nil {
				return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
			}
			return doubled
		}
		return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	xDiff := new(big.Int).Sub(P2.X, P1.X)
	yDiff := new(big.Int).Sub(P2.Y, P1.Y)

	lambda = new(big.Int).Mod(yDiff, curve.P)
	invXDiff := modInverse(xDiff, curve.P)
	lambda.Mul(lambda, invXDiff)
	lambda.Mod(lambda, curve.P)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, P1.X)
	x3.Sub(x3, P2.X)
	x3.Mod(x3, curve.P)

	y3 := new(big.Int).Sub(P1.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, P1.Y)
	y3.Mod(y3, curve.P)

	return &Point{X: x3, Y: y3}
}

func PointDouble(P *Point, curve *Curve) *Point {
	if P.X.Sign() == 0 && P.Y.Sign() == 0 {
		return &Point{X: big.NewInt(0), Y: big.NewInt(0)}
	}

	threeX2 := new(big.Int).Lsh(P.X, 1)
	threeX2.Add(threeX2, P.X)
	threeX2.Mul(threeX2, P.X)
	threeX2.Mod(threeX2, curve.P)

	twoY := new(big.Int).Lsh(P.Y, 1)
	lambda := new(big.Int).Add(threeX2, curve.A)

	invTwoY := modInverse(twoY, curve.P)
	lambda.Mul(lambda, invTwoY)
	lambda.Mod(lambda, curve.P)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, P.X)
	x3.Sub(x3, P.X)
	x3.Mod(x3, curve.P)

	y3 := new(big.Int).Sub(P.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, P.Y)
	y3.Mod(y3, curve.P)

	return &Point{X: x3, Y: y3}
}

func modInverse(a, m *big.Int) *big.Int {
	a = new(big.Int).Mod(a, m)
	if a.Sign() < 0 {
		a.Add(a, m)
	}

	g, x, _ := extendedGCD(a, m)
	if g.Cmp(big.NewInt(1)) != 0 {
		return big.NewInt(0)
	}

	x.Mod(x, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}

	return x
}

func extendedGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if a.Sign() == 0 {
		return b, big.NewInt(0), big.NewInt(1)
	}
	if b.Sign() == 0 {
		return a, big.NewInt(1), big.NewInt(0)
	}

	g, x1, y1 := extendedGCD(b, new(big.Int).Mod(b, a))

	x := new(big.Int).Sub(y1, new(big.Int).Div(b, a))
	x.Mul(x, x1)

	y := new(big.Int).Sub(x1, x)
	y.Mul(y, a)
	y.Add(y, x1)

	return g, x, y
}

func ECDH(keyPair *KeyPair, theirPublicKey Point, curve *Curve) []byte {
	shared := ScalarMultiply(keyPair.PrivateKey, &theirPublicKey, curve)

	hash := sha256.Sum256(shared.X.Bytes())
	return hash[:]
}

func (kp *KeyPair) GetPublicKeyX() string {
	return kp.PublicKey.X.Text(16)
}

func (kp *KeyPair) GetPublicKeyY() string {
	return kp.PublicKey.Y.Text(16)
}

func (kp *KeyPair) GetPrivateKey() string {
	return kp.PrivateKey.Text(16)
}

type SmallCurve struct {
	A, B, P int64
	Gx, Gy int64
	N      int64
}

func PointAddSmall(p1, p2 PointSmall, curve SmallCurve) PointSmall {
	if p1.X == 0 && p1.Y == 0 {
		return p2
	}
	if p2.X == 0 && p2.Y == 0 {
		return p1
	}

	var result PointSmall

	if p1.X == p2.X {
		if p1.Y == p2.Y {
			lambda := ((3*p1.X*p1.X + curve.A) % curve.P) * modInverseSmall(2*p1.Y, curve.P) % curve.P
			result.X = (lambda*lambda - 2*p1.X) % curve.P
			result.Y = (lambda*(p1.X-result.X) - p1.Y) % curve.P
		} else {
			result = PointSmall{X: 0, Y: 0}
		}
	} else {
		lambda := ((p2.Y - p1.Y) % curve.P + curve.P) % curve.P
		lambda = lambda * modInverseSmall((p2.X-p1.X+curve.P)%curve.P, curve.P) % curve.P
		result.X = (lambda*lambda - p1.X - p2.X) % curve.P
		result.Y = (lambda*(p1.X-result.X) - p1.Y) % curve.P
	}

	result.X = (result.X + curve.P) % curve.P
	result.Y = (result.Y + curve.P) % curve.P

	return result
}

func ScalarMultiplySmall(k int64, P PointSmall, curve SmallCurve) PointSmall {
	result := PointSmall{X: 0, Y: 0}
	addend := P

	for k > 0 {
		if k&1 == 1 {
			result = PointAddSmall(result, addend, curve)
		}
		addend = PointAddSmall(addend, addend, curve)
		k >>= 1
	}

	return result
}

type PointSmall struct {
	X int64
	Y int64
}

func modInverseSmall(a, m int64) int64 {
	a = ((a % m) + m) % m
	for i := int64(1); i < m; i++ {
		if (a*i)%m == 1 {
			return i
		}
	}
	return 1
}

func EllipticCurveDemo() []string {
	curve := SmallCurve{A: 0, B: 7, P: 97, Gx: 3, Gy: 22}

	results := []string{}

	P := PointSmall{X: curve.Gx, Y: curve.Gy}
	results = append(results, fmt.Sprintf("Generator point G = (%d, %d)", P.X, P.Y))

	for i := 1; i <= 10; i++ {
		Q := ScalarMultiplySmall(int64(i), P, curve)
		results = append(results, fmt.Sprintf("%d*G = (%d, %d)", i, Q.X, Q.Y))
	}

	R1 := ScalarMultiplySmall(3, P, curve)
	R2 := ScalarMultiplySmall(5, P, curve)
	R3 := PointAddSmall(R1, R2, curve)
	results = append(results, fmt.Sprintf("3G + 5G = 8G = (%d, %d)", R3.X, R3.Y))

	R4 := ScalarMultiplySmall(8, P, curve)
	results = append(results, fmt.Sprintf("Verification: 8G = (%d, %d)", R4.X, R4.Y))

	return results
}

func (kp *KeyPair) ExportPublicKey() map[string]string {
	return map[string]string{
		"curve":  "P-256",
		"pub_x":  kp.GetPublicKeyX(),
		"pub_y":  kp.GetPublicKeyY(),
		"priv":   kp.GetPrivateKey(),
	}
}

func ImportPublicKey(xHex, yHex string) (Point, error) {
	x, ok := new(big.Int).SetString(xHex, 16)
	if !ok {
		return Point{}, fmt.Errorf("invalid x coordinate")
	}
	y, ok := new(big.Int).SetString(yHex, 16)
	if !ok {
		return Point{}, fmt.Errorf("invalid y coordinate")
	}
	return Point{X: x, Y: y}, nil
}

func (kp *KeyPair) DeriveAESKey() []byte {
	return ECDH(kp, kp.PublicKey, &P256)
}

type ECIESCipher struct {
	EPH   Point
	C1    []byte
	C2    []byte
}

func ECIESEncrypt(plaintext []byte, recipientPubKey *Point, curve *Curve) (ECIESCipher, error) {
	ephemeralPriv, err := rand.Int(rand.Reader, curve.P)
	if err != nil {
		return ECIESCipher{}, err
	}
	
	ephemeralPub := ScalarMultiply(ephemeralPriv, &G, curve)
	
	sharedKey := ECDH(&KeyPair{PrivateKey: ephemeralPriv, PublicKey: *recipientPubKey}, *recipientPubKey, curve)
	_ = ScalarMultiply(ephemeralPriv, recipientPubKey, curve)
	
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return ECIESCipher{}, err
	}
	
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	
	ciphertext := make([]byte, len(plaintext))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, plaintext)
	
	mac := hmacSHA256(sharedKey, append(iv, ciphertext...))
	
	return ECIESCipher{
		EPH:   *ephemeralPub,
		C1:    iv,
		C2:    append(ciphertext, mac...),
	}, nil
}

func ECIESDecrypt(ec ECIESCipher, recipientPriv *big.Int, curve *Curve) ([]byte, error) {
	sharedPoint := ScalarMultiply(recipientPriv, &ec.EPH, curve)
	
	sharedKey := make([]byte, 32)
	copy(sharedKey, sharedPoint.X.Bytes())
	
	macReceived := ec.C2[len(ec.C2)-32:]
	ciphertextOnly := ec.C2[:len(ec.C2)-32]
	
	macComputed := hmacSHA256(sharedKey, append(ec.C1, ciphertextOnly...))
	if !hmacEqual(macReceived, macComputed) {
		return nil, fmt.Errorf("HMAC verification failed")
	}
	
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	
	plaintext := make([]byte, len(ciphertextOnly))
	cbc := cipher.NewCBCDecrypter(block, ec.C1)
	cbc.CryptBlocks(plaintext, ciphertextOnly)
	
	return plaintext, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := sha256.New()
	h.Write(key)
	hmacKey := h.Sum(nil)
	
	h = sha256.New()
	h.Write(hmacKey)
	h.Write(data)
	return h.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := range a {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}