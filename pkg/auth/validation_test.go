// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v2"
)

var testKey *rsa.PrivateKey
var global_auth_obj *Auth
var audience = []string{"falco-db"}
var issuer = "urn:gardener:gardener-falco-extension"

func createCustomClaims(individual map[string]string, duration time.Duration, issuer string, subject string, id string, audience []string) *CustomClaims {
	now := time.Now()
	claims := CustomClaims{
		jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id,
		},
		individual,
	}
	return &claims
}

func createKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func createToken(key *rsa.PrivateKey, method jwt.SigningMethod, claims *CustomClaims) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func writePublicKeysFile(keys *tokenVerificationKeys, filename string) error {
	content, err := yaml.Marshal(*keys)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, content, 0644); err != nil {
		return err
	}

	return nil
}

func TestMain(t *testing.T) {
	wrongKey := createKey()
	wrongPublic := &wrongKey.PublicKey

	testKey = createKey()
	public := &testKey.PublicKey

	tokenVerificationKeysInstance := tokenVerificationKeys{
		Key1: tokenVerificationKey{
			PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(wrongPublic)})[:]),
			CreatedAt: time.Now(),
		},
		Key2: tokenVerificationKey{
			PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(public)})[:]),
			CreatedAt: time.Now().Add(-time.Hour),
		},
	}

	keyFilename := "test_keys.yaml"

	if err := writePublicKeysFile(&tokenVerificationKeysInstance, keyFilename); err != nil {
		t.Fatalf("Could not write test keys to file: %s", err)
	}

	defer func() {
		if err := os.Remove(keyFilename); err != nil {
			t.Fatalf("Could not remove key file: %s", err)
		}
	}()

	global_auth_obj = NewAuth()
	if err := global_auth_obj.ReadKeysFile(keyFilename); err != nil {
		t.Fatalf("Loading key failed: %s", err.Error())
	}
}

func TestVerifyValidToken(t *testing.T) {
	individualClaims := map[string]string{"cluster-identity": "1234567"}
	claims := createCustomClaims(individualClaims, time.Hour*24*7, issuer, "TestSubject", "0000", audience)
	token, err := createToken(testKey, jwt.SigningMethodRS256, claims)
	if err != nil {
		t.Fatalf("Could not create test jwt: %s", err)
	}

	if _, err := global_auth_obj.VerifyToken(token); err != nil {
		t.Fatalf("Token could not be verified: %s", err.Error())
	}
	t.Log("Valid token was accepted")
}

func TestVerifyInvalidClaimsToken(t *testing.T) {
	individualClaims := map[string]string{"cluster-identity": "1234567"}
	claims := createCustomClaims(individualClaims, time.Hour*24*7, issuer, "TestSubject", "0000", []string{"wrong-audience"})
	token, err := createToken(testKey, jwt.SigningMethodRS256, claims)
	if err != nil {
		t.Fatalf("Could not create test jwt: %s", err)
	}

	if _, err := global_auth_obj.VerifyToken(token); err == nil {
		t.Fatalf("Invalid claims in token were accepted: %s", err.Error())
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	individualClaims := map[string]string{"cluster-identity": "1234567"}
	claimsExpired := createCustomClaims(individualClaims, 0, issuer, "TestSubject", "0000", audience)
	token, err := createToken(testKey, jwt.SigningMethodRS256, claimsExpired)
	if err != nil {
		t.Fatalf("Could not create test jwt: %s", err)
	}

	if _, err := global_auth_obj.VerifyToken(token); err != nil {
		t.Logf("Invalid token was declined: %s", err)
	} else {
		t.Fatalf("Invalid token was accepted")
	}
}

func TestVerifyWrongSigningToken(t *testing.T) {
	individualClaims := map[string]string{"cluster-identity": "1234567"}
	claimsExpired := createCustomClaims(individualClaims, 0, issuer, "TestSubject", "0000", audience)
	token, err := createToken(testKey, jwt.SigningMethodRS384, claimsExpired)
	if err != nil {
		t.Fatalf("Could not create test jwt: %s", err)
	}

	if _, err := global_auth_obj.VerifyToken(token); err != nil {
		t.Logf("Invalid token was declined: %s", err)
	} else {
		t.Fatalf("Invalid token was accepted")
	}
}

func TestVerifyInvalidClusterIdToken(t *testing.T) {
	individualClaims := map[string]string{"empty": "1234567"}
	claims := createCustomClaims(individualClaims, time.Hour*24*7, issuer, "TestSubject", "0000", audience)
	token, err := createToken(testKey, jwt.SigningMethodRS256, claims)
	if err != nil {
		t.Fatalf("Could not create test jwt: %s", err)
	}

	if _, err := global_auth_obj.VerifyToken(token); err == nil {
		t.Fatalf("Invalid token w/o cluster id was accepted: %s", err.Error())
	}
}

func TestExtractToken(t *testing.T) {
	individualClaims := map[string]string{"cluster-identity": "1234567"}
	claims := createCustomClaims(individualClaims, time.Hour*24*7, issuer, "TestSubject", "0000", audience)
	token, err := createToken(testKey, jwt.SigningMethodRS256, claims)
	if err != nil {
		t.Fatalf("Could not create test jwt: %s", err)
	}

	r := &http.Request{Header: make(http.Header)}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resToken, err := global_auth_obj.ExtractToken(r)
	if err != nil {
		t.Fatalf("Could not extract token: %s", err)
	}
	if resToken == nil {
		t.Fatalf("Token was not extracted")
	}

	r.Header.Set("Authorization", fmt.Sprintf("BearerBroken %s", token))
	_, err = global_auth_obj.ExtractToken(r)
	if err == nil {
		t.Fatalf("Extracted broken token")
	}

	r.Header.Del("Authorization")
	_, err = global_auth_obj.ExtractToken(r)
	if err == nil {
		t.Fatalf("Extracted headerless request")
	}

}
