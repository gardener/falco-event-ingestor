// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Auth struct {
	publicKey          *rsa.PublicKey
	primaryPublicKey   *rsa.PublicKey
	secondaryPublicKey *rsa.PublicKey
}

type tokenVerificationKeys struct {
	Key1 tokenVerificationKey `yaml:"key_1"`
	Key2 tokenVerificationKey `yaml:"key_2"`
}

type tokenVerificationKey struct {
	PublicKey string    `yaml:"publicKey"`
	CreatedAt time.Time `yaml:"created"`
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Custom map[string]string `json:"gardener-falco"`
}

type TokenValues struct {
	ClusterId string
}

func NewAuth() *Auth {
	return &Auth{}
}

func (a *Auth) ExtractToken(r *http.Request) (*string, error) {
	tokenHeader, ok := r.Header["Authorization"]
	if !ok {
		return nil, errors.New("token required")
	}
	splitToken := strings.Split(tokenHeader[0], "Bearer ")
	if len(splitToken) != 2 {
		return nil, errors.New("invalid token")
	}
	return &splitToken[1], nil
}

func (a *Auth) ReadKeysFile(keysFile string) error {
	fileContents, err := os.ReadFile(keysFile)
	if err != nil {
		return err
	}

	var tokenVerificationKeys tokenVerificationKeys
	if err := yaml.Unmarshal(fileContents, &tokenVerificationKeys); err != nil {
		return err
	}

	block1, _ := pem.Decode([]byte(tokenVerificationKeys.Key1.PublicKey))
	pubKey1, err := x509.ParsePKIXPublicKey(block1.Bytes)
	if err != nil {
		return err
	}

	block2, _ := pem.Decode([]byte(tokenVerificationKeys.Key2.PublicKey))
	pubKey2, err := x509.ParsePKIXPublicKey(block2.Bytes)
	if err != nil {
		return err
	}

	if tokenVerificationKeys.Key1.CreatedAt.After(tokenVerificationKeys.Key2.CreatedAt) {
		a.primaryPublicKey = pubKey1.(*rsa.PublicKey)
		a.secondaryPublicKey = pubKey2.(*rsa.PublicKey)
	} else {
		a.primaryPublicKey = pubKey2.(*rsa.PublicKey)
		a.secondaryPublicKey = pubKey1.(*rsa.PublicKey)
	}

	return nil
}

func (a *Auth) LoadKey(keyFile string) error {
	publicKeyFile, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(publicKeyFile)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the public key")
	}

	if block.Type != "PUBLIC KEY" {
		return fmt.Errorf("public key is of the wrong type, Pem Type :%s", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	a.publicKey = key.(*rsa.PublicKey)
	log.Info("Public key " + keyFile + " loaded")
	return nil
}

func (a *Auth) VerifyToken(tokenString string) (*TokenValues, error) {
	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims,
		func(token *jwt.Token) (interface{}, error) {
			return []jwt.VerificationKey{a.primaryPublicKey, a.secondaryPublicKey}, nil
		},
		jwt.WithAudience("falco-db"),
		jwt.WithIssuer("urn:gardener:gardener-falco-extension"),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
	)
	if err != nil {
		log.Errorf("Token parsing failed with %s", err)
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	clusterId, ok := claims.Custom["cluster-identity"]
	if !ok {
		return nil, errors.New("token has no cluster claim")
	}

	return &TokenValues{
		ClusterId: clusterId,
	}, nil
}
