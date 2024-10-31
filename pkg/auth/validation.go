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

func (a *Auth) VerifyToken(tokenString string) (*TokenValues, error) {
	wantedClaims := []jwt.ParserOption{
		jwt.WithAudience("falco-db"),
		jwt.WithIssuer("urn:gardener:gardener-falco-extension"),
		jwt.WithExpirationRequired(),
	}

	parser := jwt.NewParser(wantedClaims...)
	parts := strings.Split(tokenString, ".")
	signedString := strings.ReplaceAll(strings.Join(parts[0:2], "."), "\n", "")

	signature, err := parser.DecodeSegment(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := jwt.SigningMethodRS256.Verify(signedString, signature, a.primaryPublicKey); err != nil {
		log.Infof("Token verification failed with primary key %s", err)
		if err = jwt.SigningMethodRS256.Verify(signedString, signature, a.secondaryPublicKey); err != nil {
			log.Errorf("Token verification failed with secondary key %s", err)
			return nil, err
		}
	}

	claims := &CustomClaims{}
	if _, _, err := parser.ParseUnverified(tokenString, claims); err != nil {
		log.Errorf("Token parsing failed with %s", err)
		return nil, err
	}

	claimsValidator := jwt.NewValidator(wantedClaims...)
	if err := claimsValidator.Validate(claims); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	clusterId, ok := claims.Custom["cluster-identity"]
	if !ok {
		return nil, errors.New("token has no cluster identity claim")
	}

	return &TokenValues{
		ClusterId: clusterId,
	}, nil
}
