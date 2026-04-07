package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// --- Parsing ---

type ParsedSDJWTVC struct {
	IssuerJWT   string
	Disclosures []string
	KBJWT       string
	Header      map[string]any
	Payload     map[string]any
}

func parseSDJWTVC(serialized string) (*ParsedSDJWTVC, error) {
	trimmed := strings.TrimSuffix(serialized, "~")
	parts := strings.Split(trimmed, "~")
	if len(parts) < 1 || parts[0] == "" {
		return nil, errors.New("empty SD-JWT-VC")
	}

	issuerJWT := parts[0]
	disclosures := parts[1:]

	var kbJWT string
	if len(disclosures) > 0 {
		last := disclosures[len(disclosures)-1]
		if strings.Count(last, ".") == 2 {
			kbJWT = last
			disclosures = disclosures[:len(disclosures)-1]
		}
	}

	jwtParts := strings.Split(issuerJWT, ".")
	if len(jwtParts) != 3 {
		return nil, errors.New("invalid issuer JWT format")
	}

	headerBytes, err := base64URLDecode(jwtParts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}

	payloadBytes, err := base64URLDecode(jwtParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	return &ParsedSDJWTVC{
		IssuerJWT:   issuerJWT,
		Disclosures: disclosures,
		KBJWT:       kbJWT,
		Header:      header,
		Payload:     payload,
	}, nil
}

// --- Verification ---

type VerifiedPresentation struct {
	Issuer          string
	Subject         string
	VCT             string
	DisclosedClaims map[string]any
	HolderJWK       map[string]any
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

func verifySDJWTVCPresentation(presentation, expectedAud, expectedNonce string) (*VerifiedPresentation, error) {
	parsed, err := parseSDJWTVC(presentation)
	if err != nil {
		return nil, err
	}

	// Verify issuer JWT signature — resolve issuer's JWKS
	iss := stringClaim(parsed.Payload, "iss")
	if iss == "" {
		return nil, errors.New("missing iss claim")
	}
	if err := verifyIssuerSignature(parsed.IssuerJWT, parsed.Header, iss); err != nil {
		return nil, fmt.Errorf("issuer signature invalid: %w", err)
	}

	if typ, _ := parsed.Header["typ"].(string); typ != "dc+sd-jwt" {
		return nil, fmt.Errorf("unexpected typ: %s", typ)
	}

	now := time.Now().Unix()
	if exp, ok := parsed.Payload["exp"].(float64); ok && now > int64(exp) {
		return nil, errors.New("credential has expired")
	}

	sdArray, _ := parsed.Payload["_sd"].([]any)
	sdSet := make(map[string]bool)
	for _, h := range sdArray {
		if s, ok := h.(string); ok {
			sdSet[s] = true
		}
	}

	disclosedClaims := make(map[string]any)
	for _, d := range parsed.Disclosures {
		if d == "" {
			continue
		}
		hash := hashDisclosure(d)
		if !sdSet[hash] {
			return nil, errors.New("disclosure hash mismatch")
		}
		dBytes, err := base64URLDecode(d)
		if err != nil {
			return nil, fmt.Errorf("invalid disclosure encoding: %w", err)
		}
		var arr []any
		if err := json.Unmarshal(dBytes, &arr); err != nil || len(arr) != 3 {
			return nil, errors.New("invalid disclosure format")
		}
		name, _ := arr[1].(string)
		disclosedClaims[name] = arr[2]
	}

	cnf, _ := parsed.Payload["cnf"].(map[string]any)
	holderJWK, _ := cnf["jwk"].(map[string]any)

	if parsed.KBJWT != "" {
		sdHashInput := parsed.IssuerJWT + "~"
		for _, d := range parsed.Disclosures {
			sdHashInput += d + "~"
		}
		sdHash := computeSDHash(sdHashInput)
		holderJWKStr := make(map[string]string)
		for k, v := range holderJWK {
			if s, ok := v.(string); ok {
				holderJWKStr[k] = s
			}
		}
		if err := verifyKeyBindingJWT(parsed.KBJWT, holderJWKStr, expectedAud, expectedNonce, sdHash); err != nil {
			return nil, fmt.Errorf("key binding JWT invalid: %w", err)
		}
	} else if expectedNonce != "" {
		return nil, errors.New("key binding JWT required")
	}

	iat := time.Unix(0, 0)
	if v, ok := parsed.Payload["iat"].(float64); ok {
		iat = time.Unix(int64(v), 0)
	}
	exp := time.Unix(0, 0)
	if v, ok := parsed.Payload["exp"].(float64); ok {
		exp = time.Unix(int64(v), 0)
	}

	return &VerifiedPresentation{
		Issuer:          iss,
		Subject:         stringClaim(parsed.Payload, "sub"),
		VCT:             stringClaim(parsed.Payload, "vct"),
		DisclosedClaims: disclosedClaims,
		HolderJWK:       holderJWK,
		IssuedAt:        iat,
		ExpiresAt:       exp,
	}, nil
}

// --- Key Binding JWT ---

func computeSDHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func hashDisclosure(disclosure string) string {
	hash := sha256.Sum256([]byte(disclosure))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func verifyKeyBindingJWT(kbJWT string, cnfJWK map[string]string, expectedAud, expectedNonce, expectedSDHash string) error {
	parts := strings.Split(kbJWT, ".")
	if len(parts) != 3 {
		return errors.New("invalid KB-JWT format")
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return fmt.Errorf("invalid KB-JWT header encoding: %w", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("invalid KB-JWT header JSON: %w", err)
	}
	if header["typ"] != "kb+jwt" {
		return fmt.Errorf("expected typ kb+jwt, got %s", header["typ"])
	}

	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("invalid KB-JWT payload encoding: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("invalid KB-JWT payload JSON: %w", err)
	}

	if aud, _ := payload["aud"].(string); aud != expectedAud {
		return fmt.Errorf("audience mismatch: expected %s, got %s", expectedAud, aud)
	}
	if nonce, _ := payload["nonce"].(string); nonce != expectedNonce {
		return errors.New("nonce mismatch")
	}
	if sdHash, _ := payload["sd_hash"].(string); sdHash != expectedSDHash {
		return errors.New("sd_hash mismatch")
	}

	now := time.Now().Unix()
	if iat, ok := payload["iat"].(float64); ok {
		if int64(iat) > now+60 {
			return errors.New("KB-JWT issued in the future")
		}
		if now-int64(iat) > 300 {
			return errors.New("KB-JWT is too old")
		}
	} else {
		return errors.New("KB-JWT missing iat")
	}

	pubKey, err := jwkToPublicKey(cnfJWK)
	if err != nil {
		return fmt.Errorf("invalid holder key: %w", err)
	}

	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("invalid KB-JWT signature encoding: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyES256(pubKey, []byte(signingInput), sigBytes) {
		return errors.New("KB-JWT signature invalid")
	}

	return nil
}

// --- Issuer Signature Resolution ---

func verifyIssuerSignature(jwt string, header map[string]any, iss string) error {
	kid, _ := header["kid"].(string)
	pubKey, err := resolveExternalKey(iss, kid)
	if err != nil {
		return fmt.Errorf("cannot resolve issuer key for %s: %w", iss, err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return errors.New("invalid JWT")
	}

	sigBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !verifyES256(pubKey, []byte(signingInput), sigBytes) {
		return errors.New("signature verification failed")
	}
	return nil
}

func resolveExternalKey(iss, kid string) (*ecdsa.PublicKey, error) {
	var jwksURL string
	if strings.HasPrefix(iss, "did:web:") {
		host := strings.TrimPrefix(iss, "did:web:")
		host = strings.ReplaceAll(host, "%3A", ":")
		scheme := "https"
		if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
			scheme = "http"
		}
		jwksURL = scheme + "://" + host + "/.well-known/jwks.json"
	} else if strings.HasPrefix(iss, "http") {
		jwksURL = iss + "/.well-known/jwks.json"
	} else {
		return nil, fmt.Errorf("unsupported issuer scheme: %s", iss)
	}

	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d for %s", resp.StatusCode, jwksURL)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("invalid JWKS response from %s: %w", jwksURL, err)
	}

	for _, k := range jwks.Keys {
		if kid != "" && k.Kid != kid {
			continue
		}
		if k.Kty == "EC" && k.Crv == "P-256" {
			return jwkToPublicKey(map[string]string{"kty": k.Kty, "crv": k.Crv, "x": k.X, "y": k.Y})
		}
	}
	return nil, fmt.Errorf("no matching EC P-256 key found (kid=%s) at %s", kid, jwksURL)
}

// --- Crypto Helpers ---

func verifyES256(pub *ecdsa.PublicKey, message, signature []byte) bool {
	hash := sha256.Sum256(message)
	r, s, err := parseASN1Signature(signature)
	if err != nil {
		if len(signature) == 64 {
			r = new(big.Int).SetBytes(signature[:32])
			s = new(big.Int).SetBytes(signature[32:])
		} else {
			return false
		}
	}
	return ecdsa.Verify(pub, hash[:], r, s)
}

func parseASN1Signature(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) < 8 || sig[0] != 0x30 {
		return nil, nil, errors.New("not ASN.1 DER sequence")
	}
	pos := 2
	if sig[1] > 0x80 {
		pos = 2 + int(sig[1]&0x7F)
	}
	if pos >= len(sig) || sig[pos] != 0x02 {
		return nil, nil, errors.New("invalid ASN.1 DER: expected integer tag for R")
	}
	pos++
	rLen := int(sig[pos])
	pos++
	if pos+rLen > len(sig) {
		return nil, nil, errors.New("invalid ASN.1 DER: R length exceeds data")
	}
	r := new(big.Int).SetBytes(sig[pos : pos+rLen])
	pos += rLen
	if pos >= len(sig) || sig[pos] != 0x02 {
		return nil, nil, errors.New("invalid ASN.1 DER: expected integer tag for S")
	}
	pos++
	sLen := int(sig[pos])
	pos++
	if pos+sLen > len(sig) {
		return nil, nil, errors.New("invalid ASN.1 DER: S length exceeds data")
	}
	s := new(big.Int).SetBytes(sig[pos : pos+sLen])
	return r, s, nil
}

func jwkToPublicKey(jwk map[string]string) (*ecdsa.PublicKey, error) {
	if jwk["kty"] != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk["kty"])
	}
	if jwk["x"] == "" || jwk["y"] == "" {
		return nil, errors.New("missing x or y coordinate in JWK")
	}
	xBytes, err := base64URLDecode(jwk["x"])
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}
	yBytes, err := base64URLDecode(jwk["y"])
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func base64URLDecode(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func stringClaim(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
