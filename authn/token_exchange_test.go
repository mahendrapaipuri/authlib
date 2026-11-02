package authn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPrivateKey = decodeTestPrivateKey([]byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEID6lXWsmcv/UWn9SptjOThsy88cifgGIBj2Lu0M9I8tQoAoGCCqGSM49
AwEHoUQDQgAEsf6eNnNMNhl+q7jXsbdUf3ADPh248uoFUSSV9oBzgptyokHCjJz6
n6PKDm2W7i3S2+dAs5M5f3s7d8KiLjGZdQ==
-----END EC PRIVATE KEY-----
`))

func decodeTestPrivateKey(data []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(data)
	if block == nil {
		panic("should include PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic("should be able to parse ec private key")
	}
	if privateKey.Curve.Params().Name != "P-256" {
		panic("should be P-256 curve")
	}
	return privateKey
}

func TestNewTokenExchangeClient(t *testing.T) {
	t.Run("should not be able to create client wihtout token", func(t *testing.T) {
		_, err := NewTokenExchangeClient(TokenExchangeConfig{
			TokenExchangeURL: "some-url",
		})
		require.Error(t, err)

	})

	t.Run("should not be able to create client wihtout url", func(t *testing.T) {
		_, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token: "some-token",
		})
		require.Error(t, err)
	})

	t.Run("should be able to create client", func(t *testing.T) {
		_, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: "some-url",
		})
		require.NoError(t, err)
	})
}

func Test_TokenExchangeClient_Exchange(t *testing.T) {
	setup := func(srv *httptest.Server) *TokenExchangeClient {
		c, err := NewTokenExchangeClient(TokenExchangeConfig{
			Token:            "some-token",
			TokenExchangeURL: srv.URL,
		})
		require.NoError(t, err)
		return c
	}

	t.Run("should return error if namespace is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{})
		assert.ErrorIs(t, err, ErrMissingNamespace)
		assert.Nil(t, res)

	})

	t.Run("should return error if audiences is empty", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})))
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*"})
		assert.ErrorIs(t, err, ErrMissingAudiences)
		assert.Nil(t, res)
	})

	t.Run("should return error for unexpected server response", func(t *testing.T) {
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("{}"))
		})))
		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.ErrorIs(t, err, ErrInvalidExchangeResponse)
		assert.Nil(t, res)
	})

	t.Run("should cache and return token on successful request", func(t *testing.T) {
		var calls int
		c := setup(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			require.Equal(t, r.Header.Get("Authorization"), "Bearer some-token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data": {"token": "` + signAccessToken(t) + `"}}`))
			bytes.NewBuffer([]byte(`{}`))
			json.NewEncoder(&bytes.Buffer{})
		})))

		res, err := c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// same namespace and audiences should load token from cache
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 1, calls)

		// different namespace should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "stack-1", Audiences: []string{"some-service"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 2, calls)

		// different different audiences should issue new token request
		res, err = c.Exchange(context.Background(), TokenExchangeRequest{Namespace: "*", Audiences: []string{"some-service-2"}})
		assert.NoError(t, err)
		assert.NotNil(t, res)
		require.Equal(t, 3, calls)
	})
}

func signAccessToken(t *testing.T) string {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       testPrivateKey,
	}, nil)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).
		Claims(&jwt.Claims{Expiry: jwt.NewNumericDate(time.Now().Add(10 * time.Minute))}).
		Serialize()

	require.NoError(t, err)
	return token
}
