package msgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/jonboulle/clockwork"

	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/trace"
)

const baseURL = "https://graph.microsoft.com/v1.0"
const defaultPageSize = 500

type UnsupportedGroupMember struct {
	Type string
}

func (u *UnsupportedGroupMember) Error() string {
	return fmt.Sprintf("Unsupported group member: %q", u.Type)
}

var scopes = []string{"https://graph.microsoft.com/.default"}

type azureTokenProvider interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

type Config struct {
	TokenProvider azureTokenProvider
	HTTPClient    *http.Client
	Clock         clockwork.Clock
	RetryConfig   *retryutils.RetryV2Config
	PageSize      int
}

func (cfg *Config) SetDefaults() {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.RetryConfig == nil {
		cfg.RetryConfig = &retryutils.RetryV2Config{
			First:  1 * time.Second,
			Driver: retryutils.NewExponentialDriver(1 * time.Second),
			Max:    defaults.HighResPollingPeriod,
		}
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
}

func (cfg *Config) Validate() error {
	if cfg.TokenProvider == nil {
		return trace.BadParameter("TokenProvider must be set")
	}
	return nil
}

type client struct {
	httpClient    *http.Client
	tokenProvider azureTokenProvider
	clock         clockwork.Clock
	retryConfig   retryutils.RetryV2Config
	baseURL       *url.URL
	pageSize      int
}

func NewClient(cfg Config) (Client, error) {
	cfg.SetDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, trace.Wrap(err)
	}
	uri, err := url.Parse(baseURL)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &client{
		httpClient:    cfg.HTTPClient,
		tokenProvider: cfg.TokenProvider,
		clock:         cfg.Clock,
		retryConfig:   *cfg.RetryConfig,
		baseURL:       uri,
		pageSize:      cfg.PageSize,
	}, nil
}

func (c *client) request(ctx context.Context, method string, uri string, payload []byte) (*http.Response, error) {
	var body io.ReadSeeker = nil
	if payload != nil {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, uri, body)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	token, err := c.tokenProvider.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: scopes,
	})
	if err != nil {
		return nil, trace.Wrap(err, "failed to get azure authentication token")
	}
	req.Header.Add("Authorization", "Bearer "+token.Token)

	const maxRetries = 5
	var retryAfter time.Duration

	// RetryV2 only used when the API does not return a Retry-After header.
	retry, err := retryutils.NewRetryV2(c.retryConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i != 0 {
			c.clock.Sleep(retryAfter)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, trace.Wrap(err) // hard I/O error, bail
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return resp, nil
		}

		graphError, err := readError(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err // error while reading the graph error, relay
		} else if graphError != nil {
			lastErr = trace.Wrap(graphError)
		} else {
			// API did not return a valid error structure, best-effort reporting.
			lastErr = trace.Errorf(resp.Status)
		}
		if !isRetriable(resp.StatusCode) {
			break
		}

		retryAfter = retry.Duration()
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil {
				retryAfter = time.Duration(seconds) * time.Second
			}
		}
		retry.Inc()

		// prepare for the next request attempt by rewinding the body
		if body != nil {
			_, err := body.Seek(0, io.SeekStart)
			if err != nil {
				return nil, trace.Wrap(err)
			}
		}
	}
	return nil, trace.Wrap(lastErr, "%s %s", req.Method, req.URL.Path)
}

func (c *client) endpointURI(segments ...string) string {
	uri := *c.baseURL
	uri.Path = path.Join(append([]string{uri.Path}, segments...)...)
	return uri.String()
}

// roundtrip makes a request to the API,
// serializing `in` as a JSON body, and deserializing the response as the given type `T`.
func roundtrip[T any](ctx context.Context, c *client, method string, uri string, in any) (T, error) {
	var zero T
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return zero, trace.Wrap(err)
		}
	}
	resp, err := c.request(ctx, method, uri, body)
	if err != nil {
		return zero, trace.Wrap(err)
	}
	defer resp.Body.Close()

	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return zero, trace.Wrap(err)
	}
	return out, nil
}

// CreateFederatedIdentityCredential implements Client.
func (c *client) CreateFederatedIdentityCredential(ctx context.Context, appObjectID string, cred *FederatedIdentityCredential) (*FederatedIdentityCredential, error) {
	uri := c.endpointURI("applications", appObjectID, "federatedIdentityCredentials")
	out, err := roundtrip[*FederatedIdentityCredential](ctx, c, http.MethodPost, uri, cred)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return out, nil
}

// CreateServicePrincipalTokenSigningCertificate implements Client.
func (c *client) CreateServicePrincipalTokenSigningCertificate(ctx context.Context, spID string, displayName string) (*SelfSignedCertificate, error) {
	uri := c.endpointURI("servicePrincipals", spID, "addTokenSigningCertificate")
	object := map[string]string{"displayName": displayName}
	out, err := roundtrip[*SelfSignedCertificate](ctx, c, http.MethodPost, uri, object)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return out, nil
}

// GetServicePrincipalsByAppId implements Client.
func (c *client) GetServicePrincipalByAppId(ctx context.Context, appID string) (*ServicePrincipal, error) {
	uri := c.endpointURI(fmt.Sprintf("servicePrincipals(appId='%s')", appID))
	out, err := roundtrip[*ServicePrincipal](ctx, c, http.MethodGet, uri, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return out, nil
}

// GetServicePrincipalsByDisplayName implements Client.
func (c *client) GetServicePrincipalsByDisplayName(ctx context.Context, displayName string) ([]*ServicePrincipal, error) {
	panic("unimplemented")
}

// InstantiateApplicationTemplate implements Client.
func (c *client) InstantiateApplicationTemplate(ctx context.Context, appTemplateID string, displayName string) (*ApplicationServicePrincipal, error) {
	panic("unimplemented")
}

// UpdateApplication implements Client.
func (c *client) UpdateApplication(ctx context.Context, appObjectID string, app *Application) error {
	panic("unimplemented")
}

// UpdateServicePrincipal implements Client.
func (c *client) UpdateServicePrincipal(ctx context.Context, spID string, sp *ServicePrincipal) error {
	panic("unimplemented")
}

func isRetriable(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}
