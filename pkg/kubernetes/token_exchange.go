package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
	"github.com/containers/kubernetes-mcp-server/pkg/tokenexchange"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

// shouldSkipExchange returns true when the target name matches any glob in
// skip_exchange_contexts. Evaluated before the TokenExchangeProvider and
// global-STS branches so the skip cannot interact with any STS fallback.
func shouldSkipExchange(baseConfig api.BaseConfig, target string) bool {
	patterns := baseConfig.GetSkipExchangeContexts()
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, target)
		if err != nil {
			klog.V(2).Infof("invalid skip_exchange_contexts glob %q: %v", pattern, err)
			continue
		}
		if matched {
			klog.V(5).Infof("target %q matched skip_exchange_contexts %q, skipping exchange", target, pattern)
			return true
		}
	}
	return false
}

// resolveStsTokenURL returns the explicit sts_token_url if configured;
// otherwise falls back to the OIDC provider's discovered token endpoint.
// The explicit URL decouples the STS gateway from the user-token issuer
// (authorization_url), which is required for cross-realm RFC 8693 deployments
// and enables token exchange when skip_jwt_verification=true (no OIDC provider).
func resolveStsTokenURL(stsConfig api.StsConfigProvider, oidcProvider *oidc.Provider) string {
	if explicit := stsConfig.GetStsTokenURL(); explicit != "" {
		return explicit
	}
	if oidcProvider != nil {
		return oidcProvider.Endpoint().TokenURL
	}
	return ""
}

// ExchangeTokenInContext exchanges the OAuth token in the context for a token
// that can access the target cluster. The optional stsConfig parameter allows
// callers to reuse a TargetTokenExchangeConfig across calls to benefit from
// assertion caching (pass nil to build a fresh config each time).
func ExchangeTokenInContext(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	provider Provider,
	target string,
	stsConfig *tokenexchange.TargetTokenExchangeConfig,
) (context.Context, error) {
	auth, ok := ctx.Value(OAuthAuthorizationHeader).(string)
	if !ok || !strings.HasPrefix(auth, "Bearer ") {
		return ctx, nil
	}
	subjectToken := strings.TrimPrefix(auth, "Bearer ")

	if shouldSkipExchange(baseConfig, target) {
		return ctx, nil
	}

	tep, ok := provider.(TokenExchangeProvider)
	if !ok {
		return stsExchangeTokenInContext(ctx, baseConfig, oidcProvider, httpClient, subjectToken, stsConfig)
	}

	exCfg := tep.GetTokenExchangeConfig(target)
	if exCfg == nil {
		return stsExchangeTokenInContext(ctx, baseConfig, oidcProvider, httpClient, subjectToken, stsConfig)
	}

	exchanger, ok := tokenexchange.GetTokenExchanger(tep.GetTokenExchangeStrategy())
	if !ok {
		klog.Warningf("token exchange strategy %q not found in registry", tep.GetTokenExchangeStrategy())
		return stsExchangeTokenInContext(ctx, baseConfig, oidcProvider, httpClient, subjectToken, stsConfig)
	}

	exchanged, err := exchanger.Exchange(ctx, exCfg, subjectToken)
	if err != nil {
		return ctx, fmt.Errorf("token exchange failed for target %q: %w", target, err)
	}
	return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchanged.AccessToken), nil
}

func stsExchangeTokenInContext(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
	stsConfig *tokenexchange.TargetTokenExchangeConfig,
) (context.Context, error) {
	switch baseConfig.ResolveClusterAuthMode() {
	case api.ClusterAuthKubeconfig:
		return context.WithValue(ctx, OAuthAuthorizationHeader, ""), nil

	case api.ClusterAuthPassthrough:
		exchangedToken, err := exchangePassthroughToken(ctx, baseConfig, oidcProvider, httpClient, token, stsConfig)
		if err != nil {
			return ctx, err
		}
		return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchangedToken), nil

	default:
		return ctx, fmt.Errorf("unknown cluster_auth_mode %q", baseConfig.ResolveClusterAuthMode())
	}
}

// exchangePassthroughToken exchanges the user token if a strategy or STS is configured,
// otherwise returns the original token unchanged.
func exchangePassthroughToken(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
	stsConfig *tokenexchange.TargetTokenExchangeConfig,
) (string, error) {
	if strategy := baseConfig.GetStsStrategy(); strategy != "" {
		return doTokenExchange(ctx, token, func(ctx context.Context) (context.Context, error) {
			return strategyBasedTokenExchange(ctx, baseConfig, oidcProvider, httpClient, token, strategy, stsConfig)
		})
	}

	sts := NewFromConfig(baseConfig, oidcProvider)
	if sts.IsEnabled() {
		return doTokenExchange(ctx, token, func(ctx context.Context) (context.Context, error) {
			if httpClient != nil {
				ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
			}
			exchangedToken, err := sts.ExternalAccountTokenExchange(ctx, &oauth2.Token{
				AccessToken: token,
				TokenType:   "Bearer",
			})
			if err != nil {
				return ctx, fmt.Errorf("built-in STS exchange: %w", err)
			}
			return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchangedToken.AccessToken), nil
		})
	}

	return token, nil
}

// doTokenExchange runs an exchange function and extracts the Bearer token from the resulting context.
// Falls back to the original token if the exchange doesn't produce one.
func doTokenExchange(
	ctx context.Context,
	token string,
	exchangeFn func(ctx context.Context) (context.Context, error),
) (string, error) {
	exchangedCtx, err := exchangeFn(ctx)
	if err != nil {
		return "", err
	}
	if auth, ok := exchangedCtx.Value(OAuthAuthorizationHeader).(string); ok && strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer "), nil
	}
	return token, nil
}

func strategyBasedTokenExchange(
	ctx context.Context,
	baseConfig api.BaseConfig,
	oidcProvider *oidc.Provider,
	httpClient *http.Client,
	token string,
	strategy string,
	cachedConfig *tokenexchange.TargetTokenExchangeConfig,
) (context.Context, error) {
	exchanger, ok := tokenexchange.GetTokenExchanger(strategy)
	if !ok {
		return ctx, fmt.Errorf("token exchange strategy %q not found", strategy)
	}

	cfg := cachedConfig
	if cfg == nil {
		tokenURL := resolveStsTokenURL(baseConfig, oidcProvider)
		if tokenURL == "" {
			return ctx, fmt.Errorf("token exchange failed: no token URL available (set sts_token_url or configure authorization_url for OIDC discovery)")
		}

		authStyle := baseConfig.GetStsAuthStyle()
		if authStyle == "" {
			authStyle = tokenexchange.AuthStyleParams
		}

		cfg = &tokenexchange.TargetTokenExchangeConfig{
			TokenURL:           tokenURL,
			ClientID:           baseConfig.GetStsClientId(),
			ClientSecret:       baseConfig.GetStsClientSecret(),
			Audience:           baseConfig.GetStsAudience(),
			Scopes:             baseConfig.GetStsScopes(),
			AuthStyle:          authStyle,
			ClientCertFile:     baseConfig.GetStsClientCertFile(),
			ClientKeyFile:      baseConfig.GetStsClientKeyFile(),
			FederatedTokenFile: baseConfig.GetStsFederatedTokenFile(),
			SubjectTokenType:   baseConfig.GetStsSubjectTokenType(),
			RequestedTokenType: baseConfig.GetStsRequestedTokenType(),
			CAFile:             baseConfig.GetCertificateAuthority(),
		}
		if err := cfg.Validate(); err != nil {
			return ctx, fmt.Errorf("token exchange config validation: %w", err)
		}
	}

	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	exchanged, err := exchanger.Exchange(ctx, cfg, token)
	if err != nil {
		return ctx, fmt.Errorf("token exchange with strategy %q: %w", strategy, err)
	}
	return context.WithValue(ctx, OAuthAuthorizationHeader, "Bearer "+exchanged.AccessToken), nil
}
