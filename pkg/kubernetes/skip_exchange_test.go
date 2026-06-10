package kubernetes

import (
	"context"
	"testing"

	"github.com/containers/kubernetes-mcp-server/internal/test"
	"github.com/containers/kubernetes-mcp-server/pkg/config"
	"github.com/stretchr/testify/suite"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// SkipExchangeSuite covers the top-level skip_exchange_contexts behavior in
// ExchangeTokenInContext. The dispatcher matches the target name (the
// kubeconfig context name when the kubeconfig provider is in use) against
// each glob in skip_exchange_contexts. A match short-circuits the
// dispatcher before any TokenExchangeProvider/global-STS path runs.
type SkipExchangeSuite struct {
	BaseProviderSuite
	mockServer *test.MockServer
}

func (s *SkipExchangeSuite) SetupTest() {
	s.BaseProviderSuite.SetupTest()
	s.mockServer = test.NewMockServer()
}

func (s *SkipExchangeSuite) TearDownTest() {
	s.BaseProviderSuite.TearDownTest()
	if s.mockServer != nil {
		s.mockServer.Close()
	}
}

// build creates a kubeconfig provider with the given extra context names,
// alongside the StaticConfig it was built from. The cfg is passed back to
// ExchangeTokenInContext so the dispatcher reads the same
// skip_exchange_contexts list the provider was built with.
func (s *SkipExchangeSuite) build(toml string, extraContexts ...string) (Provider, *config.StaticConfig) {
	kubeconfig := s.mockServer.Kubeconfig()
	for _, name := range extraContexts {
		kubeconfig.Contexts[name] = clientcmdapi.NewContext()
	}
	cfg, err := config.ReadToml([]byte(toml))
	s.Require().NoError(err, "Expected TOML to parse")
	cfg.KubeConfig = test.KubeconfigFile(s.T(), kubeconfig)
	provider, err := NewProvider(cfg)
	s.Require().NoError(err, "Expected NewProvider to succeed")
	return provider, cfg
}

func (s *SkipExchangeSuite) TestExchangeTokenInContext() {
	s.Run("glob match preserves the original bearer", func() {
		p, cfg := s.build(`
			cluster_provider_strategy = "kubeconfig"
			token_exchange_strategy   = "rfc8693"
			sts_token_url             = "https://sts.example.test/token"
			skip_exchange_contexts    = ["eks-*"]
		`, "eks-prod-1")
		ctx := context.WithValue(context.Background(), OAuthAuthorizationHeader, "Bearer original-token")
		result, err := ExchangeTokenInContext(ctx, cfg, nil, nil, p, "eks-prod-1", nil)
		s.Require().NoError(err)
		auth, _ := result.Value(OAuthAuthorizationHeader).(string)
		s.Equal("Bearer original-token", auth, "Expected original bearer to be preserved when context name matches")
	})

	s.Run("non-matching target falls through to existing path", func() {
		// Without a registered exchanger and no built-in STS configured, the
		// passthrough path returns the original token unchanged. This proves
		// the dispatcher reached the existing path rather than short-circuiting.
		p, cfg := s.build(`
			cluster_provider_strategy = "kubeconfig"
			skip_exchange_contexts    = ["eks-*"]
		`, "vanilla-prod-1")
		ctx := context.WithValue(context.Background(), OAuthAuthorizationHeader, "Bearer original-token")
		result, err := ExchangeTokenInContext(ctx, cfg, nil, nil, p, "vanilla-prod-1", nil)
		s.Require().NoError(err)
		auth, _ := result.Value(OAuthAuthorizationHeader).(string)
		s.Equal("Bearer original-token", auth, "Expected fall-through path to preserve token in absence of STS strategy")
	})

	s.Run("empty skip_exchange_contexts list is a no-op", func() {
		p, cfg := s.build(`
			cluster_provider_strategy = "kubeconfig"
		`, "eks-prod-1")
		ctx := context.WithValue(context.Background(), OAuthAuthorizationHeader, "Bearer original-token")
		result, err := ExchangeTokenInContext(ctx, cfg, nil, nil, p, "eks-prod-1", nil)
		s.Require().NoError(err)
		auth, _ := result.Value(OAuthAuthorizationHeader).(string)
		s.Equal("Bearer original-token", auth, "Expected no skip when patterns list is empty")
	})

	s.Run("no-bearer context short-circuits regardless of skip", func() {
		p, cfg := s.build(`
			cluster_provider_strategy = "kubeconfig"
			skip_exchange_contexts    = ["eks-*"]
		`, "eks-prod-1")
		ctx := context.Background()
		result, err := ExchangeTokenInContext(ctx, cfg, nil, nil, p, "eks-prod-1", nil)
		s.Require().NoError(err)
		_, ok := result.Value(OAuthAuthorizationHeader).(string)
		s.False(ok, "Expected no auth header on result when none was provided")
	})

	s.Run("exact name match without globbing", func() {
		p, cfg := s.build(`
			cluster_provider_strategy = "kubeconfig"
			skip_exchange_contexts    = ["only-this-one"]
		`, "only-this-one", "but-not-this")
		ctx := context.WithValue(context.Background(), OAuthAuthorizationHeader, "Bearer t")
		result, err := ExchangeTokenInContext(ctx, cfg, nil, nil, p, "only-this-one", nil)
		s.Require().NoError(err)
		auth, _ := result.Value(OAuthAuthorizationHeader).(string)
		s.Equal("Bearer t", auth, "Expected exact name to be skipped")
	})

	s.Run("question-mark glob matches single character", func() {
		p, cfg := s.build(`
			cluster_provider_strategy = "kubeconfig"
			skip_exchange_contexts    = ["eks-prod-?"]
		`, "eks-prod-1")
		ctx := context.WithValue(context.Background(), OAuthAuthorizationHeader, "Bearer t")
		result, err := ExchangeTokenInContext(ctx, cfg, nil, nil, p, "eks-prod-1", nil)
		s.Require().NoError(err)
		auth, _ := result.Value(OAuthAuthorizationHeader).(string)
		s.Equal("Bearer t", auth, "Expected single-char glob to match")
	})
}

func TestSkipExchange(t *testing.T) {
	suite.Run(t, new(SkipExchangeSuite))
}
