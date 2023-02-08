package safesearch

import (
	"testing"

	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefaultMatcher(t *testing.T) {
	m, err := NewDefaultMatcher(-1, safeSearchRules)
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestDefaultMatcher_MatchRequest(t *testing.T) {
	m, err := NewDefaultMatcher(-1, safeSearchRules)
	require.NoError(t, err)

	testCases := []struct {
		name string
		host string
		want string
		dtyp uint16
	}{{
		name: "not_filtered",
		host: "test-not-filtered.com",
		want: "",
		dtyp: dns.TypeA,
	}, {
		name: "yandex",
		host: "yandex.by",
		want: "|yandex.by^$dnsrewrite=NOERROR;A;213.180.193.56",
		dtyp: dns.TypeA,
	}, {
		name: "google",
		host: "www.google.com",
		want: "|www.google.com^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com",
		dtyp: dns.TypeA,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rws := m.MatchRequest(&urlfilter.DNSRequest{
				Hostname: tc.host,
				DNSType:  tc.dtyp,
			})

			if tc.want != "" {
				require.NotEmpty(t, rws)
				assert.Equal(t, tc.want, rws[0].RuleText)
			} else {
				assert.Empty(t, rws)
			}
		})
	}
}
