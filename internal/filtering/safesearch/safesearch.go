// Package safesearch implements safesearch host matching.
package safesearch

import (
	"fmt"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// Settings is a struct with safe search related settings.
type Settings struct {
	// Enabled indicates if safe search is enabled entirely.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Services flags.  Each flag indicates if the corresponding service is
	// enabled or disabled.

	Bing       bool `yaml:"bing" json:"bing"`
	DuckDuckGo bool `yaml:"duckduckgo" json:"duckduckgo"`
	Google     bool `yaml:"google" json:"google"`
	Pixabay    bool `yaml:"pixabay" json:"pixabay"`
	Yandex     bool `yaml:"yandex" json:"yandex"`
	Youtube    bool `yaml:"youtube" json:"youtube"`
}

// Matcher interface.
type Matcher interface {
	// MatchRequest returns matching safesearch rewrites rules for request.
	MatchRequest(dReq *urlfilter.DNSRequest) (rules []*rules.NetworkRule)
}

// DefaultMatcher is the default safesearch matcher.
type DefaultMatcher struct {
	// engine is the DNS filtering engine.
	engine *urlfilter.DNSEngine

	// ruleList is the filtering rule ruleList used by the engine.
	ruleList filterlist.RuleList
}

// NewDefaultMatcher returns new safesearch matcher.  listID is used as an
// identifier of the underlying rules list.
func NewDefaultMatcher(listID int, rulesText string) (m *DefaultMatcher, err error) {
	m = &DefaultMatcher{}

	err = m.resetRules(listID, rulesText)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// type check
var _ Matcher = (*DefaultMatcher)(nil)

// MatchRequest implements the [Matcher] interface for *DefaultMatcher.
func (m *DefaultMatcher) MatchRequest(dReq *urlfilter.DNSRequest) (rules []*rules.NetworkRule) {
	res, _ := m.engine.MatchRequest(dReq)

	return res.DNSRewrites()
}

// resetRules resets the filtering rules.
func (m *DefaultMatcher) resetRules(urlFilterID int, rulesText string) (err error) {
	strList := &filterlist.StringRuleList{
		ID:             urlFilterID,
		RulesText:      rulesText,
		IgnoreCosmetic: true,
	}

	rs, err := filterlist.NewRuleStorage([]filterlist.RuleList{strList})
	if err != nil {
		return fmt.Errorf("creating rule storage: %w", err)
	}

	m.ruleList = strList
	m.engine = urlfilter.NewDNSEngine(rs)

	log.Info("safesearch: filter %d: reset %d rules", urlFilterID, m.engine.RulesCount)

	return nil
}
