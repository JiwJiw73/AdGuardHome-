// Package safesearch implements safesearch host matching.
package safesearch

import (
	"fmt"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

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
