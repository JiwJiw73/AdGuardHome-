package filtering

import (
	"net/http"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
)

// handleSafeSearchEnable is the handler for POST /control/safesearch/enable
// HTTP API.
//
// Deprecated: Use handleSafeSearchSettings.
func (d *DNSFilter) handleSafeSearchEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(&d.confLock, &d.Config.SafeSearchEnabled, true)
	d.Config.ConfigModified()

	// TODO(d.kolyshev): !! Update SafeSearch.Enabled
}

// handleSafeSearchDisable is the handler for POST /control/safesearch/disable
// HTTP API.
//
// Deprecated: Use handleSafeSearchSettings.
func (d *DNSFilter) handleSafeSearchDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(&d.confLock, &d.Config.SafeSearchEnabled, false)
	d.Config.ConfigModified()

	// TODO(d.kolyshev): !! Update SafeSearch.Enabled
}

// handleSafeSearchStatus is the handler for GET /control/safesearch/status
// HTTP API.
//
// TODO(d.kolyshev): !! Add new fields
func (d *DNSFilter) handleSafeSearchStatus(w http.ResponseWriter, r *http.Request) {
	resp := &struct {
		Enabled bool `json:"enabled"`
	}{
		Enabled: protectedBool(&d.confLock, &d.Config.SafeSearchEnabled),
	}

	_ = aghhttp.WriteJSONResponse(w, r, resp)
}

// handleSafeSearchSettings is the handler for PUT /control/safesearch/settings
// HTTP API.
func (d *DNSFilter) handleSafeSearchSettings(w http.ResponseWriter, r *http.Request) {
	// TODO(d.kolyshev): !! Implement handleSafeSearchSettings

	aghhttp.Error(r, w, http.StatusBadRequest, "not implemented")
}
