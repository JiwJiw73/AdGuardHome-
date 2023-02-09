package filtering

import (
	"encoding/json"
	"net/http"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/safesearch"
)

// handleSafeSearchEnable is the handler for POST /control/safesearch/enable
// HTTP API.
//
// Deprecated: Use handleSafeSearchSettings.
func (d *DNSFilter) handleSafeSearchEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(&d.confLock, &d.Config.SafeSearch.Enabled, true)
	d.Config.ConfigModified()
}

// handleSafeSearchDisable is the handler for POST /control/safesearch/disable
// HTTP API.
//
// Deprecated: Use handleSafeSearchSettings.
func (d *DNSFilter) handleSafeSearchDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(&d.confLock, &d.Config.SafeSearch.Enabled, false)
	d.Config.ConfigModified()
}

// handleSafeSearchStatus is the handler for GET /control/safesearch/status
// HTTP API.
func (d *DNSFilter) handleSafeSearchStatus(w http.ResponseWriter, r *http.Request) {
	d.confLock.RLock()
	resp := d.Config.SafeSearch
	d.confLock.RUnlock()

	_ = aghhttp.WriteJSONResponse(w, r, resp)
}

// handleSafeSearchSettings is the handler for PUT /control/safesearch/settings
// HTTP API.
func (d *DNSFilter) handleSafeSearchSettings(w http.ResponseWriter, r *http.Request) {
	req := &safesearch.Settings{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "reading req: %s", err)

		return
	}

	d.confLock.Lock()
	d.Config.SafeSearch = *req
	d.confLock.Unlock()

	d.Config.ConfigModified()

	aghhttp.OK(w)
}
