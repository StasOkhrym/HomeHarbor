package httpapi

import "github.com/StasOkhrym/homeharbor/internal/web/assets"

var (
	adminCSS       = assets.Static("admin.css")
	adminScript    = assets.Static("admin.js")
	activityScript = assets.Static("activity.js")
	htmxScript     = assets.Static("htmx-2.0.11.min.js")
)
