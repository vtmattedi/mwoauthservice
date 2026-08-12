// MW_OAUTH_STEP_01
package buildinfo

import "runtime"

const ServiceName = "MW OAuth Service"

// Replaced through -ldflags in production builds.
var (
	Version    = "dev"
	Commit     = "unknown"
	BuiltAt    = "unknown"
	APICurrent = "v1"
)

type Info struct {
	Service     string   `json:"service"`
	Version     string   `json:"version"`
	Commit      string   `json:"commit"`
	BuiltAt     string   `json:"built_at"`
	GoVersion   string   `json:"go_version"`
	APICurrent  string   `json:"api_current"`
	APIAccepted []string `json:"api_accepted"`
}

func Current() Info {
	return Info{
		Service:     ServiceName,
		Version:     Version,
		Commit:      Commit,
		BuiltAt:     BuiltAt,
		GoVersion:   runtime.Version(),
		APICurrent:  APICurrent,
		APIAccepted: []string{"v1"},
	}
}
