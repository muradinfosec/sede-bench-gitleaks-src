package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MaxMindLicenseKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "maxmind-license-key",
		Description: "Discovered a potential MaxMind license key.",
		Regex:       utils.GenerateUniqueTokenRegex(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`, false),
		Entropy:     4,
		Keywords:    []string{"_mmk"},
	}

	// validate

	return utils.Validate(r, tps, nil)
}
