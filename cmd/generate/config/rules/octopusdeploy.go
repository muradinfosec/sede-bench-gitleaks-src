package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OctopusDeployApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "octopus-deploy-api-key",
		Description: "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
		Regex:       utils.GenerateUniqueTokenRegex(`API-[A-Z0-9]{26}`, false),
		Entropy:     3,
		Keywords:    []string{"api-"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("octopus", secrets.NewSecret(`API-[A-Z0-9]{26}`)),

	}
	fps := []string{
		// Invalid start
		`msgstr "GSSAPI-VIRHEKAPSELOINTIMERKKIJONO."`,
		`https://sonarcloud.io/api/project_badges/measure?project=Garden-Coin_API-CalculadoraDeInvestimentos&metric=alert_status`,

		`<iframe src="./archive/gifs/api-c99e353f761d318322c853c03e.gif"> </iframe>`, // Wrong case
	}
	return utils.Validate(r, tps, fps)
}
