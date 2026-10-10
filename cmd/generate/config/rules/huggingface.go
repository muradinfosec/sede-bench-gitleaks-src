package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Reference: https://huggingface.co/docs/hub/security-tokens
//
// Old tokens have the prefix `api_`, however, I am not sure it's worth detecting them as that would be high noise.
// https://huggingface.co/docs/api-inference/quicktour
func HuggingFaceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "huggingface-access-token",
		Description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
		Regex:       utils.GenerateUniqueTokenRegex("hf_(?i:[a-z]{34})", false),
		Entropy:     2,
		Keywords: []string{
			"hf_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("huggingface", "hf_"+secrets.NewSecret("[a-zA-Z]{34}"))
	tps = append(tps,














		`# Not critical, only usable on the sandboxed CI instance.


	)
	fps := []string{
		`- (id)hf_requiredCharacteristicTypesForDisplayMetadata;`,
		`amazon.de#@#div[data-cel-widget="desktop-rhf_SponsoredProductsRemoteRHFSearchEXPSubsK2ClickPagination"]`,
		`                            _kHMSymptomhf_generatedByHomeAppForDebuggingPurposesKey,`,
		`    #define OSCHF_DebugGetExpectedAverageCrystalAmplitude NOROM_OSCHF_DebugGetExpectedAverageCrystalAmplitude`,
		`  M_UINT       (ServingCellPriorityParametersDescription_t,  H_PRIO,  2, &hf_servingcellpriorityparametersdescription_h_prio),`,
		`+HWI-ST565_0092:4:1101:5508:5860#ACTTGA/1
		bb_eeeeegfgffhiiiiiiiiiiihiiiiicgafhf_eefghihhiiiifhifhhdhifhiiiihifdgdhggf\bbceceedbcd
		@HWI-ST565_0092:4:1101:7621:5770#ACTTGA/1`,
		`y{}x|~|}{~}}~|~}||�~|�{��|{}{|~z{}{{|{||{|}|{}{~|y}vjoePbUBJ7&;";  <; :;?!!;<7%$IACa_ecghbfbaebejhahfbhf_ddbficghbgfbhhcghdghfhigiifhhehhdggcgfchf_fgcei^[[.40&54"5666 6`,
		`                    change_dir(cwd)
		subdirs = glob.glob('HF_CAASIMULIAComputeServicesBuildTime.HF*.Linux64')
		if len(subdirs) == 1:`,
		`        os.environ.get("HF_AUTH_TOKEN",
		"hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),`,
		`# HuggingFace API Token https://huggingface.co/settings/tokens
		HUGGINGFACE_API_TOKEN=hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,`,
	}
	return utils.Validate(r, tps, fps)
}

// Will be deprecated Aug 1st, 2023.
func HuggingFaceOrganizationApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "huggingface-organization-api-token",
		Description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
		Regex:       utils.GenerateUniqueTokenRegex("api_org_(?i:[a-z]{34})", false),

		Entropy: 2,
		Keywords: []string{
			"api_org_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("huggingface", "api_org_"+secrets.NewSecret("[a-zA-Z]{34}"))
	tps = append(tps,







		`def test_private_space(self):

        io = gr.load(`,



		fmt.Sprintf("api_org_%s", secrets.NewSecret(`[a-zA-Z]{34}`)),
	)
	fps := []string{
		`public static final String API_ORG_EXIST = "APIOrganizationExist";`,
		`const api_org_controller = require('../../controllers/api/index').organizations;`,
		`API_ORG_CREATE("https://qyapi.weixin.qq.com/cgi-bin/department/create?access_token=ACCESS_TOKEN"),`,
		`def test_internal_api_org_inclusion_with_href(api_name, href, expected, monkeypatch, called_with):
		monkeypatch.setattr("requests.sessions.Session.request", called_with)`,
		`    def _api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a(self, method, url, body, headers):
        body = self.fixtures.load("api_org_96726c78_4ae3_402f_b08b_7a78c6903d2a.xml")
        return httplib.OK, body, headers, httplib.responses[httplib.OK]`,

		`  From Hugging Face docs:

		If you do not submit your API token when sending requests to the API, you will not be able to run inference on your private models.`,
	}
	return utils.Validate(r, tps, fps)
}
