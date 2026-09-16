# Token tier inventory

Scope: every distinct built-in family, including duplicate aliases. This is
an inventory of supported syntactic detectors, not a promise to recognize all
provider credentials or validate whether any token is live. Provider formats
can change; uncertain low-floor detectors stay gated rather than being promoted
solely because their current regex has a prefix. Existing Tier-1 legacy lengths
are compatibility heuristics, not authoritative provider specifications.

Tier-1 uses explicit token/envelope structure in UTF-8 files. Tier-2 retains
context-dependent or insufficiently distinctive patterns in protected paths.
Whole-file encryption remains the safest path for designated credential files.
The integration test checks that this table covers exactly the current family
names and that its tier decisions match the constructors. Duplicate pattern
names (Azure, Alibaba) and GCP/Google aliases are intentionally retained for
compatibility; this task does not silently drop detectors.

| Family | Tier | Decision / limitation |
|---|---|---|
| AWS Access Key ID | 1 | Keep established fixed prefix and 16-character ID; ID alone is not the signing secret. |
| GitHub Token (ghp) | 1 | Keep distinctive provider prefix; legacy length heuristic. |
| GitHub Token (gho) | 1 | Keep distinctive provider prefix; legacy length heuristic. |
| GitHub Token (ghu) | 1 | Keep distinctive provider prefix; legacy length heuristic. |
| GitHub Token (ghs) | 1 | Keep distinctive provider prefix; legacy length heuristic. |
| GitHub Token (ghr) | 1 | Keep distinctive provider prefix; legacy length heuristic. |
| GitLab Token | 1 | Keep provider prefix and body; custom server prefixes are not inferred. |
| GitLab Runner Token | 1 | Keep established runner prefix; newer formats require separate evidence. |
| Stripe Live Secret Key | 1 | Keep provider prefix and body. |
| Stripe Live Restricted Key | 1 | Keep provider prefix and body. |
| Stripe Test Secret Key | 1 | Keep: test credentials still grant access. |
| Stripe Test Restricted Key | 1 | Keep: test credentials still grant access. |
| Stripe Webhook Secret | 1 | Keep distinctive signing-secret prefix. |
| Slack Token | 1 | Keep established provider prefix and segments. |
| Slack Bot Token | 1 | Keep established segmented format. |
| Slack Bot Token (Compact) | 1 | Keep compatibility detector; compact length is heuristic. |
| Twilio API Key | 1 | Keep fixed prefix and hex body; key SID is an identifier, not its secret. |
| Twilio Account SID | 1 | Keep compatibility: account identifier is not itself authentication. |
| SendGrid API Key | 1 | Keep provider prefix and two fixed segments. |
| Mailchimp API Key | 1 | Keep fixed hex body plus data-centre suffix; suffix substitutes for prefix. |
| RSA Private Key | 1 | Keep matching labelled envelope. |
| DSA Private Key | 1 | Keep matching labelled envelope. |
| EC Private Key | 1 | Keep matching labelled envelope. |
| OpenSSH Private Key | 1 | Keep matching labelled envelope. |
| PGP Private Key | 1 | Keep private-key-block envelope. |
| SSH Private Key (generic) | 1 | Keep generic labelled envelope; not cryptographic validation. |
| NPM Access Token | 1 | Keep provider prefix plus fixed body. |
| OpenAI API Key | 1 | Tightened: exclude embedded slug matches and hyphenated prose; explicit project/service prefixes, alphanumeric legacy body. Lengths remain compatibility heuristics. |
| PKCS8 Private Key | 1 | Added unlabelled PRIVATE KEY envelope missed by labelled rule. |
| Encrypted PKCS8 Private Key | 1 | Added explicit encrypted envelope; encrypted keys remain sensitive assets. |
| GCP API Key | 1 | Moved: distinctive prefix and 35-character body, including terminal hyphen. |
| Google API Key | 1 | Moved with identical GCP alias; preserve reporting compatibility. |
| Google Client Secret | 1 | Moved: distinctive OAuth-secret prefix; exact casing, full token boundary. |
| DigitalOcean Token | 1 | Moved: versioned provider prefix plus 64 hex characters. |
| Shopify Token | 1 | Moved: provider prefix plus fixed hex body. |
| Shopify Secret | 1 | Moved: provider secret prefix plus fixed hex body. |
| Square Access Token | 1 | Moved legacy 22-character body; reject partial overlong matches. Other Square formats are not claimed. |
| Square OAuth Secret | 1 | Moved legacy 43-character body; token boundary allows terminal hyphen. |
| HashiCorp Vault Token | 1 | Moved explicit service-token prefix; other Vault formats not inferred. |
| AWS MWS Key | 1 | Moved provider prefix plus UUID-shaped body; bare UUID is not sufficient. |
| AWS Secret Access Key | 2 | Stays: generic base64 needs AWS context. |
| AWS Session Token | 2 | Stays: variable-name context, generic body. |
| GCP OAuth Access Token | 2 | Stays: current bounded heuristic may truncate variable-length OAuth tokens; do not broaden rollout without a supported length contract. |
| Azure Shared Access Signature | 2 | Stays: query syntax and parameter ordering, not rigid standalone token. |
| Azure Storage Account Key | 2 | Stays: generic base64, no provider prefix. |
| Alibaba Access Key ID | 2 | Stays: reviewed against the gitleaks alibaba-access-key-id rule and TruffleHog's `LTAI[a-zA-Z0-9]{17,21}` detector — both treat it as an identifier paired with a separate secret; the ID alone is not authentication, and the warden Tier-2 detector covers the same shape inside protected paths. |
| Google Client ID | 2 | Stays: public OAuth identifier rather than secret. |
| Google Service Account | 2 | Stays: metadata declaration, not private key span. |
| Firebase Database URL | 2 | Stays: public endpoint can be ordinary application configuration. |
| Firebase API Key | 2 | Stays: contextual heuristic; rigid Google key format covered separately. |
| Azure Storage Key | 2 | Stays: connection-string grammar, mixed metadata and credential. |
| Azure SAS Token | 2 | Stays: loose query-fragment heuristic. |
| Azure AD Client Secret | 2 | Stays: context-dependent matching. |
| Alibaba Secret Key | 2 | Stays: generic body plus keyword context. |
| IBM Cloud API Key | 2 | Stays: generic body plus keyword context. |
| Oracle Cloud API Key | 2 | Stays: OCID is a resource identifier, not authentication. |
| GitHub Client Secret | 2 | Stays: generic hex with contextual keywords. |
| Discord Client Secret | 2 | Stays: generic body with context. |
| Microsoft Client Secret | 2 | Stays: contextual secret heuristic. |
| GitHub App Token | 2 | Stays: contextual legacy heuristic, unlike explicit token prefixes. |
| Bitbucket Token | 2 | Stays: generic body with context. |

| Discord Token | 2 | Stays: weak leading character and broad segmented body, no fixed provider prefix. |
| Discord Webhook | 2 | Stays: current URL detector has no credential-length floor. |
| Telegram Bot Token | 2 | Stays: numeric prefix is not provider-specific; needs stronger context/format validation. |
| Mailgun API Key | 2 | Stays: generic key-prefix can match source slugs. |
| PostgreSQL URL | 2 | Stays: credential URL grammar includes ordinary example strings. |
| MySQL URL | 2 | Stays: credential URL grammar includes ordinary example strings. |
| MongoDB URL | 2 | Stays: credential URL grammar includes ordinary example strings. |
| Redis URL | 2 | Stays: credential URL grammar includes ordinary example strings. |
| Database Password | 2 | Stays: keyword-driven secret detection. |
| JWT Token | 2 | Stays: token may contain public or synthetic data; not provider-specific. |
| Bearer Token | 2 | Stays: generic header context. |
| Basic Auth Header | 2 | Stays: generic header context. |
| OAuth Token | 2 | Stays: keyword context. |
| Heroku API Key | 2 | Stays: UUID plus keyword, not distinctive token structure. |
| Vercel Token | 2 | Stays: generic body plus context. |
| Netlify Token | 2 | Stays: generic body plus context. |
| Cohere API Key | 2 | Stays: generic body plus context. |
| DigitalOcean Spaces Key | 2 | Stays: generic uppercase identifier plus context. |
| Linode Token | 2 | Stays: generic hex plus context. |
| PayPal Client ID | 2 | Stays: public identifier plus context. |
| HashiCorp Terraform Token | 2 | Stays: contextual multi-segment heuristic, not explicit provider prefix. |
| Age Secret Key | 2 | Stays: identity-bootstrap exclusions must be preserved; global promotion would bypass the identity-file special case. |
| NVIDIA API Key | 2 | Stays Tier-2 by format audit: the `nvapi-` prefix is provider-specific, but public docs/model cards (build.nvidia.com keys, provider quickstarts) do not publish a fixed body length — bodies vary in length and charset, and a 20-char floor is invented. The Tier-2 form stays protected-path-only until NVIDIA documents a rigid format. |
| OpenRouter API Key | 1 | Moved: `sk-or-v1-` plus exactly 64 lowercase hex characters; TruffleHog openrouter detector, corroborated by authenticated `/api/v1/auth/key` verifier. Full adjacent boundaries required. |
| MiniMax API Key | 2 | Stays Tier-2 with current Tier-2 body constraints unchanged: no official fixed-length format is published for `sk-cp-` keys (provider quickstart shows only redacted placeholders). Tier-1's fixed-prefix + rigid-body bar is not met; inside protected paths the detector still runs. |
| Modal API Key | 2 | Stays: Modal publishes no rigid token format (`modal.com` docs show bearer-token usage with no length contract; TruffleHog has no Modal detector). Tier-1 requires fixed-prefix + rigid-body; Modal meets neither. |
| Resend API Key | 1 | Moved: `re_` plus 8 base58 characters, underscore, 24 base58 characters; TruffleHog resend detector and provider API-key creation docs. Segments and boundaries prevent ordinary identifier matches. |
| Slack Webhook | 1 | Moved: `hooks.slack.com` plus `services`/`workflows`/`triggers` path and 43-56-character body; gitleaks slack-webhook-url rule. Length floor closes the short-body gap of the old detector. |
| Together AI API Key | 2 | Stays: Together does not publish a fixed token length or charset (docs show opaque bearer strings); the existing `tly_` low-floor pattern predates a verifiable spec. Not promotable without inventing format constraints. |
| Groq API Key | 1 | Moved: `gsk_` plus exactly 52 alphanumeric characters; TruffleHog groq detector and `/openai/v1/models` verifier. Full adjacent boundaries required. |
| DeepSeek API Key | 2 | Stays: generic shared prefix; explicit alphanumeric shapes also overlap Tier-1. |
| Mistral API Key | 2 | Stays: known model-ID false-positive class. |
| Cloudflare R2 Account ID | 2 | Stays: contextual public identifier. |
| Cloudflare R2 Access Key | 2 | Stays: generic hex plus variable-name context. |
| Cloudflare R2 Secret Key | 2 | Stays: generic hex plus variable-name context. |
| Backblaze B2 Key ID | 2 | Stays: numeric identifier prefix, not strong secret evidence. |
| Backblaze B2 Application Key | 2 | Stays: B2 app keys are 100-char base62 per provider docs, but the current detector's `{20,}` floor cannot be tightened without an authoritative charset/length contract (TruffleHog has none); the key-ID companion detector is separately documented. |
| Hex Secret (Quoted) | 2 | Stays: generic quoted hex plus keyword. |
| High-Entropy Secret (Quoted) | 2 | Stays: generic quoted alphanumeric plus keyword, not measured entropy. |
| Generic API Key | 2 | Stays: assignment-context heuristic. |
| Generic Secret | 2 | Stays: assignment-context heuristic. |
| Private Token Pattern | 2 | Stays: variable-name heuristic. |
| Generic Secret (Unquoted) | 2 | Stays: assignment-context heuristic. |
| Generic API Key (Unquoted) | 2 | Stays: assignment-context heuristic. |
| Private Key Variable (Unquoted) | 2 | Stays: variable-name heuristic. |
| Password Variable (Unquoted) | 2 | Stays: low-floor password context. |
| Generic Assignment (Unquoted) | 2 | Stays: variable-name heuristic. |
