//! Secret scanning patterns and detection.

use anyhow::Result;
use regex::Regex;

use crate::is_inside_secret_tag;

#[derive(Debug)]
pub struct SecretFinding {
    pub name: String,
    pub line: usize,
    pub snippet: String,
}

pub struct SecretScanner {
    patterns: Vec<(String, Regex)>,
    full_regex: Regex,
}

/// Return a display snippet capped at `max_bytes` without splitting a UTF-8
/// code point. A byte slice at the cap can panic on multi-byte secrets.
fn snippet_for_display(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let end = value
        .char_indices()
        .map(|(start, ch)| (start, start + ch.len_utf8()))
        .take_while(|(_, end)| *end <= max_bytes)
        .last()
        .map_or(0, |(_, end)| end);
    format!("{}...", &value[..end])
}

impl SecretScanner {
    /// Tier-1 (high-confidence, structured provider tokens) patterns.
    ///
    /// ADDED 2026-09-16 (eager source encryption): these run on EVERY
    /// non-hatched text file, including source files outside the
    /// protected-patterns gate (see `smart_clean_with_path`). Membership
    /// bar: a fixed provider prefix + rigid body shape, so ordinary code
    /// (model IDs, function names, test vectors, base64 blobs) cannot
    /// match. Generic/keyword-anchored/low-floor patterns stay Tier-2
    /// (protected paths only) — running those on arbitrary source
    /// repeats the 2026-06 gibuardien false-positive incident.
    ///
    /// Relative order mirrors the original `get_patterns` interleaving so
    /// combined-regex match attribution is unchanged.
    pub fn tier1_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            ("AWS Access Key ID", concat!("AK", "IA[0-9A-Z]{16}")),
            // GitHub's 2021 format: 30 base62 random bytes + 6 checksum
            // characters after the prefix. The maintained github/v2 detector
            // supports 36..255 body characters, including newer token variants.
            // See token-tier-inventory.md#format-review-sources.
            (
                "GitHub Token (ghp)",
                concat!(r"\bgh", "p_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (gho)",
                concat!(r"\bgh", "o_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (ghu)",
                concat!(r"\bgh", "u_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (ghs)",
                concat!(r"\bgh", "s_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (ghr)",
                concat!(r"\bgh", "r_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Fine-grained PAT",
                r"\bgithub_pat_[A-Za-z0-9_]{36,255}",
            ),
            ("GitLab Token", concat!("gl", "pat-[A-Za-z0-9\\-_]{20,}")),
            ("GitLab Runner Token", r"GR1348941[A-Za-z0-9\-_]{20,}"),
            (
                "Stripe Live Secret Key",
                concat!("sk", "_live_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Live Restricted Key",
                concat!("rk", "_live_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Test Secret Key",
                concat!("sk", "_test_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Test Restricted Key",
                concat!("rk", "_test_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Webhook Secret",
                concat!("wh", "sec_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Slack Token",
                concat!("xox", "[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
            ),
            (
                "Slack Bot Token",
                concat!("xox", "b-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}"),
            ),
            (
                "Slack Bot Token (Compact)",
                concat!("xox", "b-[A-Za-z0-9]{24,68}"),
            ),
            ("Twilio API Key", r"SK[a-f0-9]{32}"),
            ("Twilio Account SID", r"AC[a-f0-9]{32}"),
            (
                "SendGrid API Key",
                r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            ),
            ("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}"),
            (
                "RSA Private Key",
                concat!(
                    r"(?s)-----BEGIN RSA PRIV",
                    r"ATE KEY-----.*?-----END RSA PRIVATE KEY-----"
                ),
            ),
            (
                "DSA Private Key",
                concat!(
                    r"(?s)-----BEGIN DSA PRIV",
                    r"ATE KEY-----.*?-----END DSA PRIVATE KEY-----"
                ),
            ),
            (
                "EC Private Key",
                concat!(
                    r"(?s)-----BEGIN EC PRIV",
                    r"ATE KEY-----.*?-----END EC PRIVATE KEY-----"
                ),
            ),
            (
                "OpenSSH Private Key",
                concat!(
                    r"(?s)-----BEGIN OPENSSH PRIV",
                    r"ATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----"
                ),
            ),
            (
                "PGP Private Key",
                concat!(
                    r"(?s)-----BEGIN PGP PRIV",
                    r"ATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----"
                ),
            ),
            (
                "SSH Private Key (generic)",
                r"(?s)-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
            ),
            ("NPM Access Token", r"npm_[A-Za-z0-9]{36}"),
            // Boundaries prevent matching the interior of task-like slugs.
            // Project/service keys have explicit prefixes; legacy bare keys
            // have an alphanumeric body, not arbitrary hyphenated prose.
            (
                "OpenAI API Key",
                r"\bsk-(?:(?:proj|svcacct)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})",
            ),
            (
                "PKCS8 Private Key",
                concat!(
                    r"(?s)-----BEGIN PRIV",
                    r"ATE KEY-----.*?-----END PRIVATE KEY-----"
                ),
            ),
            (
                "Encrypted PKCS8 Private Key",
                concat!(
                    r"(?s)-----BEGIN ENCRYPTED PRIV",
                    r"ATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----"
                ),
            ),
            ("OpenRouter API Key", r"\bsk-or-v1-[0-9a-f]{64}"),
            ("Groq API Key", r"\bgsk_[A-Za-z0-9]{52}"),
            (
                "Resend API Key",
                r"\bre_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}",
            ),
            ("GCP API Key", concat!(r"\bAI", r"za[0-9A-Za-z_-]{35}")),
            ("Google API Key", concat!(r"\bAI", r"za[0-9A-Za-z_-]{35}")),
            ("Google Client Secret", r"\bGOCSPX-[A-Za-z0-9_-]{28,}"),
            (
                "DigitalOcean Token",
                concat!(r"\bdop", r"_v1_[a-f0-9]{64}\b"),
            ),
            ("Shopify Token", concat!(r"\bsh", r"pat_[a-fA-F0-9]{32}\b")),
            ("Shopify Secret", r"\bshpss_[a-fA-F0-9]{32}\b"),
            (
                "Square Access Token",
                concat!(r"\bsq", r"0atp-[A-Za-z0-9_-]{22}"),
            ),
            (
                "Square OAuth Secret",
                concat!(r"\bsq", r"0csp-[A-Za-z0-9_-]{43}"),
            ),
            (
                "HashiCorp Vault Token",
                concat!(r"\bhvs", r"\.[A-Za-z0-9_-]{24,}"),
            ),
            (
                "AWS MWS Key",
                r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            ),
            (
                "Slack Webhook",
                r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
            ),
        ]
    }

    /// POSIX-ERE transliteration of the Tier-1 provider-token shapes, and the
    /// SINGLE source the pre-push hook's `SECRET_RE` renders from (audit M10,
    /// 2026-10-02: the hook's hand-written regex covered only AKIA/PEM plus
    /// password/secret/api_key assignments, so every other Tier-1 shape pushed
    /// clean when the filter was bypassed).
    ///
    /// Same membership bar as [`tier1_patterns`](Self::tier1_patterns): a
    /// fixed provider prefix + rigid body shape. Names match Tier-1 names
    /// one-for-one EXCEPT the eight private-key entries (`RSA/DSA/EC/OpenSSH/
    /// PGP/PKCS8/Encrypted-PKCS8/SSH-generic Private Key`), which are
    /// multi-line `(?s)` patterns the line-oriented hook cannot express —
    /// they map to the hook's shared `-----BEGIN ... PRIVATE KEY` header
    /// alternative instead. `test_hook_shapes_cover_tier1_names` enforces
    /// both halves: no Tier-1 entry without a hook shape (or the documented
    /// PEM mapping), no hook shape without a Tier-1 entry.
    ///
    /// ERE transliteration rules (the hook runs `grep -E`, not the `regex`
    /// crate): no `\b` (anchor by alternation position instead — a hook
    /// false positive only blocks a push, it never encrypts source), no
    /// `\s`/`\d`/`\w`, no `(?:...)`/`(?...)` (plain `(...)` groups are
    /// fine), `{m,n}` kept verbatim, and a literal `-` inside a class goes
    /// LAST (`[A-Za-z0-9_-]`, never `[\-...]` — POSIX leaves `\-` undefined
    /// and GNU grep reads it as a range). `test_hook_shapes_are_posix_ere`
    /// statically guards every fragment against PCRE-only constructs.
    ///
    /// Like Tier-1, fixed prefixes that naive substring scanners trip on are
    /// split with `concat!` (same split points as Tier-1), so this source
    /// file introduces no new literal exposure beyond what Tier-1 ships.
    pub fn hook_token_shapes_ere() -> Vec<(&'static str, &'static str)> {
        vec![
            // The `A{1}` keeps a literal AKIA prefix out of the installed
            // hook text (the hook must never match its own file).
            ("AWS Access Key ID", concat!("A{1}K", "IA[A-Z0-9]{16}")),
            (
                "GitHub Token (ghp)",
                concat!("gh", "p_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (gho)",
                concat!("gh", "o_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (ghu)",
                concat!("gh", "u_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (ghs)",
                concat!("gh", "s_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Token (ghr)",
                concat!("gh", "r_[A-Za-z0-9_]{36,255}"),
            ),
            (
                "GitHub Fine-grained PAT",
                "github_pat_[A-Za-z0-9_]{36,255}",
            ),
            ("GitLab Token", concat!("gl", "pat-[A-Za-z0-9_-]{20,}")),
            ("GitLab Runner Token", "GR1348941[A-Za-z0-9_-]{20,}"),
            (
                "Stripe Live Secret Key",
                concat!("sk", "_live_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Live Restricted Key",
                concat!("rk", "_live_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Test Secret Key",
                concat!("sk", "_test_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Test Restricted Key",
                concat!("rk", "_test_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Stripe Webhook Secret",
                concat!("wh", "sec_[0-9a-zA-Z]{24,}"),
            ),
            (
                "Slack Token",
                concat!("xox", "[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
            ),
            (
                "Slack Bot Token",
                concat!("xox", "b-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}"),
            ),
            (
                "Slack Bot Token (Compact)",
                concat!("xox", "b-[A-Za-z0-9]{24,68}"),
            ),
            ("Twilio API Key", "SK[a-f0-9]{32}"),
            ("Twilio Account SID", "AC[a-f0-9]{32}"),
            (
                "SendGrid API Key",
                r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            ),
            ("Mailchimp API Key", "[0-9a-f]{32}-us[0-9]{1,2}"),
            ("NPM Access Token", "npm_[A-Za-z0-9]{36}"),
            (
                "OpenAI API Key",
                "sk-((proj|svcacct)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})",
            ),
            ("OpenRouter API Key", "sk-or-v1-[0-9a-f]{64}"),
            ("Groq API Key", "gsk_[A-Za-z0-9]{52}"),
            (
                "Resend API Key",
                "re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24}",
            ),
            ("GCP API Key", concat!("AI", "za[0-9A-Za-z_-]{35}")),
            ("Google API Key", concat!("AI", "za[0-9A-Za-z_-]{35}")),
            ("Google Client Secret", "GOCSPX-[A-Za-z0-9_-]{28,}"),
            ("DigitalOcean Token", concat!("dop", "_v1_[a-f0-9]{64}")),
            ("Shopify Token", concat!("sh", "pat_[a-fA-F0-9]{32}")),
            ("Shopify Secret", "shpss_[a-fA-F0-9]{32}"),
            (
                "Square Access Token",
                concat!("sq", "0atp-[A-Za-z0-9_-]{22}"),
            ),
            (
                "Square OAuth Secret",
                concat!("sq", "0csp-[A-Za-z0-9_-]{43}"),
            ),
            (
                "HashiCorp Vault Token",
                concat!("hvs", r"\.[A-Za-z0-9_-]{24,}"),
            ),
            (
                "AWS MWS Key",
                r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
            (
                "Slack Webhook",
                r"https://hooks\.slack\.com/(services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
            ),
        ]
    }

    /// Expose patterns for integrity testing (e.g. Max Length Check).
    /// Tier-1 first, then Tier-2 — full set unchanged.
    pub fn get_patterns() -> Vec<(&'static str, &'static str)> {
        let mut all = Self::tier1_patterns();
        all.extend(Self::tier2_patterns());
        all
    }

    /// Tier-2 (generic / keyword-anchored / low-floor) patterns: protected
    /// paths only. Unchanged content, original order.
    fn tier2_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            // ============================================================
            // AWS
            // ============================================================
            (
                "AWS Secret Access Key",
                r#"(?i)aws(.{0,20})?["'][0-9a-zA-Z/+]{40}["']"#,
            ),
            (
                "AWS Session Token",
                r"(?i)aws_session_token\s*=\s*[a-zA-Z0-9/+=]{16,}",
            ),
            // ============================================================
            // Cloud Providers Extended
            // ============================================================
            ("GCP OAuth Access Token", r"ya29\.[0-9A-Za-z_\-]{20,80}"),
            (
                "Azure Shared Access Signature",
                r"sv=\d{4}-\d{2}-\d{2}&(?:[a-z]{2,3}=[a-z0-9%]+&)+sig=[a-zA-Z0-9%+\/]{10,}",
            ),
            ("Azure Storage Account Key", r"[a-zA-Z0-9+/]{86}=="),
            ("Alibaba Access Key ID", concat!("LT", "AI[a-zA-Z0-9]{20}")),
            // ============================================================
            // Google Cloud
            // ============================================================
            (
                "Google Client ID",
                r"[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com",
            ),
            (
                "Google Service Account",
                r#"(?i)"type":\s*"service_account""#,
            ),
            (
                "Firebase Database URL",
                r"https://[a-z0-9-]+\.firebaseio\.com",
            ),
            (
                "Firebase API Key",
                r#"(?i)firebase.{0,20}["'][A-Za-z0-9_]{30,}["']"#,
            ),
            // ============================================================
            // Azure / Microsoft
            // ============================================================
            (
                "Azure Shared Access Signature",
                r"sv=\d{4}-\d{2}-\d{2}&(?:[a-z]{2,3}=[a-z0-9%]+&)+sig=[a-zA-Z0-9%+\/]{10,}",
            ),
            ("Azure Storage Account Key", r"[a-zA-Z0-9+/]{86}=="),
            (
                "Azure Storage Key",
                r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
            ),
            ("Azure SAS Token", r"sig=[A-Za-z0-9%]+&se=[0-9]+"),
            (
                "Azure AD Client Secret",
                r#"(?i)azure.{0,20}client.{0,20}secret.{0,20}["'][A-Za-z0-9_.\-~]{34,}["']"#,
            ),
            // ============================================================
            // Alibaba / IBM / Oracle
            // ============================================================
            ("Alibaba Access Key ID", concat!("LT", "AI[a-zA-Z0-9]{20}")),
            (
                "Alibaba Secret Key",
                r"(?i)(?:alibaba|aliyun).{0,20}(?:secret|key).{0,20}\s*[:=]\s*[a-zA-Z0-9]{30}",
            ),
            (
                "IBM Cloud API Key",
                r"(?i)(?:ibm).{0,20}(?:cloud|api|iam).{0,20}(?:key).{0,20}\s*[:=]\s*[a-zA-Z0-9_\-]{44}",
            ),
            (
                "Oracle Cloud API Key",
                r"(?i)ocid1\.[a-z]+\.[a-z0-9]+\.[a-z0-9]+",
            ),
            // ============================================================
            // GitHub / GitLab / Bitbucket
            // ============================================================
            // GitHub / GitLab / Bitbucket: structured gh*_ / glpat tokens
            // are Tier-1 (see tier1_patterns); keyword-anchored variants
            // stay Tier-2 here.
            (
                "GitHub Client Secret",
                r#"(?i)github.{0,20}client.{0,20}secret.{0,20}["']?[a-f0-9]{40}["']?"#,
            ),
            (
                "Discord Client Secret",
                r#"(?i)discord.{0,20}client.{0,20}secret.{0,20}["']?[A-Za-z0-9_\-]{32}["']?"#,
            ),
            (
                "Microsoft Client Secret",
                r#"(?i)microsoft.{0,20}client.{0,20}secret.{0,20}["']?[A-Za-z0-9_.\-~]{34,}["']?"#,
            ),
            (
                "GitHub App Token",
                r#"(?i)github.{0,20}["'][A-Za-z0-9_]{35,40}["']"#,
            ),
            (
                "Bitbucket Token",
                r#"(?i)bitbucket.{0,20}["'][A-Za-z0-9_]{30,}["']"#,
            ),
            // Stripe structured keys are Tier-1 (see tier1_patterns).
            // ============================================================
            // Slack
            // ============================================================
            // (broad xox* token is Tier-1); the rigid hooks.slack.com URL
            // format moved to Tier-1 below, this detector accepted short bodies.
            (
                "Slack Webhook",
                concat!(
                    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/",
                    r"[A-Za-z0-9]+"
                ),
            ),
            // (xoxb bot tokens are Tier-1)
            // ============================================================
            // Discord
            // ============================================================
            ("Discord Token", r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
            (
                "Discord Webhook",
                r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
            ),
            ("Telegram Bot Token", r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"),
            // ============================================================
            // Twilio / SendGrid / Mailgun
            // ============================================================
            // (Twilio/SendGrid structured keys are Tier-1)
            ("Mailgun API Key", concat!("key", "-[0-9a-zA-Z]{28,34}")),
            // ============================================================
            // Database / Connection Strings
            // ============================================================
            ("PostgreSQL URL", r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+"),
            ("MySQL URL", r"mysql://[^:]+:[^@]+@[^/]+"),
            ("MongoDB URL", r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+"),
            ("Redis URL", r"redis://[^:]+:[^@]+@[^/]+"),
            (
                "Database Password",
                r#"(?i)(?:db|database)(?:_)?(?:pass|password|pwd).{0,10}[=:].{0,5}["'][^"']{8,}["']"#,
            ),
            // ============================================================
            // Auth / Tokens / JWT
            // ============================================================
            (
                "JWT Token",
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ),
            ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
            ("Basic Auth Header", r"(?i)basic\s+[A-Za-z0-9+/=]{20,}"),
            (
                "OAuth Token",
                r#"(?i)oauth.{0,20}["'][A-Za-z0-9_-]{20,}["']"#,
            ),
            // ============================================================
            // SSH / Private Keys
            // ============================================================
            // (PEM blocks + npm/OpenAI structured tokens are Tier-1)
            // ============================================================
            // Heroku / Vercel / Netlify
            // ============================================================
            (
                "Heroku API Key",
                r#"(?i)heroku.{0,20}["'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']"#,
            ),
            (
                "Vercel Token",
                r#"(?i)vercel.{0,20}["'][A-Za-z0-9]{24}["']"#,
            ),
            (
                "Netlify Token",
                r#"(?i)netlify.{0,20}["'][A-Za-z0-9_-]{40,}["']"#,
            ),
            // ============================================================
            // OpenAI / Anthropic / AI APIs
            // ============================================================
            // (OpenAI sk- structured key is Tier-1)
            (
                "Cohere API Key",
                r#"(?i)cohere.{0,20}["'][A-Za-z0-9]{40}["']"#,
            ),
            // ============================================================
            // DigitalOcean / Linode / Vultr
            // ============================================================
            (
                "DigitalOcean Spaces Key",
                r#"(?i)digitalocean.{0,20}spaces.{0,20}["'][A-Z0-9]{20}["']"#,
            ),
            ("Linode Token", r#"(?i)linode.{0,20}["'][a-f0-9]{64}["']"#),
            // ============================================================
            // Shopify / Square / Payment
            // ============================================================
            (
                "PayPal Client ID",
                r#"(?i)paypal.{0,20}client.{0,20}id.{0,10}["'][A-Za-z0-9_-]{80}["']"#,
            ),
            // ============================================================
            // HashiCorp / Vault
            // ============================================================
            (
                "HashiCorp Terraform Token",
                r#"(?i)terraform.{0,20}["'][A-Za-z0-9]{14}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{67}["']"#,
            ),
            // ============================================================
            // Age Encryption (Arcane uses this!)
            // ============================================================
            (
                "Age Secret Key",
                concat!(
                    "AGE",
                    "-SECRET",
                    "-KEY-",
                    "1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"
                ),
            ),
            // ============================================================
            // AI / Cloud Provider API Keys
            // ============================================================
            ("NVIDIA API Key", r"nvapi-[A-Za-z0-9_-]{20,}"),
            ("MiniMax API Key", r"sk-cp-[A-Za-z0-9_-]{20,}"),
            ("Modal API Key", r"modalresearch_[A-Za-z0-9_-]{20,}"),
            ("Together AI API Key", r"tly_[A-Za-z0-9_-]{20,}"),
            ("DeepSeek API Key", r"sk-[A-Za-z0-9]{20,}"),
            ("Mistral API Key", r"mistral-[A-Za-z0-9_-]{20,}"),
            // Cloudflare R2
            (
                "Cloudflare R2 Account ID",
                r"(?:account[_-]?id|cf[_-]?account[_-]?id).{0,10}[0-9a-f]{32}",
            ),
            (
                "Cloudflare R2 Access Key",
                r"(?:access[_-]?key[_-]?id|cf[_-]?access[_-]?key[_-]?id).{0,10}[0-9a-f]{20}",
            ),
            (
                "Cloudflare R2 Secret Key",
                r"(?:secret[_-]?key|cf[_-]?secret[_-]?key).{0,10}[a-f0-9]{40}",
            ),
            // Backblaze B2
            ("Backblaze B2 Key ID", r"0055[a-f0-9]{16}"),
            ("Backblaze B2 Application Key", r"K005[a-zA-Z0-9]{20,}"),
            // ============================================================
            // Generic High-Entropy / Passwords
            // ============================================================
            (
                "Hex Secret (Quoted)",
                r#"(?i)(?:secret|token|key|password|credential|auth).{0,20}["'][a-fA-F0-9]{32,}["']"#,
            ),
            (
                "High-Entropy Secret (Quoted)",
                r#"(?i)(?:secret|token|key|password|credential|auth).{0,20}["'][A-Za-z0-9]{24,}["']"#,
            ),
            (
                "Generic API Key",
                r#"(?i)(?:api[_-]?key|apikey).{0,10}[=:].{0,5}["'][^\s"\[]{20,}["']"#,
            ),
            (
                "Generic Secret",
                r#"(?i)(?:secret|token|password|passwd|pwd|credential).{0,10}[=:].{0,5}["'][^\s"\[]{16,}["']"#,
            ),
            (
                "Private Token Pattern",
                r#"(?i)private[_-]?(?:key|token).{0,10}[=:].{0,5}["'][A-Za-z0-9_-]{20,}["']"#,
            ),
            // ============================================================
            // Unquoted Assignments (Env Vars / Configs)
            // ============================================================
            // FIXED 2026-08-11 (audit MEDIUM): "Generic Secret (Unquoted)"
            // was commented out upstream, so whitespace-padded unquoted
            // secrets (a bare password value in a protected file such as
            // secrets/app.yaml) committed plaintext AND passed the
            // pre-push defense-in-depth hook. Re-enabled with two
            // hardening tweaks: `\b` word boundaries (the old pattern
            // matched `password` inside `notpassword`) and `\s*` around
            // `=` (whitespace-padded assignments). Blast radius is
            // protected paths only (see filter.rs: the scanner runs on
            // secret_patterns matches, never on arbitrary source).
            (
                "Generic Secret (Unquoted)",
                r#"(?i)\b(?:secret|token|password|passwd|pwd|credential)\b.{0,10}\s*=\s*[^\s"\[]{16,}"#,
            ),
            (
                "Generic API Key (Unquoted)",
                r#"(?i)(?:api[_-]?key|apikey).{0,10}\s*=\s*[A-Za-z0-9_-]{20,}"#,
            ),
            (
                "Private Key Variable (Unquoted)",
                r#"(?i)[A-Z0-9_]*PRIVATE_KEY[A-Z0-9_]*\s*=\s*[A-Za-z0-9_-]{20,}"#,
            ),
            (
                "Password Variable (Unquoted)",
                r#"(?i)[A-Z0-9_]*PASSWORD[A-Z0-9_]*\s*=\s*[a-zA-Z0-9!$%&*+\-.=?@^_~]{6,}"#,
            ),
            (
                "Generic Assignment (Unquoted)",
                r#"(?i)[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|ACCESS)[A-Z0-9_]*\s*=\s*[^\s"'`]{20,}"#,
            ),
        ]
    }

    pub fn new() -> Result<Self> {
        Self::new_with_custom_patterns(&[])
    }

    /// Create a scanner with custom patterns merged with built-in patterns.
    /// Custom patterns are tuples of (name, regex_pattern).
    /// Create a Tier-1-only scanner (structured provider tokens).
    /// ADDED 2026-09-16: runs on every non-hatched text file including
    /// unprotected source files. See `tier1_patterns` for the membership
    /// bar and `smart_clean_with_path` for the call site.
    pub fn new_tier1() -> Result<Self> {
        Self::build_from_raw(&Self::tier1_patterns())
    }

    /// Shared builder: compile `patterns_raw` into per-pattern regexes
    /// plus the combined single-pass regex. Extracted 2026-09-16 so
    /// `new_with_custom_patterns` and `new_tier1` share one code path.
    fn build_from_raw(patterns_raw: &[(&str, &str)]) -> Result<Self> {
        let patterns: Vec<(String, Regex)> = patterns_raw
            .iter()
            .filter_map(|(name, pattern)| {
                // Build the processed pattern exactly as it appears in the
                // combined regex so individual and combined behavior match.
                let p = if pattern.starts_with("(?") {
                    pattern.to_string()
                } else {
                    format!("(?sm){}", pattern)
                };
                Regex::new(&p).ok().map(|re| (name.to_string(), re))
            })
            .collect();

        let combined: String = patterns_raw
            .iter()
            .map(|(_, p)| format!("(?:{})", p))
            .collect::<Vec<_>>()
            .join("|");
        // Use RegexBuilder to cap DFA memory and prevent excessive compilation
        // costs from the large alternation. The regex crate uses finite automata
        // (no catastrophic backtracking), but very large combined regexes can
        // still use prohibitive memory during DFA construction.
        let full_regex = regex::RegexBuilder::new(&format!("(?sm){}", combined))
            .size_limit(10 * (1 << 20)) // 10 MiB total regex memory
            .dfa_size_limit(5 * (1 << 20)) // 5 MiB DFA cache
            .build()
            .map_err(|e| anyhow::anyhow!("invalid regex pattern in SecretScanner::new: {}", e))?;

        Ok(Self {
            patterns,
            full_regex,
        })
    }

    pub fn new_with_custom_patterns(custom: &[(&str, &str)]) -> Result<Self> {
        let mut patterns_raw = Self::get_patterns();
        for (name, pattern) in custom {
            patterns_raw.push((*name, *pattern));
        }

        Self::build_from_raw(&patterns_raw)
    }

    /// Create a scanner that excludes age identity key patterns.
    /// Used for master.age and identity.age files to prevent encrypting
    /// the age key itself while still scanning for other secrets.
    pub fn new_without_age_keys() -> Result<Self> {
        let patterns_raw = Self::get_patterns();

        let patterns: Vec<(String, Regex)> = patterns_raw
            .iter()
            .filter(|(name, _)| *name != "Age Secret Key")
            .filter_map(|(name, pattern)| {
                // Build the processed pattern exactly as it appears in the
                // combined regex so individual and combined behavior match.
                let p = if pattern.starts_with("(?") {
                    pattern.to_string()
                } else {
                    format!("(?sm){}", pattern)
                };
                Regex::new(&p).ok().map(|re| (name.to_string(), re))
            })
            .collect();

        let combined: String = patterns_raw
            .iter()
            .filter(|(name, _)| *name != "Age Secret Key")
            .map(|(_, p)| format!("(?:{})", p))
            .collect::<Vec<_>>()
            .join("|");
        let full_regex = regex::RegexBuilder::new(&format!("(?sm){}", combined))
            .size_limit(10 * (1 << 20))
            .dfa_size_limit(5 * (1 << 20))
            .build()
            .map_err(|e| {
                anyhow::anyhow!(
                    "invalid regex pattern in SecretScanner::new_without_age_keys: {}",
                    e
                )
            })?;

        Ok(Self {
            patterns,
            full_regex,
        })
    }

    /// Regex word boundaries are not token boundaries: '-', '_', '+', and
    /// '/' are valid inside several provider bodies (Slack webhook URLs use
    /// base64-style '+/' segments). Check the surrounding bytes without
    /// consuming delimiters (which would skip adjacent keys).
    fn has_token_boundaries(name: &str, content: &str, start: usize, end: usize) -> bool {
        if !matches!(
            name,
            "OpenAI API Key"
                | "GitHub Token (ghp)"
                | "GitHub Token (gho)"
                | "GitHub Token (ghu)"
                | "GitHub Token (ghs)"
                | "GitHub Token (ghr)"
                | "GitHub Fine-grained PAT"
                | "GCP API Key"
                | "Google API Key"
                | "Google Client Secret"
                | "DigitalOcean Token"
                | "Shopify Token"
                | "Shopify Secret"
                | "Square Access Token"
                | "Square OAuth Secret"
                | "HashiCorp Vault Token"
                | "AWS MWS Key"
                | "OpenRouter API Key"
                | "Groq API Key"
                | "Resend API Key"
                | "Slack Webhook"
        ) {
            return true;
        }
        let token_byte =
            |b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/');
        !start
            .checked_sub(1)
            .and_then(|i| content.as_bytes().get(i))
            .is_some_and(token_byte)
            && !content.as_bytes().get(end).is_some_and(token_byte)
    }

    pub fn scan(&self, content: &str) -> Vec<SecretFinding> {
        use rayon::prelude::*;

        // Fast-path: Use the optimized single-pass regex to see if ANY secret exists
        if !self.full_regex.is_match(content) {
            return Vec::new();
        }

        let found: Vec<SecretFinding> = self
            .patterns
            .par_iter()
            .flat_map(|(name, re)| {
                let mut results = Vec::new();
                for mat in re.find_iter(content) {
                    let start_idx = mat.start();
                    if !Self::has_token_boundaries(name, content, start_idx, mat.end()) {
                        continue;
                    }

                    // SAFEGUARD: Ignore secrets already inside an encrypted tag.
                    // Accepts any marker name that ends with "_SECRET".
                    if is_inside_secret_tag(content, start_idx) {
                        continue;
                    }

                    let line_num = content[..start_idx].chars().filter(|&c| c == '\n').count() + 1;
                    let matching_str = mat.as_str();
                    let snippet = snippet_for_display(matching_str, 60);

                    results.push(SecretFinding {
                        name: name.clone(),
                        line: line_num,
                        snippet,
                    });
                }
                results
            })
            .collect();

        // Sort by line number for consistent output
        let mut sorted = found;
        sorted.sort_by_key(|f| f.line);
        sorted
    }
    /// Returns the number of patterns loaded
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Returns the names of all loaded patterns (for diagnostics).
    pub fn pattern_names(&self) -> Vec<String> {
        self.patterns.iter().map(|(n, _)| n.clone()).collect()
    }

    /// Scans content and replaces detected secrets using a callback.
    /// This allows for in-situ transformation (e.g. wrapping in REDACTED_REGEX)
    pub fn scan_and_replace<F>(&self, content: &str, mut f: F) -> String
    where
        F: FnMut(&str, &str) -> String,
    {
        let mut new_result = String::new();
        let mut last_end = 0;

        for mat in self.full_regex.find_iter(content) {
            let matched_str = mat.as_str();

            // 1. SAFEGUARD: Check if we are inside an existing tag
            if is_inside_secret_tag(content, mat.start()) {
                continue;
            }

            // 3. Find which specific pattern matched
            let mut pattern_name = "Unknown";
            for (name, re) in &self.patterns {
                if re.is_match(matched_str) {
                    pattern_name = name;
                    break;
                }
            }

            if !Self::has_token_boundaries(pattern_name, content, mat.start(), mat.end()) {
                continue;
            }
            new_result.push_str(&content[last_end..mat.start()]);
            new_result.push_str(&f(pattern_name, matched_str));
            last_end = mat.end();
        }

        new_result.push_str(&content[last_end..]);
        new_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_with_custom_patterns() {
        let custom = vec![("Custom Secret", r"CUSTOM_SECRET_[A-Z0-9]{16}")];
        let scanner = SecretScanner::new_with_custom_patterns(&custom).unwrap();

        // Should find custom pattern
        let findings = scanner.scan("CUSTOM_SECRET_ABCDEF1234567890");
        assert!(findings.iter().any(|f| f.name == "Custom Secret"));

        // Should also find built-in patterns
        let findings = scanner.scan(concat!("AK", "IAIOSFODNN7EXAMPLE"));
        assert!(findings.iter().any(|f| f.name == "AWS Access Key ID"));
    }

    #[test]
    fn test_scanner_custom_patterns_empty() {
        let scanner = SecretScanner::new_with_custom_patterns(&[]).unwrap();
        let findings = scanner.scan("no secrets here");
        assert!(findings.is_empty());
    }

    /// Tier-1 entries with no hook shape: the eight multi-line `(?s)`
    /// private-key patterns, which the line-oriented hook covers with its
    /// shared `-----BEGIN ... PRIVATE KEY` header alternative instead.
    const HOOK_PEM_MAPPED_NAMES: &[&str] = &[
        "RSA Private Key",
        "DSA Private Key",
        "EC Private Key",
        "OpenSSH Private Key",
        "PGP Private Key",
        "SSH Private Key (generic)",
        "PKCS8 Private Key",
        "Encrypted PKCS8 Private Key",
    ];

    #[test]
    fn test_hook_shapes_cover_tier1_names() {
        // Both halves of the M10 sharing contract: no Tier-1 entry without
        // a hook shape (or the documented PEM mapping), no hook shape
        // without a Tier-1 entry. A new Tier-1 pattern without a hook
        // transliteration fails here instead of pushing clean past the hook.
        let tier1: std::collections::HashSet<&str> = SecretScanner::tier1_patterns()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let hook: std::collections::HashSet<&str> =
            SecretScanner::hook_token_shapes_ere()
                .into_iter()
                .map(|(name, _)| name)
                .collect();
        for mapped in HOOK_PEM_MAPPED_NAMES {
            assert!(
                tier1.contains(mapped),
                "PEM-mapped name {mapped:?} is not a Tier-1 entry (renamed?)"
            );
            assert!(
                !hook.contains(mapped),
                "PEM-mapped name {mapped:?} must not also have a hook shape"
            );
        }
        for name in &tier1 {
            assert!(
                hook.contains(name) || HOOK_PEM_MAPPED_NAMES.contains(name),
                "Tier-1 entry {name:?} has no hook shape and no PEM mapping"
            );
        }
        for name in &hook {
            assert!(
                tier1.contains(name),
                "hook shape {name:?} has no Tier-1 entry"
            );
        }
    }

    #[test]
    fn test_hook_shapes_are_posix_ere() {
        // The hook runs `grep -E`, not the `regex` crate: every fragment
        // must be free of PCRE-only constructs AND compile, so a future
        // edit cannot smuggle `\b`/`(?:`/`\-` into the hook regex (where
        // GNU grep would silently misread them).
        for (name, ere) in SecretScanner::hook_token_shapes_ere() {
            for bad in ["\\b", "\\s", "\\d", "\\w", "\\S", "\\D", "\\W", "(?", "\\-"] {
                assert!(
                    !ere.contains(bad),
                    "hook shape {name:?} contains PCRE-only {bad:?}: {ere}"
                );
            }
            regex::Regex::new(ere)
                .unwrap_or_else(|e| panic!("hook shape {name:?} does not compile: {e}"));
        }
    }

    #[test]
    fn test_hook_shapes_detect_their_tokens() {
        // Every ERE fragment detects a well-formed token of its shape
        // (matched with the `regex` crate, whose semantics coincide with
        // ERE for these constructs; `test_hook_shapes_are_posix_ere`
        // guards the coincidence). Samples are `concat!`-split like the
        // Tier-1 samples above, so no matchable literal ever sits in this
        // source file.
        let samples: &[(&str, &str)] = &[
            ("AWS Access Key ID", concat!("AK", "IAIOSFODNN7EXAMPLE")),
            (
                "GitHub Token (ghp)",
                concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                "GitHub Token (gho)",
                concat!("gh", "o_abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                "GitHub Token (ghu)",
                concat!("gh", "u_abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                "GitHub Token (ghs)",
                concat!("gh", "s_abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                "GitHub Token (ghr)",
                concat!("gh", "r_abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                "GitHub Fine-grained PAT",
                concat!("github", "_pat_abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            ("GitLab Token", concat!("gl", "pat-abcdefghijklmnopqrst")),
            (
                "GitLab Runner Token",
                concat!("GR13", "48941abcdefghijklmnopqrst"),
            ),
            (
                "Stripe Live Secret Key",
                concat!("sk", "_live_abcdefghijklmnopqrstuvwx"),
            ),
            (
                "Stripe Live Restricted Key",
                concat!("rk", "_live_abcdefghijklmnopqrstuvwx"),
            ),
            (
                "Stripe Test Secret Key",
                concat!("sk", "_test_abcdefghijklmnopqrstuvwx"),
            ),
            (
                "Stripe Test Restricted Key",
                concat!("rk", "_test_abcdefghijklmnopqrstuvwx"),
            ),
            (
                "Stripe Webhook Secret",
                concat!("wh", "sec_abcdefghijklmnopqrstuvwx"),
            ),
            (
                "Slack Token",
                concat!("xox", "b-12345678901-12345678901-AbCdEfGh"),
            ),
            (
                "Slack Bot Token",
                concat!("xox", "b-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx"),
            ),
            (
                "Slack Bot Token (Compact)",
                concat!("xox", "b-AbCdEfGhIjKlMnOpQrStUvWxYz0123"),
            ),
            ("Twilio API Key", concat!("SK", "abcdef0123456789abcdef0123456789")),
            (
                "Twilio Account SID",
                concat!("AC", "abcdef0123456789abcdef0123456789"),
            ),
            (
                "SendGrid API Key",
                concat!(
                    "SG",
                    ".abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
                ),
            ),
            (
                "Mailchimp API Key",
                concat!("abcdef0123456789", "abcdef0123456789-us1"),
            ),
            ("NPM Access Token", concat!("npm", "_abcdefghijklmnopqrstuvwxyz0123456789")),
            (
                "OpenAI API Key",
                concat!("sk-", "abcdefghijklmnopqrstuvwxyz0123456789"),
            ),
            (
                "OpenRouter API Key",
                concat!(
                    "sk-or-v1-",
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                ),
            ),
            (
                "Groq API Key",
                concat!("gsk_", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            ),
            (
                "Resend API Key",
                concat!("re_", "AB123456_ABCD23456789ABCDEFGHJKLM"),
            ),
            (
                "GCP API Key",
                concat!("AI", "zaABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"),
            ),
            (
                "Google API Key",
                concat!("AI", "zaABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"),
            ),
            (
                "Google Client Secret",
                concat!("GOCSPX-", "ABCDEFGHIJKLMNOPQRSTUVWXYZab"),
            ),
            (
                "DigitalOcean Token",
                concat!(
                    "dop",
                    "_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                ),
            ),
            (
                "Shopify Token",
                concat!("sh", "pat_abcdef0123456789ABCDEF0123456789"),
            ),
            (
                "Shopify Secret",
                concat!("shp", "ss_abcdef0123456789ABCDEF0123456789"),
            ),
            (
                "Square Access Token",
                concat!("sq", "0atp-ABCDEFGHIJKLMNOPQRSTUV"),
            ),
            (
                "Square OAuth Secret",
                concat!("sq", "0csp-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"),
            ),
            (
                "HashiCorp Vault Token",
                concat!("hvs", ".ABCDEFGHIJKLMNOPQRSTUVWX"),
            ),
            (
                "AWS MWS Key",
                concat!("amzn", ".mws.12345678-1234-1234-1234-123456789012"),
            ),
            (
                "Slack Webhook",
                concat!(
                    "https://hooks",
                    ".slack.com/services/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
                ),
            ),
        ];
        let shapes: std::collections::HashMap<&str, &str> =
            SecretScanner::hook_token_shapes_ere().into_iter().collect();
        assert_eq!(
            samples.len(),
            shapes.len(),
            "every hook shape needs a detection sample"
        );
        for (name, sample) in samples {
            let ere = shapes
                .get(name)
                .unwrap_or_else(|| panic!("no hook shape named {name:?}"));
            let re = regex::Regex::new(ere).expect("shape compiles");
            assert!(
                re.is_match(sample),
                "hook shape {name:?} ({ere}) missed its sample"
            );
        }
        // The OpenAI project-key branch (`sk-proj-...`) is a second shape
        // through the same transliterated group — pin it too.
        let openai = shapes["OpenAI API Key"];
        let re = regex::Regex::new(openai).expect("openai compiles");
        assert!(re.is_match(concat!("sk-proj-", "abcdefghijklmnopqrstuvwxyz0123456789")));
    }

    #[test]
    fn test_scanner_truncates_utf8_snippet_at_char_boundary() {
        let scanner = SecretScanner::new().unwrap();
        let content = format!("password:\"{}\"", "🙂".repeat(20));
        let findings = scanner.scan(&content);
        let finding = findings
            .iter()
            .find(|finding| finding.name == "Generic Secret")
            .expect("generic secret should be detected");

        assert_eq!(
            finding.snippet,
            format!("password:\"{}...", "🙂".repeat(12))
        );
        assert!(finding.snippet.is_char_boundary(finding.snippet.len()));
    }
}
