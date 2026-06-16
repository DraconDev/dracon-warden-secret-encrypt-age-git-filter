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

impl SecretScanner {
    /// Expose patterns for integrity testing (e.g. Max Length Check)
    pub fn get_patterns() -> Vec<(&'static str, &'static str)> {
        vec![
            // ============================================================
            // AWS
            // ============================================================
            ("AWS Access Key ID", concat!("AK", "IA[0-9A-Z]{16}")),
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
            ("GCP API Key", concat!("AI", "za[0-9A-Za-z\\-_]{35}")),
            ("GCP OAuth Access Token", r"ya29\.[0-9A-Za-z_\-]{20,80}"),
            (
                "Azure Shared Access Signature",
                r"sv=\d{4}-\d{2}-\d{2}&(?:[a-z]{2,3}=[a-z0-9%]+&)+sig=[a-zA-Z0-9%+\/]{10,}",
            ),
            ("Azure Storage Account Key", r"[a-zA-Z0-9+/]{86}=="),
            ("Alibaba Access Key ID", concat!("LT", "AI[a-zA-Z0-9]{20}")),
            (
                "AWS MWS Key",
                r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ),
            // ============================================================
            // Google Cloud
            // ============================================================
            ("Google API Key", concat!("AI", "za[0-9A-Za-z\\-_]{35}")),
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
            ("GitHub Token (ghp)", concat!("gh", "p_[A-Za-z0-9_]{30,40}")),
            ("GitHub Token (gho)", concat!("gh", "o_[A-Za-z0-9_]{30,40}")),
            ("GitHub Token (ghu)", concat!("gh", "u_[A-Za-z0-9_]{30,40}")),
            ("GitHub Token (ghs)", concat!("gh", "s_[A-Za-z0-9_]{30,40}")),
            ("GitHub Token (ghr)", concat!("gh", "r_[A-Za-z0-9_]{30,40}")),
            (
                "GitHub Client Secret",
                r#"(?i)github.{0,20}client.{0,20}secret.{0,20}["']?[a-f0-9]{40}["']?"#,
            ),
            ("Google Client Secret", r#"(?i)GOCSPX-[A-Za-z0-9_\-]{28,}"#),
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
            ("GitLab Token", concat!("gl", "pat-[A-Za-z0-9\\-_]{20,}")),
            ("GitLab Runner Token", r"GR1348941[A-Za-z0-9\-_]{20,}"),
            (
                "Bitbucket Token",
                r#"(?i)bitbucket.{0,20}["'][A-Za-z0-9_]{30,}["']"#,
            ),
            // ============================================================
            // Stripe (ONLY LIVE KEYS)
            // ============================================================
            ("Stripe Live Secret Key", concat!("sk", "_live_[0-9a-zA-Z]{24,}")),
            ("Stripe Live Restricted Key", concat!("rk", "_live_[0-9a-zA-Z]{24,}")),
            ("Stripe Test Secret Key", concat!("sk", "_test_[0-9a-zA-Z]{24,}")),
            ("Stripe Test Restricted Key", concat!("rk", "_test_[0-9a-zA-Z]{24,}")),
            ("Stripe Webhook Secret", concat!("wh", "sec_[0-9a-zA-Z]{24,}")),
            // ============================================================
            // Slack
            // ============================================================
            (
                "Slack Token",
                concat!("xox", "[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
            ),
            (
                "Slack Webhook",
                r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            ),
            (
                "Slack Bot Token",
                concat!("xox", "b-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}"),
            ),
            ("Slack Bot Token (Compact)", concat!("xox", "b-[A-Za-z0-9]{24,68}")),
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
            ("Twilio API Key", r"SK[a-f0-9]{32}"),
            ("Twilio Account SID", r"AC[a-f0-9]{32}"),
            (
                "SendGrid API Key",
                r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            ),
            ("Mailgun API Key", concat!("key", "-[0-9a-zA-Z]{28,34}")),
            ("Mailchimp API Key", r"[0-9a-f]{32}-us[0-9]{1,2}"),
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
            (
                "RSA Private Key",
                r"(?s)-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
            ),
            (
                "DSA Private Key",
                r"(?s)-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
            ),
            (
                "EC Private Key",
                r"(?s)-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
            ),
            (
                "OpenSSH Private Key",
                r"(?s)-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
            ),
            (
                "PGP Private Key",
                r"(?s)-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----",
            ),
            (
                "SSH Private Key (generic)",
                r"(?s)-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
            ),
            // ============================================================
            // NPM / PyPI / Package Managers
            // ============================================================
            (
                "NPM Token",
                r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+",
            ),
            ("NPM Access Token", r"npm_[A-Za-z0-9]{36}"),
            ("PyPI Token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
            ("NuGet API Key", r"oy2[a-z0-9]{43}"),
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
            ("OpenAI API Key", r"sk-[a-zA-Z0-9_\-]{20,}"),
            (
                "Cohere API Key",
                r#"(?i)cohere.{0,20}["'][A-Za-z0-9]{40}["']"#,
            ),
            // ============================================================
            // DigitalOcean / Linode / Vultr
            // ============================================================
            ("DigitalOcean Token", concat!("dop", "_v1_[a-f0-9]{64}")),
            (
                "DigitalOcean Spaces Key",
                r#"(?i)digitalocean.{0,20}spaces.{0,20}["'][A-Z0-9]{20}["']"#,
            ),
            ("Linode Token", r#"(?i)linode.{0,20}["'][a-f0-9]{64}["']"#),
            // ============================================================
            // Shopify / Square / Payment
            // ============================================================
            ("Shopify Token", concat!("sh", "pat_[a-fA-F0-9]{32}")),
            ("Shopify Secret", r"shpss_[a-fA-F0-9]{32}"),
            ("Square Access Token", concat!("sq", "0atp-[A-Za-z0-9_-]{22}")),
            ("Square OAuth Secret", concat!("sq", "0csp-[A-Za-z0-9_-]{43}")),
            (
                "PayPal Client ID",
                r#"(?i)paypal.{0,20}client.{0,20}id.{0,10}["'][A-Za-z0-9_-]{80}["']"#,
            ),
            // ============================================================
            // HashiCorp / Vault
            // ============================================================
            ("HashiCorp Vault Token", concat!("hvs", "\\.[A-Za-z0-9_-]{24,}")),
            (
                "HashiCorp Terraform Token",
                r#"(?i)terraform.{0,20}["'][A-Za-z0-9]{14}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{67}["']"#,
            ),
            // ============================================================
            // Age Encryption (Arcane uses this!)
            // ============================================================
            (
                "Age Secret Key",
                concat!("AGE", "-SECRET", "-KEY-", "1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
            ),
            // ============================================================
            // AI / Cloud Provider API Keys
            // ============================================================
            ("NVIDIA API Key", r"nvapi-[A-Za-z0-9_-]{20,}"),
            ("OpenRouter API Key", r"sk-or-v1-[A-Za-z0-9_-]{20,}"),
            ("MiniMax API Key", r"sk-cp-[A-Za-z0-9_-]{20,}"),
            ("Modal API Key", r"modalresearch_[A-Za-z0-9_-]{20,}"),
            ("Resend API Key", r"re_[A-Za-z0-9_-]{20,}"),
            ("Together AI API Key", r"tly_[A-Za-z0-9_-]{20,}"),
            ("Groq API Key", r"gsk_[A-Za-z0-9_-]{20,}"),
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
            // (
            //     "Generic Secret (Unquoted)",
            //     r#"(?i)(?:secret|token|password|passwd|pwd|credential).{0,10}=[^\s"\[]{16,}"#,
            // ),
            (
                "Generic API Key (Unquoted)",
                r#"(?i)(?:api[_-]?key|apikey).{0,10}=[A-Za-z0-9_-]{20,}"#,
            ),
            (
                "Private Key Variable (Unquoted)",
                r#"(?i)[A-Z0-9_]*PRIVATE_KEY[A-Z0-9_]*=[A-Za-z0-9_-]{20,}"#,
            ),
            (
                "Password Variable (Unquoted)",
                r#"(?i)[A-Z0-9_]*PASSWORD[A-Z0-9_]*=[a-zA-Z0-9!$%&*+\-.=?@^_~]{8,}"#,
            ),
            (
                "Generic Assignment (Unquoted)",
                r#"(?i)[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|ACCESS)[A-Z0-9_]*=[^\s"'`]{20,}"#,
            ),
        ]
    }

    pub fn new() -> Result<Self> {
        Self::new_with_custom_patterns(&[])
    }

    /// Create a scanner with custom patterns merged with built-in patterns.
    /// Custom patterns are tuples of (name, regex_pattern).
    pub fn new_with_custom_patterns(custom: &[(&str, &str)]) -> Result<Self> {
        let mut patterns_raw = Self::get_patterns();
        for (name, pattern) in custom {
            patterns_raw.push((*name, *pattern));
        }

        let patterns_raw = patterns_raw;

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

                    // SAFEGUARD: Ignore secrets already inside an encrypted tag.
                    // Accepts any marker name that ends with "_SECRET".
                    if is_inside_secret_tag(content, start_idx) {
                        continue;
                    }

                    let line_num = content[..start_idx].chars().filter(|&c| c == '\n').count() + 1;
                    let matching_str = mat.as_str();
                    let snippet = if matching_str.len() > 60 {
                        format!("{}...", &matching_str[..60])
                    } else {
                        matching_str.to_string()
                    };

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
}
