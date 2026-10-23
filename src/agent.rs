//! Codex execution mode and the trusted VM bootstrap. Task input travels through the API.
use crate::cloud::SecretReference;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub enum AgentMode {
    #[default]
    Hello,
    Codex {
        model: String,
    },
}

impl AgentMode {
    pub fn parse(mode: &str, model: Option<String>) -> anyhow::Result<Self> {
        match mode {
            "hello" => Ok(Self::Hello),
            "codex" => {
                let model = model.filter(|value| !value.is_empty()).ok_or_else(|| {
                    anyhow::anyhow!("FACTORY_CODEX_MODEL must be set in codex mode")
                })?;
                anyhow::ensure!(
                    model.len() <= 128
                        && model.as_bytes()[0].is_ascii_alphanumeric()
                        && model
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                    "FACTORY_CODEX_MODEL must start with a letter or number and contain only letters, numbers, '.', '_' or '-'"
                );
                Ok(Self::Codex { model })
            }
            _ => anyhow::bail!("FACTORY_AGENT_MODE must be hello or codex"),
        }
    }
}

/// Codex callbacks currently use a dedicated HTTPS origin on the standard port.
pub fn validate_codex_url(value: &str) -> anyhow::Result<()> {
    let url =
        reqwest::Url::parse(value).map_err(|_| anyhow::anyhow!("invalid Codex callback URL"))?;
    anyhow::ensure!(
        value.bytes().all(|b| (33..=126).contains(&b))
            && !value.contains('\\')
            && value
                .strip_prefix("https://")
                .is_some_and(|rest| rest.find('/').is_none_or(|index| &rest[index..] == "/"))
            && url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == Some(443)
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "Codex callback URL must be an HTTPS origin on port 443 without credentials or a path"
    );
    Ok(())
}

pub fn codex_script(
    base_url: &str,
    task_id: Uuid,
    secret: &SecretReference,
    model: &str,
) -> String {
    let quote = |value: &str| format!("'{}'", value.replace('\'', r"'\''"));
    format!(
        "set +x\nset -eu\numask 077\nwork=$(mktemp -d)\ntrap 'rm -rf \"$work\"' EXIT\ntrap 'exit 1' HUP INT TERM\ncat > \"$work/runner.py\" <<'FACTORY_CODEX_RUNNER_SOURCE'\n{source}\nFACTORY_CODEX_RUNNER_SOURCE\npython3 \"$work/runner.py\" --base-url {base} --task-id {task_id} --parameter {parameter} --region {region} --model {model}\n",
        source = include_str!("../vm/runner.py"),
        base = quote(base_url),
        parameter = quote(&secret.name),
        region = quote(&secret.region),
        model = quote(model)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codex_url_matches_the_vm_contract() {
        assert!(validate_codex_url("https://factory.example").is_ok());
        assert!(validate_codex_url("https://factory.example:443/").is_ok());
        for url in [
            "http://factory.example",
            "https://factory.example:8443",
            "https://factory.example/api",
            "https://factory.example/api/..",
            "https://user:secret@factory.example",
            "https://factory.example/?query",
            "https://factory.example/#fragment",
        ] {
            assert!(validate_codex_url(url).is_err());
        }
    }

    #[test]
    fn execution_mode_requires_an_explicit_model_and_known_mode() {
        assert!(matches!(
            AgentMode::parse("hello", None).unwrap(),
            AgentMode::Hello
        ));
        assert!(AgentMode::parse("codex", None).is_err());
        for model in [".model", "_model", "-model", "model/name"] {
            assert!(AgentMode::parse("codex", Some(model.into())).is_err());
        }
        assert!(AgentMode::parse("arbitrary", None).is_err());
        assert!(AgentMode::parse("codex", Some("model; command".into())).is_err());
        assert!(matches!(
            AgentMode::parse("codex", Some("configured-model".into())).unwrap(),
            AgentMode::Codex { .. }
        ));
    }
}
