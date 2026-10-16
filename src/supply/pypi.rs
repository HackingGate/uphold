//! Evidence for guarddog's comparison of optional extras with required dependencies.
//!
//! The report drops markers. Only the exact release's `requires_dist` can
//! establish that every occurrence of a reported name requires an extra.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use pyreq::Requirement;
use serde_json::Value;

/// The release endpoint, rather than the project endpoint, binds the evidence
/// to what guarddog scanned. `PyPI` documents it at <https://docs.pypi.org/api/json/>.
fn release_url(name: &str, version: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let name = package_name(name)?;
    // Versions are a single URL segment, never a caller-selected destination.
    if !version.bytes().any(|byte| byte.is_ascii_digit())
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!+_-".contains(&byte))
    {
        return None;
    }
    Some(format!("https://pypi.org/pypi/{name}/{version}/json"))
}

/// Fetch bounded, exact-release registry evidence. Failure leaves the scanner's
/// risk available to the ordinary finding and waiver handling.
pub(super) fn fetch(name: &str, version: &str) -> Result<Value, String> {
    let url = release_url(name, version).ok_or("invalid release identity")?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(15)))
        .build()
        .into();
    read_response(agent.get(&url).call().map_err(|error| error.to_string())?)
}

/// Redirect bodies and partial responses cannot supply release evidence even
/// when their JSON has the expected fields.
fn read_response(mut response: ureq::http::Response<ureq::Body>) -> Result<Value, String> {
    if response.status() != 200 {
        return Err(format!("unexpected PyPI HTTP status {}", response.status()));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(2 * 1024 * 1024)
        .read_to_string()
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&body).map_err(|error| error.to_string())
}

/// Only the one-sided, names-only report has a meaning this evidence proves.
/// Unknown blocks, malformed names and duplicate normalized names stay findings.
pub(super) fn differences(description: &str) -> Option<BTreeSet<String>> {
    let mut lines = description.lines();
    if lines.next()? != "Dependency mismatch between PyPI metadata and pyproject.toml:" {
        return None;
    }
    let names = lines
        .next()?
        .strip_prefix("  In PyPI metadata but NOT in pyproject.toml: ")?;
    if lines.next().is_some() {
        return None;
    }
    let mut parsed = BTreeSet::new();
    for name in names.split(", ") {
        if name.is_empty() || !parsed.insert(package_name(name)?) {
            return None;
        }
    }
    (!parsed.is_empty()).then_some(parsed)
}

/// Names are parsed by the requirement reader, then constrained to the bare
/// name form so URL segments and report entries cannot carry extra syntax.
fn package_name(name: &str) -> Option<String> {
    let requirement = Requirement::parse(name).ok()?;
    (requirement.name == name).then(|| super::references::normalise(name))
}

/// Confirm every reported name occurs only under a recognized optional-extra
/// marker in the named release. Any other occurrence prevents tolerance.
pub(super) fn confirms(
    metadata: &Value,
    name: &str,
    version: &str,
    differences: &BTreeSet<String>,
) -> Option<String> {
    let info = metadata.get("info")?;
    if package_name(info.get("name")?.as_str()?)? != package_name(name)?
        || info.get("version")?.as_str()? != version
    {
        return None;
    }
    // The closed normalization recognizes a simple positive equality. More
    // expressive markers stay findings; no host environment is guessed.
    let extra_marker = regex::Regex::new(
        r#"^(?:extra == "[A-Za-z0-9][A-Za-z0-9._-]*"|"[A-Za-z0-9][A-Za-z0-9._-]*" == extra)$"#,
    )
    .ok()?;
    let mut optional = BTreeMap::new();
    for raw in info.get("requires_dist")?.as_array()? {
        let requirement = Requirement::parse(raw.as_str()?).ok()?;
        let extra_only = requirement
            .marker
            .as_ref()
            .is_some_and(|marker| extra_marker.is_match(&marker.to_string()));
        optional
            .entry(package_name(&requirement.name)?)
            .and_modify(|all| *all &= extra_only)
            .or_insert(extra_only);
    }
    if !differences
        .iter()
        .all(|dependency| optional.get(dependency) == Some(&true))
    {
        return None;
    }
    Some(format!(
        "{} ({})",
        super::Normalization::OptionalExtras.name(),
        differences
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::{confirms, differences, read_response, release_url};
    use serde_json::json;
    use std::io::Write as _;

    const DESCRIPTION: &str = "Dependency mismatch between PyPI metadata and pyproject.toml:\n  In PyPI metadata but NOT in pyproject.toml: pyarrow\n";

    /// Exercise the production response reader over a local HTTP connection;
    /// production URL selection always uses HTTPS at the fixed registry host.
    fn response(status: u16, body: &str) -> Result<serde_json::Value, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = body.to_owned();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).ok();
        });
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(std::time::Duration::from_secs(5)))
            .build()
            .into();
        let result = read_response(agent.get(format!("http://{address}/")).call().unwrap());
        server.join().unwrap();
        result
    }

    #[test]
    fn only_a_complete_bounded_json_response_can_be_evidence() {
        assert_eq!(response(200, "{}"), Ok(json!({})));
        for status in [206, 301, 302, 307, 404, 500] {
            assert!(response(status, "{}").is_err(), "{status}");
        }
        assert!(response(200, "not json").is_err());
        assert!(response(200, &" ".repeat(2 * 1024 * 1024 + 1)).is_err());
    }

    #[test]
    fn the_recorded_pandas_report_is_explained_by_its_release_metadata() {
        let report: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/guarddog/pypi-pandas-3.0.3.json"
        ))
        .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/guarddog/pypi-pandas-3.0.3-metadata.json"
        ))
        .unwrap();
        let names = differences(
            report[0]["result"]["results"]["metadata_mismatch"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(confirms(&metadata, "pandas", "3.0.3", &names).is_some());
    }

    #[test]
    fn every_occurrence_must_require_a_positive_extra() {
        let names = differences(DESCRIPTION).unwrap();
        for (requirements, accepted) in [
            (vec!["pyarrow>=13; extra == 'parquet'"], true),
            (
                vec!["pyarrow; python_version >= '3.10' and extra == 'parquet'"],
                false,
            ),
            (vec!["pyarrow; 'parquet' == extra"], true),
            (
                vec!["pyarrow; extra == 'parquet'", "pyarrow; extra == 'test'"],
                true,
            ),
            (
                vec![
                    "pyarrow; extra == 'parquet'",
                    "pyarrow; sys_platform == 'win32'",
                ],
                false,
            ),
            (
                vec!["pyarrow; extra == 'parquet' or python_version < '3.10'"],
                false,
            ),
            (vec!["pyarrow; extra != 'parquet'"], false),
            (vec!["pyarrow"], false),
            (vec!["another; extra == 'parquet'"], false),
            (vec!["pyarrow; extra =="], false),
            (vec![], false),
        ] {
            let metadata = json!({"info": {"name": "example", "version": "1.0", "requires_dist": requirements}});
            assert_eq!(
                confirms(&metadata, "example", "1.0", &names).is_some(),
                accepted,
                "{metadata}"
            );
        }
    }

    #[test]
    fn evidence_must_name_the_scanned_release_and_every_difference() {
        let names = differences(DESCRIPTION).unwrap();
        for metadata in [
            json!({"info": {"name": "different", "version": "1.0", "requires_dist": ["pyarrow; extra == 'x'"]}}),
            json!({"info": {"name": "example", "version": "2.0", "requires_dist": ["pyarrow; extra == 'x'"]}}),
            json!({"info": {"name": "example", "version": "1.0", "requires_dist": null}}),
            json!({"info": {"name": "example", "version": "1.0", "requires_dist": [42]}}),
            json!({}),
        ] {
            assert!(confirms(&metadata, "example", "1.0", &names).is_none());
        }
        let two = differences(&DESCRIPTION.replace("pyarrow\n", "pyarrow, injected\n")).unwrap();
        let metadata = json!({"info": {"name": "Example_Kit", "version": "1.0", "requires_dist": ["PyArrow; extra == 'x'"]}});
        assert!(confirms(&metadata, "example-kit", "1.0", &names).is_some());
        assert!(confirms(&metadata, "example-kit", "1.0", &two).is_none());
    }

    #[test]
    fn unknown_or_ambiguous_report_shapes_are_not_candidates() {
        for description in [
            DESCRIPTION.replace("pyarrow", ""),
            DESCRIPTION.replace("pyarrow", "pyarrow, PyArrow"),
            DESCRIPTION.replace("pyarrow", "pyarrow>=13"),
            DESCRIPTION.replace(
                "pyarrow",
                "pyarrow, injected\n  In pyproject.toml but NOT in PyPI metadata: removed",
            ),
            format!("{DESCRIPTION}unrecognized difference\n"),
            format!("{DESCRIPTION}\n"),
        ] {
            assert!(differences(&description).is_none(), "{description}");
        }
    }

    #[test]
    fn release_identity_cannot_change_the_destination() {
        assert_eq!(
            release_url("Example_Kit", "1.0+local"),
            Some(String::from(
                "https://pypi.org/pypi/example-kit/1.0+local/json"
            ))
        );
        for name in ["../evil", "https://elsewhere", "x?y", "x#y", ""] {
            assert!(release_url(name, "1.0").is_none());
        }
        for version in [
            "../evil",
            "1.0/anything",
            "1.0?x",
            "1.0#x",
            "%2f",
            ".",
            "..",
            "",
        ] {
            assert!(release_url("example", version).is_none());
        }
    }
}
