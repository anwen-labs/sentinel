//! Input-safety limits — bound memory and CPU on untrusted input.
//!
//! The engine parses attacker-controlled config (a paste in the browser demo, a
//! file in a CI runner). These guards implement the threat model's
//! "input validation, size limits, sandboxed parsing" mitigation for
//! malicious/oversized input. All three were reproduced as real DoS before
//! being added (see the crate tests).

/// Largest input we will parse, in bytes (5 MiB). Larger inputs are rejected at
/// the application boundary before any parser runs. Parsing memory is roughly
/// linear in input size (~17 KB per Compose service observed), so this bounds
/// peak memory to a few hundred MB even on pathological-but-valid input.
pub const MAX_INPUT_BYTES: usize = 5 * 1024 * 1024;

/// Maximum number of YAML alias references (`*anchor`) accepted.
///
/// `yaml-rust2` caps nesting *depth* but not alias *expansion*, so a handful of
/// chained aliases expand exponentially — the classic "billion laughs" bomb
/// (a 387-byte file drove the process to 13 GB before this guard). Worst-case
/// expansion for `n` aliases is bounded by `e^(n/e)` nodes, so the cap of 32
/// bounds expansion to ≲130k nodes (a few MB). Real Compose/K8s files use a
/// handful of aliases at most.
pub const MAX_YAML_ALIASES: usize = 32;

/// Maximum block/value nesting depth for the hand-written HCL (Terraform)
/// parser. It is recursive-descent, so without a guard deeply nested blocks
/// overflow the stack and abort the process (reproduced: 50k-deep blocks →
/// `STATUS_STACK_OVERFLOW`). Real Terraform never nests anywhere near this.
pub const MAX_HCL_DEPTH: usize = 64;

/// Maximum YAML block/flow nesting depth accepted. `yaml-rust2`'s tree loader
/// (`YamlLoader::load_from_str`) and the marked-event loader behind `yaml-loc`
/// recurse once per nesting level with no bound, so deeply-nested block YAML
/// (`- - - … x`, ~2 bytes/level) overflows the stack and aborts the process —
/// under the size cap and with zero aliases, so neither guard above catches it.
/// [`check_yaml_depth`] rejects it on the iterative event parser before any
/// recursive loader runs. Matches [`MAX_HCL_DEPTH`]; real Compose/K8s/Actions
/// files nest a dozen levels at most.
pub const MAX_YAML_DEPTH: usize = 64;

/// Reject inputs larger than [`MAX_INPUT_BYTES`]. Call at the application
/// boundary (CLI/WASM) so every format is covered uniformly.
pub fn check_input_size(input: &str) -> Result<(), String> {
    let n = input.len();
    if n > MAX_INPUT_BYTES {
        return Err(format!(
            "input too large: {n} bytes (limit {MAX_INPUT_BYTES} bytes)"
        ));
    }
    Ok(())
}

/// Reject YAML whose alias count exceeds [`MAX_YAML_ALIASES`] — a billion-laughs
/// guard.
///
/// Counts aliases via the low-level event parser, which emits one `Alias` event
/// per `*ref` and does **not** materialize the referenced subtree. So this runs
/// in time/space linear in the *source*, and the exponential expansion that
/// `YamlLoader` would perform never happens for a bomb. Malformed YAML is left
/// for the real loader to report — a scan error here returns `Ok(())`.
pub fn check_yaml_aliases(input: &str) -> Result<(), String> {
    use yaml_rust2::parser::{Event, Parser};
    let mut parser = Parser::new_from_str(input);
    let mut aliases = 0usize;
    loop {
        match parser.next_token() {
            Ok((Event::Alias(_), _)) => {
                aliases += 1;
                if aliases > MAX_YAML_ALIASES {
                    return Err(format!(
                        "too many YAML aliases (>{MAX_YAML_ALIASES}) — possible alias-expansion bomb"
                    ));
                }
            }
            Ok((Event::StreamEnd, _)) => return Ok(()),
            Ok(_) => {}
            // Let the real loader produce a precise parse error for malformed input.
            Err(_) => return Ok(()),
        }
    }
}

/// Reject YAML nested deeper than [`MAX_YAML_DEPTH`] — a stack-exhaustion guard.
///
/// Counts container open/close events on the low-level *iterative* event parser
/// (an explicit state stack, not native recursion, so it cannot itself overflow),
/// tracking current depth. Runs before the recursive `YamlLoader` / `yaml-loc`
/// walk, so over-deep input is rejected instead of crashing the process.
/// Malformed YAML is left for the real loader — a scan error here returns `Ok(())`.
pub fn check_yaml_depth(input: &str) -> Result<(), String> {
    use yaml_rust2::parser::{Event, Parser};
    let mut parser = Parser::new_from_str(input);
    let mut depth = 0usize;
    loop {
        match parser.next_token() {
            Ok((Event::MappingStart(..), _)) | Ok((Event::SequenceStart(..), _)) => {
                depth += 1;
                if depth > MAX_YAML_DEPTH {
                    return Err(format!(
                        "YAML nesting too deep (>{MAX_YAML_DEPTH}) — possible stack-exhaustion input"
                    ));
                }
            }
            Ok((Event::MappingEnd, _)) | Ok((Event::SequenceEnd, _)) => {
                depth = depth.saturating_sub(1);
            }
            Ok((Event::StreamEnd, _)) => return Ok(()),
            Ok(_) => {}
            Err(_) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_input() {
        let big = "x".repeat(MAX_INPUT_BYTES + 1);
        assert!(check_input_size(&big).is_err());
        assert!(check_input_size("services: {}").is_ok());
    }

    #[test]
    fn allows_a_few_legit_aliases() {
        let yaml = "\
defaults: &d
  image: nginx:latest
services:
  a: *d
  b: *d
  c: *d
";
        assert!(check_yaml_aliases(yaml).is_ok());
    }

    #[test]
    fn rejects_alias_bomb() {
        // The exact billion-laughs shape used in the security review: chained
        // anchors each referencing the previous one nine times.
        let mut bomb = String::from("a: &a [x,x,x,x,x,x,x,x,x]\n");
        let mut prev = "a".to_string();
        for ch in "bcdefghij".chars() {
            let refs = vec![format!("*{prev}"); 9].join(",");
            bomb.push_str(&format!("{ch}: &{ch} [{refs}]\n"));
            prev = ch.to_string();
        }
        // Counting aliases must stay cheap and must reject before any expansion.
        assert!(check_yaml_aliases(&bomb).is_err());
    }

    #[test]
    fn rejects_deeply_nested_block_yaml() {
        // ~100k levels of nested block sequence: under the 5 MiB cap, zero
        // aliases — the shape the security review used to overflow the loader.
        let deep = format!("{}x", "- ".repeat(100_000));
        assert!(check_yaml_depth(&deep).is_err());
        // A normal shallow document is accepted.
        assert!(check_yaml_depth("services:\n  web:\n    image: nginx\n").is_ok());
    }
}
