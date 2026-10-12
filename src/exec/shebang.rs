//! `#!` line parsing with the kernel's rules.

/// The interpreter named by a shebang line, with its optional argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shebang {
    /// Interpreter path as written (a guest path).
    pub interp: Vec<u8>,
    /// Everything after the interpreter, trimmed, passed as one argument.
    pub arg: Option<Vec<u8>>,
}

/// Parses the payload of a `#!` line (without the `#!`, without newline).
///
/// Leading blanks are skipped, the interpreter runs until the next blank,
/// and the remainder, trimmed at both ends, becomes a single argument,
/// exactly like `fs/binfmt_script.c`.
///
/// # Arguments
/// * `line` - Bytes after `#!`, at most 255.
///
/// # Returns
/// The parsed [`Shebang`], or `None` when no interpreter is present.
pub fn parse(line: &[u8]) -> Option<Shebang> {
    let is_blank = |b: &u8| *b == b' ' || *b == b'\t';
    let line = &line[..line.len().min(255)];
    // The kernel also stops the line at the first NUL or newline.
    let end = line
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(line.len());
    let line = &line[..end];
    let start = line.iter().position(|b| !is_blank(b))?;
    let rest = &line[start..];
    let ilen = rest.iter().position(is_blank).unwrap_or(rest.len());
    let interp = rest[..ilen].to_vec();
    if interp.is_empty() {
        return None;
    }
    let tail = &rest[ilen..];
    let tstart = tail.iter().position(|b| !is_blank(b)).unwrap_or(tail.len());
    let tend = tail
        .iter()
        .rposition(|b| !is_blank(b))
        .map(|p| p + 1)
        .unwrap_or(tstart);
    let arg = if tend > tstart {
        Some(tail[tstart..tend].to_vec())
    } else {
        None
    };
    Some(Shebang { interp, arg })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interpreter_and_single_argument() {
        assert_eq!(
            parse(b"/bin/sh"),
            Some(Shebang {
                interp: b"/bin/sh".to_vec(),
                arg: None
            })
        );
        assert_eq!(
            parse(b"  /usr/bin/env   python3 -u  "),
            Some(Shebang {
                interp: b"/usr/bin/env".to_vec(),
                arg: Some(b"python3 -u".to_vec())
            })
        );
        assert_eq!(
            parse(b"/bin/bash\t-e"),
            Some(Shebang {
                interp: b"/bin/bash".to_vec(),
                arg: Some(b"-e".to_vec())
            })
        );
        assert_eq!(parse(b"   "), None);
        assert_eq!(parse(b""), None);
    }
}
