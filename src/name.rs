//! Domain names: text form, wire form, and bounded decompression (RFC 1035
//! sections 3.1 and 4.1.4).

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::error::{DecodeError, NameError};

/// The longest name in wire form, the root's zero byte included (RFC 1035 section 2.3.4).
pub const MAX_NAME: usize = 255;
/// The longest label (RFC 1035 section 2.3.4).
pub const MAX_LABEL: usize = 63;
/// The most compression pointers one name may follow. A name has at most 127
/// labels, so a legitimate one never needs more; with every pointer required
/// to point strictly before the last, this bounds the work per name.
pub const MAX_POINTERS: usize = 127;

/// A domain name, kept in wire form (length-prefixed labels ending with the
/// root's zero byte) exactly as it was written or received.
///
/// Equality and hashing ignore ASCII case, as DNS does (RFC 4343);
/// [`Name::eq_exact`] compares the bytes, which is what case randomization
/// needs.
///
/// ```
/// use dns_net::Name;
/// let a = Name::parse("Example.COM")?;
/// let b = Name::parse("example.com.")?;
/// assert_eq!(a, b);
/// assert!(!a.eq_exact(&b));
/// assert_eq!(a.to_string(), "Example.COM");
/// # Ok::<(), dns_net::NameError>(())
/// ```
#[derive(Clone)]
pub struct Name {
    wire: Box<[u8]>,
}

impl Name {
    /// The root name, `.`.
    ///
    /// ```
    /// assert!(dns_net::Name::root().is_root());
    /// ```
    #[must_use]
    pub fn root() -> Name {
        Name {
            wire: Box::new([0]),
        }
    }

    /// Parses the text form: labels separated by dots, an optional trailing
    /// dot, `\.` and `\\` for a literal dot or backslash, and `\DDD` (three
    /// decimal digits) for any byte. Printable ASCII only: a name in another
    /// script must be converted to its ASCII form (IDNA) first.
    ///
    /// # Errors
    ///
    /// [`NameError`] says what was wrong: an empty name or label, a label over
    /// 63 bytes, a name over 255, a bad escape, or a byte that is not
    /// printable ASCII.
    ///
    /// ```
    /// let n = dns_net::Name::parse("a\\.b.example")?;
    /// assert_eq!(n.label_count(), 2);
    /// assert!(dns_net::Name::parse("a..b").is_err());
    /// # Ok::<(), dns_net::NameError>(())
    /// ```
    pub fn parse(text: &str) -> Result<Name, NameError> {
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return Err(NameError::Empty);
        }
        if bytes == b"." {
            return Ok(Name::root());
        }
        let mut wire = Vec::with_capacity(bytes.len() + 2);
        let mut label_start = 0;
        wire.push(0);
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            let byte = match b {
                b'.' => {
                    let len = wire.len() - label_start - 1;
                    if len == 0 {
                        return Err(NameError::EmptyLabel);
                    }
                    wire[label_start] = len as u8;
                    i += 1;
                    if i == bytes.len() {
                        break;
                    }
                    label_start = wire.len();
                    wire.push(0);
                    continue;
                }
                b'\\' => {
                    let next = *bytes.get(i + 1).ok_or(NameError::BadEscape)?;
                    if next.is_ascii_digit() {
                        let d = bytes.get(i + 1..i + 4).ok_or(NameError::BadEscape)?;
                        if !d.iter().all(u8::is_ascii_digit) {
                            return Err(NameError::BadEscape);
                        }
                        let v = u32::from(d[0] - b'0') * 100
                            + u32::from(d[1] - b'0') * 10
                            + u32::from(d[2] - b'0');
                        if v > 255 {
                            return Err(NameError::BadEscape);
                        }
                        i += 4;
                        v as u8
                    } else if (0x21..=0x7E).contains(&next) {
                        i += 2;
                        next
                    } else {
                        return Err(NameError::BadEscape);
                    }
                }
                0x21..=0x7E => {
                    i += 1;
                    b
                }
                _ => return Err(NameError::NotPrintable),
            };
            if wire.len() - label_start > MAX_LABEL {
                return Err(NameError::LabelTooLong);
            }
            wire.push(byte);
            if wire.len() + 1 > MAX_NAME {
                return Err(NameError::TooLong);
            }
        }
        // The last label is never empty here: an empty one ends in a dot,
        // which either refused it or was the trailing dot.
        let len = wire.len() - label_start - 1;
        wire[label_start] = len as u8;
        // The wire never holds the root byte inside the loop (a label byte
        // written as `\000` is a label byte, not the root).
        wire.push(0);
        if wire.len() > MAX_NAME {
            return Err(NameError::TooLong);
        }
        Ok(Name {
            wire: wire.into_boxed_slice(),
        })
    }

    /// Parses a host name for an address lookup: letters, digits, `-` and
    /// `_` only, no escapes. Stricter than [`Name::parse`], so a host taken
    /// from a URL or a configuration cannot carry bytes another parser would
    /// read differently.
    ///
    /// # Errors
    ///
    /// As [`Name::parse`]; [`NameError::NotHostname`] for any other byte.
    ///
    /// ```
    /// assert!(dns_net::Name::parse_hostname("api.example.com").is_ok());
    /// assert!(dns_net::Name::parse_hostname("a\\.b").is_err());
    /// ```
    pub fn parse_hostname(text: &str) -> Result<Name, NameError> {
        if !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(NameError::NotHostname);
        }
        let name = Name::parse(text)?;
        if name.is_root() {
            return Err(NameError::NotHostname);
        }
        Ok(name)
    }

    /// Builds a name from its wire form (uncompressed).
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when `wire` is not exactly one well-formed name.
    ///
    /// ```
    /// let n = dns_net::Name::from_wire(b"\x03www\x07example\x00")?;
    /// assert_eq!(n.to_string(), "www.example");
    /// # Ok::<(), dns_net::DecodeError>(())
    /// ```
    pub fn from_wire(wire: &[u8]) -> Result<Name, DecodeError> {
        let mut pos = 0;
        let name = read_name(wire, &mut pos)?;
        if pos != wire.len() || name.wire.len() != wire.len() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(name)
    }

    /// The wire form, root byte included.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// The length of the wire form (1 for the root, at most 255).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// Whether this is the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// The labels, leftmost first, root excluded.
    ///
    /// ```
    /// let n = dns_net::Name::parse("www.example.com")?;
    /// assert_eq!(n.labels().next(), Some(&b"www"[..]));
    /// # Ok::<(), dns_net::NameError>(())
    /// ```
    pub fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.wire }
    }

    /// How many labels, root excluded.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Byte-for-byte equality, case included.
    #[must_use]
    pub fn eq_exact(&self, other: &Name) -> bool {
        self.wire == other.wire
    }

    /// Whether `self` is `zone` or a name under it (case ignored).
    ///
    /// ```
    /// use dns_net::Name;
    /// let host = Name::parse("a.b.example")?;
    /// assert!(host.is_within(&Name::parse("example")?));
    /// assert!(host.is_within(&Name::root()));
    /// assert!(!host.is_within(&Name::parse("b.example.org")?));
    /// # Ok::<(), dns_net::NameError>(())
    /// ```
    #[must_use]
    pub fn is_within(&self, zone: &Name) -> bool {
        let mut rest: &[u8] = &self.wire;
        loop {
            if rest.len() == zone.wire.len() {
                return rest.eq_ignore_ascii_case(&zone.wire);
            }
            if rest.len() < zone.wire.len() || rest[0] == 0 {
                return false;
            }
            rest = &rest[1 + usize::from(rest[0])..];
        }
    }

    /// The name with ASCII letters in lower case.
    #[must_use]
    pub fn to_lowercase(&self) -> Name {
        Name {
            wire: self.wire.to_ascii_lowercase().into_boxed_slice(),
        }
    }

    /// The name with the case of each ASCII letter taken from `bits`, one bit
    /// per letter (1: upper), cycling through `bits` if the name has more
    /// letters. Used for case randomization (the 0x20 bit).
    #[must_use]
    pub fn with_case(&self, bits: &[u8]) -> Name {
        let mut wire = self.wire.to_vec();
        if bits.is_empty() {
            return Name {
                wire: wire.into_boxed_slice(),
            };
        }
        let mut k = 0usize;
        let mut pos = 0;
        while wire[pos] != 0 {
            let len = usize::from(wire[pos]);
            for b in &mut wire[pos + 1..=pos + len] {
                if b.is_ascii_alphabetic() {
                    let bit = (bits[(k / 8) % bits.len()] >> (k % 8)) & 1;
                    *b = if bit == 1 {
                        b.to_ascii_uppercase()
                    } else {
                        b.to_ascii_lowercase()
                    };
                    k += 1;
                }
            }
            pos += 1 + len;
        }
        Name {
            wire: wire.into_boxed_slice(),
        }
    }

    /// How many ASCII letters the name has: the bits case randomization adds.
    #[must_use]
    pub fn letter_count(&self) -> usize {
        self.labels()
            .map(|l| l.iter().filter(|b| b.is_ascii_alphabetic()).count())
            .sum()
    }

    /// Joins `self` (a relative prefix) in front of `suffix`.
    ///
    /// # Errors
    ///
    /// [`NameError::TooLong`] past 255 bytes.
    ///
    /// ```
    /// use dns_net::Name;
    /// let full = Name::parse("_sip._tcp")?.join(&Name::parse("example.com")?)?;
    /// assert_eq!(full.to_string(), "_sip._tcp.example.com");
    /// # Ok::<(), dns_net::NameError>(())
    /// ```
    pub fn join(&self, suffix: &Name) -> Result<Name, NameError> {
        let len = self.wire.len() - 1 + suffix.wire.len();
        if len > MAX_NAME {
            return Err(NameError::TooLong);
        }
        let mut wire = Vec::with_capacity(len);
        wire.extend_from_slice(&self.wire[..self.wire.len() - 1]);
        wire.extend_from_slice(&suffix.wire);
        Ok(Name {
            wire: wire.into_boxed_slice(),
        })
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.wire.len());
        for b in self.wire.iter() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for (i, label) in self.labels().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            for &b in label {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x21..=0x7E => write!(f, "{}", b as char)?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

impl std::str::FromStr for Name {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Name, NameError> {
        Name::parse(s)
    }
}

/// The labels of a [`Name`], from [`Name::labels`].
#[derive(Clone, Debug)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(*self.rest.first()?);
        if len == 0 {
            return None;
        }
        let label = self.rest.get(1..=len)?;
        self.rest = &self.rest[1 + len..];
        Some(label)
    }
}

/// Reads a possibly compressed name at `*pos` in `msg`, leaving `*pos` after
/// it (after the first pointer when there is one).
///
/// Every pointer must point strictly before the run of labels it ends, so the
/// walk always moves backwards and cannot loop; at most [`MAX_POINTERS`] are
/// followed and the result is at most [`MAX_NAME`] bytes, so one name costs at
/// most a few hundred steps whatever the message holds.
pub(crate) fn read_name(msg: &[u8], pos: &mut usize) -> Result<Name, DecodeError> {
    let mut out = [0u8; MAX_NAME];
    let mut len = 0usize;
    let mut p = *pos;
    let mut floor = p;
    let mut jumped = false;
    let mut pointers = 0usize;
    loop {
        let b = *msg.get(p).ok_or(DecodeError::Short)?;
        match b & 0xC0 {
            0x00 => {
                let l = usize::from(b);
                if l == 0 {
                    out[len] = 0;
                    len += 1;
                    if !jumped {
                        *pos = p + 1;
                    }
                    break;
                }
                let label = msg.get(p + 1..p + 1 + l).ok_or(DecodeError::Short)?;
                // The label, its length byte, and the root byte still to come.
                if len + 1 + l + 1 > MAX_NAME {
                    return Err(DecodeError::NameTooLong);
                }
                out[len] = b;
                out[len + 1..len + 1 + l].copy_from_slice(label);
                len += 1 + l;
                p += 1 + l;
            }
            0xC0 => {
                let lo = *msg.get(p + 1).ok_or(DecodeError::Short)?;
                let target = (usize::from(b & 0x3F) << 8) | usize::from(lo);
                if target >= floor {
                    return Err(DecodeError::BadPointer);
                }
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return Err(DecodeError::TooManyPointers);
                }
                if !jumped {
                    *pos = p + 2;
                    jumped = true;
                }
                floor = target;
                p = target;
            }
            _ => return Err(DecodeError::BadLabelType),
        }
    }
    Ok(Name {
        wire: out[..len].into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn text_round_trip() {
        for s in [
            ".",
            "a",
            "example.com",
            "_sip._tcp.example.com",
            "a\\.b.c",
            "a\\\\b",
            "\\000\\255x",
        ] {
            let name = n(s);
            let again = n(&name.to_string());
            assert!(name.eq_exact(&again), "{s}");
        }
        assert_eq!(n("example.com.").to_string(), "example.com");
    }

    #[test]
    fn text_limits() {
        assert_eq!(Name::parse(""), Err(NameError::Empty));
        assert_eq!(Name::parse(".."), Err(NameError::EmptyLabel));
        assert_eq!(Name::parse(".a"), Err(NameError::EmptyLabel));
        assert_eq!(Name::parse("a..b"), Err(NameError::EmptyLabel));
        assert_eq!(Name::parse("a b"), Err(NameError::NotPrintable));
        assert_eq!(Name::parse("caf\u{e9}"), Err(NameError::NotPrintable));
        assert_eq!(Name::parse("a\\"), Err(NameError::BadEscape));
        assert_eq!(Name::parse("a\\25"), Err(NameError::BadEscape));
        assert_eq!(Name::parse("a\\256"), Err(NameError::BadEscape));
        let l63 = "a".repeat(63);
        assert!(Name::parse(&l63).is_ok());
        assert_eq!(Name::parse(&"a".repeat(64)), Err(NameError::LabelTooLong));
        // 4 labels of 63: 4 * 64 + 1 = 257 bytes.
        let long = [l63.as_str(); 4].join(".");
        assert_eq!(Name::parse(&long), Err(NameError::TooLong));
        // 253 characters of text is the longest name: 255 bytes of wire.
        let max = format!("{}.{}.{}.{}", l63, l63, l63, "a".repeat(61));
        assert_eq!(max.len(), 253);
        assert_eq!(n(&max).wire_len(), 255);
        assert_eq!(
            Name::parse(&format!("{max}a")),
            Err(NameError::TooLong),
            "254 characters"
        );
    }

    #[test]
    fn hostname_is_strict() {
        assert!(Name::parse_hostname("a-b_c.example").is_ok());
        assert_eq!(Name::parse_hostname("."), Err(NameError::NotHostname));
        assert_eq!(Name::parse_hostname("a\\.b"), Err(NameError::NotHostname));
        assert_eq!(Name::parse_hostname("a/b"), Err(NameError::NotHostname));
        assert_eq!(Name::parse_hostname("a%00b"), Err(NameError::NotHostname));
    }

    #[test]
    fn case_rules() {
        let a = n("WwW.Example.com");
        assert_eq!(a, n("www.example.COM"));
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        a.hash(&mut h1);
        n("www.example.com").hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        let up = a.with_case(&[0xFF]);
        assert_eq!(up.to_string(), "WWW.EXAMPLE.COM");
        let low = a.with_case(&[0]);
        assert_eq!(low.to_string(), "www.example.com");
        assert_eq!(a.letter_count(), 13);
        assert!(n("1-2.3").with_case(&[0xFF]).eq_exact(&n("1-2.3")));
    }

    #[test]
    fn within() {
        assert!(n("a.example.com").is_within(&n("EXAMPLE.com")));
        assert!(n("example.com").is_within(&n("example.com")));
        assert!(!n("aexample.com").is_within(&n("example.com")));
        assert!(!n("com").is_within(&n("example.com")));
    }

    #[test]
    fn decompression_follows_backward_pointers() {
        // "example.com" at 0, then "www" + pointer to 0 at 13.
        let mut msg = b"\x07example\x03com\x00".to_vec();
        msg.extend_from_slice(b"\x03www\xC0\x00");
        let mut pos = 13;
        let name = read_name(&msg, &mut pos).unwrap();
        assert_eq!(name.to_string(), "www.example.com");
        assert_eq!(pos, msg.len());
    }

    #[test]
    fn decompression_refuses_loops_and_forward_pointers() {
        // A pointer to itself.
        let msg = b"\xC0\x00";
        assert_eq!(read_name(msg, &mut 0), Err(DecodeError::BadPointer));
        // A pointer forward.
        let msg = b"\xC0\x02\x00";
        assert_eq!(read_name(msg, &mut 0), Err(DecodeError::BadPointer));
        // Two pointers that point at each other: the second must point before
        // the first's target, so it is refused.
        let msg = b"\x01a\xC0\x04\x01b\xC0\x00";
        assert_eq!(read_name(msg, &mut 4), Err(DecodeError::BadPointer));
        // A label that points back into itself through a later pointer.
        let msg = b"\x01a\xC0\x00";
        assert_eq!(read_name(msg, &mut 0), Err(DecodeError::BadPointer));
        // The reserved label types.
        assert_eq!(read_name(b"\x40", &mut 0), Err(DecodeError::BadLabelType));
        assert_eq!(read_name(b"\x80", &mut 0), Err(DecodeError::BadLabelType));
        assert_eq!(read_name(b"\x03ab", &mut 0), Err(DecodeError::Short));
    }

    #[test]
    fn decompression_bounds_the_length() {
        // 128 labels "a" of 2 bytes each, built from a backward chain: each
        // name is one label and a pointer to the one before it.
        let mut msg = vec![0u8];
        let mut prev = 0usize;
        for _ in 0..200 {
            let here = msg.len();
            msg.extend_from_slice(&[1, b'a', 0xC0 | (prev >> 8) as u8, prev as u8]);
            prev = here;
        }
        let mut pos = prev;
        assert_eq!(read_name(&msg, &mut pos), Err(DecodeError::NameTooLong));
    }

    #[test]
    fn decompression_bounds_the_pointers() {
        // A chain of bare pointers, each to the one before: no output at all.
        let mut msg = vec![0u8, 0u8];
        for i in 1..300usize {
            let prev = (i - 1) * 2;
            msg.extend_from_slice(&[0xC0 | (prev >> 8) as u8, prev as u8]);
        }
        let mut pos = msg.len() - 2;
        assert_eq!(read_name(&msg, &mut pos), Err(DecodeError::TooManyPointers));
    }

    #[test]
    fn from_wire_is_exact() {
        assert!(Name::from_wire(b"\x01a\x00").is_ok());
        assert_eq!(
            Name::from_wire(b"\x01a\x00\x00"),
            Err(DecodeError::TrailingBytes)
        );
        assert_eq!(Name::from_wire(b"\xC0\x00"), Err(DecodeError::BadPointer));
    }

    #[test]
    fn join_and_labels() {
        let j = n("a").join(&n("b.c")).unwrap();
        assert_eq!(j.to_string(), "a.b.c");
        assert_eq!(j.label_count(), 3);
        assert_eq!(Name::root().label_count(), 0);
        let l63 = "a".repeat(63);
        let big = n(&[l63.as_str(); 3].join("."));
        assert_eq!(big.join(&big), Err(NameError::TooLong));
    }
}
