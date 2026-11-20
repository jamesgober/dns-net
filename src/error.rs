//! The codec's errors. Each says what was refused.

use std::fmt;

/// Why a name's text form was refused ([`crate::Name::parse`]).
///
/// ```
/// assert_eq!(dns_net::Name::parse("").unwrap_err(), dns_net::NameError::Empty);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    /// No text at all.
    Empty,
    /// Two dots in a row, or a leading dot.
    EmptyLabel,
    /// A label over 63 bytes.
    LabelTooLong,
    /// Over 255 bytes in wire form (253 characters of text).
    TooLong,
    /// A backslash not followed by a printable character or three digits up to 255.
    BadEscape,
    /// A byte that is not printable ASCII (convert other scripts with IDNA first).
    NotPrintable,
    /// Not a host name: only letters, digits, `-`, `_` and dots.
    NotHostname,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameError::Empty => "the name is empty",
            NameError::EmptyLabel => "the name has an empty label",
            NameError::LabelTooLong => "a label is longer than 63 bytes",
            NameError::TooLong => "the name is longer than 255 bytes",
            NameError::BadEscape => "the name has a bad escape",
            NameError::NotPrintable => "the name has a byte that is not printable ASCII",
            NameError::NotHostname => "not a host name (letters, digits, '-', '_' and dots only)",
        })
    }
}

impl std::error::Error for NameError {}

/// Why a message, or part of one, was refused by the decoder.
///
/// ```
/// let e = dns_net::Message::decode(&[0; 5]).unwrap_err();
/// assert_eq!(e, dns_net::DecodeError::Short);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The message ends inside a field.
    Short,
    /// Over 65,535 bytes: longer than any message can be.
    TooLong,
    /// Bytes left after the last record the header counts, or after one rdata.
    TrailingBytes,
    /// A label type other than a length or a pointer (`01` or `10` in the top bits).
    BadLabelType,
    /// A compression pointer that does not point strictly backwards.
    BadPointer,
    /// More compression pointers in one name than a name can need.
    TooManyPointers,
    /// A name over 255 bytes once decompressed.
    NameTooLong,
    /// The header counts more records than the limit, or than the message could hold.
    TooManyRecords,
    /// More than one question.
    QuestionCount,
    /// Record data that does not match its type's format.
    BadRdata {
        /// The record type.
        rtype: u16,
    },
    /// An OPT record that is not the only one, not in the additional section,
    /// or not owned by the root.
    BadOpt,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Short => f.write_str("the message ends inside a field"),
            DecodeError::TooLong => f.write_str("the message is longer than 65,535 bytes"),
            DecodeError::TrailingBytes => f.write_str("bytes are left after the last field"),
            DecodeError::BadLabelType => f.write_str("a name has a reserved label type"),
            DecodeError::BadPointer => {
                f.write_str("a compression pointer does not point backwards")
            }
            DecodeError::TooManyPointers => f.write_str("a name follows too many pointers"),
            DecodeError::NameTooLong => f.write_str("a name is longer than 255 bytes"),
            DecodeError::TooManyRecords => f.write_str("the message counts too many records"),
            DecodeError::QuestionCount => f.write_str("the message has more than one question"),
            DecodeError::BadRdata { rtype } => {
                write!(f, "the data of a type {rtype} record is malformed")
            }
            DecodeError::BadOpt => f.write_str("the message has a misplaced or second OPT record"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a message could not be written.
///
/// ```
/// assert_eq!(
///     dns_net::EncodeError::TooLong.to_string(),
///     "the message is longer than 65,535 bytes"
/// );
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The message would be over 65,535 bytes.
    TooLong,
    /// One record's data would be over 65,535 bytes, or a TXT string or CAA
    /// tag over 255.
    FieldTooLong,
    /// More than 65,535 records in one section.
    TooManyRecords,
    /// A CAA tag that is empty or not letters and digits (RFC 8659 section 4.1).
    BadCaaTag,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EncodeError::TooLong => "the message is longer than 65,535 bytes",
            EncodeError::FieldTooLong => "a field is longer than its length prefix allows",
            EncodeError::TooManyRecords => "a section has more than 65,535 records",
            EncodeError::BadCaaTag => "a CAA tag is empty or not letters and digits",
        })
    }
}

impl std::error::Error for EncodeError {}
