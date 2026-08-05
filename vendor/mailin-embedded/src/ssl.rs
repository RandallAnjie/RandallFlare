use std::io::{Read, Write};

/// `SslConfig` is used to configure the STARTTLS configuration of the server
pub enum SslConfig {
    /// Do not support STARTTLS
    None,
    /// Use a self-signed certificate for STARTTLS
    SelfSigned {
        /// Certificate path
        cert_path: String,
        /// Path to key file
        key_path: String,
    },
    /// Use a certificate from an authority
    Trusted {
        /// Certificate path
        cert_path: String,
        /// Key file path
        key_path: String,
        /// Path to CA bundle
        chain_path: String,
    },
    /// Load the current certificate for every new SMTP connection. STARTTLS
    /// is advertised only while the files form a valid certificate pair.
    Reloading {
        /// Certificate path.
        cert_path: String,
        /// Path to key file.
        key_path: String,
        /// Optional CA chain appended after the leaf certificate.
        chain_path: Option<String>,
    },
}

pub trait Stream: Read + Write {}
