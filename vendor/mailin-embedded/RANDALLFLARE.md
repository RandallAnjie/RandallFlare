# RandallFlare mailin-embedded patch

This directory vendors `mailin-embedded` 0.8.3 (`MIT OR Apache-2.0`) from
<https://code.alienscience.org/alienscience/mailin>.

RandallFlare adds `SslConfig::Reloading`. A new SMTP connection advertises
STARTTLS only when the configured certificate and key can currently be loaded;
the TLS handshake reads the files again. This lets ACME materialize the first
certificate and replace renewed certificates atomically without restarting the
optional mail node. Existing `None`, `SelfSigned`, and `Trusted` behavior stays
unchanged for upstream callers.
