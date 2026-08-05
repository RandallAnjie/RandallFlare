# RandallFlare mailin patch

This directory vendors `mailin` 0.6.5 (`MIT OR Apache-2.0`) from
<https://code.alienscience.org/alienscience/mailin>.

RandallFlare adds the RFC 6531 `SMTPUTF8` EHLO capability and accepts the
`SMTPUTF8` `MAIL FROM` parameter alongside `BODY=8BITMIME`. The public handler
API is unchanged, so `mailin-embedded` remains an unmodified dependency. The
workspace `Cargo.toml` applies this directory through `[patch.crates-io]`.
