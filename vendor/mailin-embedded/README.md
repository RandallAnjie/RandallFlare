
A SMTP server that can be embedded into another program

This library provides a simple embeddable SMTP server. The
server uses blocking IO and a threadpool.

# Examples
```rust
use mailin_embedded::{Server, SslConfig, Handler};

#[derive(Clone)]
struct MyHandler {}
impl Handler for MyHandler{}

let handler = MyHandler {};
let mut server = Server::new(handler);

server.with_name("example.com")
   .with_ssl(SslConfig::None)?
   .with_addr("127.0.0.1:25")?;
server.serve_forever();
```

# SSL

The `mailin-embedded` library requires an SSL implementation. The SSL implementation is selected with a feature:

Using RustTLS (the default and recommended, so far no compatibility problems):

```
$ cargo build
```

Using OpenSSL (with [Mozilla modern](https://wiki.mozilla.org/Security/Server_Side_TLS)):

```
$ cargo build --features "ossl"
```

The SSL configuration for both of these libraries is quite strict and might not work with some older Email servers. However, until now, I have only seen problems with spammers and no problems with real email servers.


# Using in Cargo.toml

```
mailin-embedded = "^0"
```
