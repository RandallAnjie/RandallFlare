use crate::ssl::{SslConfig, Stream};
use crate::Error;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{Error as TLSError, ServerConfig, ServerConnection, StreamOwned};
use std::fs;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;

// Rustls wrapper
#[derive(Clone)]
pub enum SslImpl {
    Static(Arc<ServerConfig>),
    Reloading {
        cert_path: String,
        key_path: String,
        chain_path: Option<String>,
    },
}

impl Stream for StreamOwned<ServerConnection, TcpStream> {}

impl From<TLSError> for Error {
    fn from(error: TLSError) -> Self {
        let msg = error.to_string();
        Error::with_source(msg, error)
    }
}

impl SslImpl {
    pub fn setup(ssl_config: SslConfig) -> Result<Option<Self>, Error> {
        let implementation = match ssl_config {
            SslConfig::Trusted {
                cert_path,
                key_path,
                chain_path,
            } => {
                let mut certs = load_certs(&cert_path)?;
                let mut chain = load_certs(&chain_path)?;
                certs.append(&mut chain);
                let key = load_key(&key_path)?;
                let config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?;
                Some(SslImpl::Static(Arc::new(config)))
            }
            SslConfig::SelfSigned {
                cert_path,
                key_path,
            } => {
                let certs = load_certs(&cert_path)?;
                let key = load_key(&key_path)?;
                let config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?;
                Some(SslImpl::Static(Arc::new(config)))
            }
            SslConfig::Reloading {
                cert_path,
                key_path,
                chain_path,
            } => Some(SslImpl::Reloading {
                cert_path,
                key_path,
                chain_path,
            }),
            _ => None,
        };
        Ok(implementation)
    }

    pub fn is_ready(&self) -> bool {
        self.current_config().is_ok()
    }

    pub fn accept(&self, stream: TcpStream) -> Result<impl Stream, Error> {
        let session = ServerConnection::new(self.current_config()?)?;
        let tls_stream = StreamOwned::new(session, stream);
        Ok(tls_stream)
    }

    fn current_config(&self) -> Result<Arc<ServerConfig>, Error> {
        match self {
            Self::Static(config) => Ok(config.clone()),
            Self::Reloading {
                cert_path,
                key_path,
                chain_path,
            } => {
                let mut certs = load_certs(cert_path)?;
                if let Some(chain_path) = chain_path {
                    certs.append(&mut load_certs(chain_path)?);
                }
                let key = load_key(key_path)?;
                let config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?;
                Ok(Arc::new(config))
            }
        }
    }
}

fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let ret: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    ret.map_err(|_| Error::new("Unparseable certificates"))
}

fn load_key(filename: &str) -> Result<PrivateKeyDer<'static>, Error> {
    // Prefer to load pkcs8 keys
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let Some(key) = rustls_pemfile::private_key(&mut reader)
        .map_err(|_| Error::new("Unparseable PKCS8 key"))?
    else {
        return Err(Error::new("No private certificate keys found in pem"));
    };
    Ok(key)
}
