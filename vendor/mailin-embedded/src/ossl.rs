use crate::ssl::{SslConfig, Stream};
use crate::Error;
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslStream};
use openssl::x509::X509;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

// Openssl wrapper
#[derive(Clone)]
pub enum SslImpl {
    Static(Arc<SslAcceptor>),
    Reloading {
        cert_path: String,
        key_path: String,
        chain_path: Option<String>,
    },
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        let msg = error.to_string();
        Error::with_source(msg, error)
    }
}

impl Stream for SslStream<TcpStream> {}

impl SslImpl {
    pub fn setup(ssl_config: SslConfig) -> Result<Option<Self>, Error> {
        let implementation = match ssl_config {
            SslConfig::Trusted {
                cert_path,
                key_path,
                chain_path,
            } => {
                let mut builder = ssl_builder(&cert_path, &key_path)?;
                let chain_pem = slurp(chain_path)?;
                let chain = X509::stack_from_pem(&chain_pem)?;
                for cert in chain {
                    builder.add_extra_chain_cert(cert.as_ref().to_owned())?;
                }
                Some(SslImpl::Static(Arc::new(builder.build())))
            }
            SslConfig::SelfSigned {
                cert_path,
                key_path,
            } => {
                let builder = ssl_builder(&cert_path, &key_path)?;
                Some(SslImpl::Static(Arc::new(builder.build())))
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
        self.current_acceptor().is_ok()
    }

    pub fn accept(&self, stream: TcpStream) -> Result<impl Stream, Error> {
        let ret = self
            .current_acceptor()?
            .accept(stream)
            .map_err(|e| Error::with_source("Cannot upgrade to TLS", e))?;
        Ok(ret)
    }

    fn current_acceptor(&self) -> Result<Arc<SslAcceptor>, Error> {
        match self {
            Self::Static(acceptor) => Ok(acceptor.clone()),
            Self::Reloading {
                cert_path,
                key_path,
                chain_path,
            } => {
                let mut builder = ssl_builder(cert_path, key_path)?;
                if let Some(chain_path) = chain_path {
                    let chain_pem = slurp(chain_path)?;
                    let chain = X509::stack_from_pem(&chain_pem)?;
                    for cert in chain {
                        builder.add_extra_chain_cert(cert.as_ref().to_owned())?;
                    }
                }
                Ok(Arc::new(builder.build()))
            }
        }
    }
}

fn ssl_builder(cert_path: &str, key_path: &str) -> Result<SslAcceptorBuilder, Error> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    let cert_pem = slurp(cert_path)?;
    let cert = X509::from_pem(&cert_pem)?;
    let key_pem = slurp(key_path)?;
    let pkey = PKey::private_key_from_pem(&key_pem)?;
    builder.set_private_key(&pkey)?;
    builder.set_certificate(&cert)?;
    builder.check_private_key()?;
    Ok(builder)
}

pub fn slurp<P>(path: P) -> Result<Vec<u8>, Error>
where
    P: AsRef<Path> + Display,
{
    let mut file =
        File::open(&path).map_err(|e| Error::with_source(format!("Cannot open {}", path), e))?;
    let mut ret = Vec::with_capacity(1024);
    file.read_to_end(&mut ret)?;
    Ok(ret)
}
