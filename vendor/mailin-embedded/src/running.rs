use crate::err::Error;
cfg_if::cfg_if! {
    if #[cfg(feature = "ossl")] {
        use crate::ossl::SslImpl;
    } else {
        use crate::rtls::SslImpl;
    }
}
use crate::ssl::Stream;
use crate::Server;
use bufstream_fresh::BufStream;
use log::{debug, error, info};
use mailin::{Action, Handler, Response, Session, SessionBuilder};
use scoped_threadpool::Pool;
use std::io::{BufRead, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::Duration;

const FIVE_MINUTES: Duration = Duration::new(5 * 60, 0);

enum SessionResult {
    Finished,
    UpgradeTls,
}

struct ServerState<H>
where
    H: Handler + Clone + Send,
{
    listener: TcpListener,
    handler: H,
    session_builder: SessionBuilder,
    ssl: Option<SslImpl>,
    num_threads: u32,
}

pub(crate) fn serve<H>(config: Server<H>) -> Result<(), Error>
where
    H: Handler + Clone + Send,
{
    let mut session_builder = SessionBuilder::new(config.name.clone());
    for auth in &config.auth {
        session_builder.enable_auth(auth.clone());
    }
    let listen = if let Some(listener) = config.tcp_listener {
        listener
    } else {
        let addr = config.socket_address;
        TcpListener::bind(&addr[..])
            .map_err(|err| Error::with_source("Cannot open listen address", err))?
    };
    let server_state = ServerState {
        listener: listen,
        handler: config.handler,
        session_builder,
        ssl: config.ssl,
        num_threads: config.num_threads,
    };
    run(&config.name, &server_state)
}

fn run<H>(name: &str, server_state: &ServerState<H>) -> Result<(), Error>
where
    H: Handler + Clone + Send,
{
    let mut pool = Pool::new(server_state.num_threads);
    let localaddr = server_state.listener.local_addr()?;
    info!("{} SMTP started on {}", name, localaddr);
    pool.scoped(|scoped| {
        for conn in server_state.listener.incoming() {
            match conn {
                Ok(stream) => {
                    let acceptor = server_state.ssl.clone();
                    let mut builder = server_state.session_builder.clone();
                    if acceptor.as_ref().is_some_and(SslImpl::is_ready) {
                        builder.enable_start_tls();
                    }
                    let handler_clone = server_state.handler.clone();
                    scoped.execute(move || {
                        handle_connection(stream, &builder, acceptor, handler_clone)
                    });
                }
                Err(e) => error!("Connection failed: {}", e),
            }
        }
    });
    Ok(())
}

fn handle_session<H, S>(session: &mut Session<H>, stream: &mut S) -> Result<SessionResult, Error>
where
    S: BufRead + Write,
    H: Handler,
{
    let mut line = Vec::with_capacity(80);
    loop {
        line.clear();
        let num_bytes = stream.read_until(b'\n', &mut line)?;
        if num_bytes == 0 {
            break;
        }
        let res = session.process(&line);
        match res.action {
            Action::Reply => {
                write_response(stream, &res)?;
            }
            Action::Close => {
                write_response(stream, &res)?;
                if res.is_error {
                    return Error::bail("SMTP error");
                } else {
                    return Ok(SessionResult::Finished);
                }
            }
            Action::UpgradeTls => {
                write_response(stream, &res)?;
                return Ok(SessionResult::UpgradeTls);
            }
            Action::NoReply => (),
        }
    }
    Error::bail("Unexpected Eof")
}

fn write_response(mut writer: &mut dyn Write, res: &Response) -> Result<(), Error> {
    res.write_to(&mut writer)?;
    writer
        .flush()
        .map_err(|e| Error::with_source("Cannot write response", e))
}

fn upgrade_tls(stream: TcpStream, ssl: Option<SslImpl>) -> Result<impl Stream, Error> {
    if let Some(acceptor) = ssl {
        let ret = acceptor.accept(stream)?;
        Ok(ret)
    } else {
        Error::bail("Cannot upgrade to TLS without an SslAcceptor")
    }
}

fn start_session<H: Handler>(
    session_builder: &SessionBuilder,
    remote: IpAddr,
    mut stream: BufStream<TcpStream>,
    ssl: Option<SslImpl>,
    handler: H,
) -> Result<(), Error> {
    let mut session = session_builder.build(remote, handler);
    write_response(&mut stream, &session.greeting())?;
    let res = handle_session(&mut session, &mut stream)?;
    if let SessionResult::UpgradeTls = res {
        let inner_stream = stream
            .into_inner()
            .map_err(|e| Error::with_source("Cannot flush original TcpStream", e))?;
        let tls = upgrade_tls(inner_stream, ssl)?;
        session.tls_active();
        let mut buf_tls = BufStream::new(tls);
        handle_session(&mut session, &mut buf_tls)?;
    }
    Ok(())
}

fn handle_connection<H: Handler>(
    stream: TcpStream,
    session_builder: &SessionBuilder,
    ssl: Option<SslImpl>,
    handler: H,
) {
    let remote = stream
        .peer_addr()
        .map(|saddr| saddr.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
    debug!("New connection from {}", remote);
    stream.set_read_timeout(Some(FIVE_MINUTES)).ok();
    stream.set_write_timeout(Some(FIVE_MINUTES)).ok();
    let bufstream = BufStream::new(stream);
    if let Err(err) = start_session(session_builder, remote, bufstream, ssl, handler) {
        debug!("({}) Cannot start session: {}", remote, err);
    }
}
