//! Backends for TLS connections for WebSocket clients.

#![cfg(any(feature = "use-native-tls", feature = "use-rustls"))]

use std::fmt::{self, Debug};
use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::{
    error::Result,
    stream::{Mode, NoDelay},
};

#[cfg(feature = "use-native-tls")]
pub use self::native_tls::Wrapper as NativeTlsWrapper;
#[cfg(feature = "use-rustls")]
pub use self::rustls::Wrapper as RustlsWrapper;

/// A stream that is similar to the [`crate::stream::Stream`] but with variations of TLS backends
/// that allows to pick a specific backend while multiple of them are enabled.
#[allow(clippy::large_enum_variant)]
pub enum AutoStream {
    /// Use the TLS implementation from the `native-tls` crate utilizing the local OS specific
    /// TLS libraries.
    #[cfg(feature = "use-native-tls")]
    NativeTls(native_tls::AutoStream),
    /// Use the TLS implementation from the `rustls` crate which is a pure Rust implementation of
    /// TLS.
    #[cfg(feature = "use-rustls")]
    Rustls(rustls::AutoStream),
}

impl Debug for AutoStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            #[cfg(feature = "use-native-tls")]
            Self::NativeTls(_) => "AutoStream::NativeTls",
            #[cfg(feature = "use-rustls")]
            Self::Rustls(_) => "AutoStream::Rustls",
        })
    }
}

impl Read for AutoStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(feature = "use-native-tls")]
            Self::NativeTls(stream) => stream.read(buf),
            #[cfg(feature = "use-rustls")]
            Self::Rustls(stream) => stream.read(buf),
        }
    }
}

impl Write for AutoStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(feature = "use-native-tls")]
            Self::NativeTls(stream) => stream.write(buf),
            #[cfg(feature = "use-rustls")]
            Self::Rustls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(feature = "use-native-tls")]
            Self::NativeTls(stream) => stream.flush(),
            #[cfg(feature = "use-rustls")]
            Self::Rustls(stream) => stream.flush(),
        }
    }
}

impl NoDelay for AutoStream {
    fn set_nodelay(&mut self, nodelay: bool) -> std::io::Result<()> {
        match self {
            #[cfg(feature = "use-native-tls")]
            Self::NativeTls(stream) => stream.set_nodelay(nodelay),
            #[cfg(feature = "use-rustls")]
            Self::Rustls(stream) => stream.set_nodelay(nodelay),
        }
    }
}

/// A wrapper that takes a plain TCP stream an encapsulates it in a TLS stream.
pub trait TlsWrapper {
    /// The wrapped stream to return.
    type Stream;

    /// Wrap the given stream with TLS, establishing a secured connection automatically while using
    /// the returned stream. If the given [`Mode`] is [`Mode::Plain`] then the returned stream
    /// should simply forward to the [`TcpStream`] and not apply any TLS.
    fn wrap_stream(&self, stream: TcpStream, domain: &str, mode: Mode) -> Result<Self::Stream>;
}

#[cfg(feature = "use-native-tls")]
mod native_tls {
    pub use native_tls::TlsStream;
    use native_tls::{HandshakeError as TlsHandshakeError, TlsConnector};
    use std::net::TcpStream;

    pub use crate::stream::Stream as StreamSwitcher;
    /// TCP stream switcher (plain/TLS).
    pub type AutoStream = StreamSwitcher<TcpStream, TlsStream<TcpStream>>;

    use crate::{error::Result, stream::Mode};

    /// A wrapper around a plain TCP stream that utilizes the `native-tls` crate to apply TLS to it.
    #[derive(Clone, Copy, Debug)]
    pub struct Wrapper;

    impl super::TlsWrapper for Wrapper {
        type Stream = super::AutoStream;

        fn wrap_stream(&self, stream: TcpStream, domain: &str, mode: Mode) -> Result<Self::Stream> {
            match mode {
                Mode::Plain => Ok(Self::Stream::NativeTls(StreamSwitcher::Plain(stream))),
                Mode::Tls => {
                    let connector = TlsConnector::builder().build()?;
                    connector
                        .connect(domain, stream)
                        .map_err(|e| match e {
                            TlsHandshakeError::Failure(f) => f.into(),
                            TlsHandshakeError::WouldBlock(_) => {
                                panic!("Bug: TLS handshake not blocked")
                            }
                        })
                        .map(StreamSwitcher::Tls)
                        .map(Self::Stream::NativeTls)
                }
            }
        }
    }
}

#[cfg(feature = "use-rustls")]
mod rustls {
    use rustls::ClientConfig;
    pub use rustls::{ClientSession, StreamOwned};
    use std::{net::TcpStream, sync::Arc};
    use webpki::DNSNameRef;

    pub use crate::stream::Stream as StreamSwitcher;
    /// TCP stream switcher (plain/TLS).
    pub type AutoStream = StreamSwitcher<TcpStream, StreamOwned<ClientSession, TcpStream>>;

    use super::TlsWrapper;
    use crate::{error::Result, stream::Mode};

    /// A wrapper around a plain TCP stream that utilizes the `rustls` crate to apply TLS to it.
    #[derive(Clone, Copy, Debug)]
    pub struct Wrapper;

    impl TlsWrapper for Wrapper {
        type Stream = super::AutoStream;

        fn wrap_stream(&self, stream: TcpStream, domain: &str, mode: Mode) -> Result<Self::Stream> {
            match mode {
                Mode::Plain => Ok(Self::Stream::Rustls(StreamSwitcher::Plain(stream))),
                Mode::Tls => {
                    let config = {
                        let mut config = ClientConfig::new();
                        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

                        Arc::new(config)
                    };
                    let domain = DNSNameRef::try_from_ascii_str(domain)?;
                    let client = ClientSession::new(&config, domain);
                    let stream = StreamOwned::new(client, stream);

                    Ok(Self::Stream::Rustls(StreamSwitcher::Tls(stream)))
                }
            }
        }
    }
}
