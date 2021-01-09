#![cfg(not(any(feature = "use-native-tls", feature = "use-rustls")))]
use std::net::TcpStream;

use crate::{
    error::{Error, Result},
    stream::Mode,
};

pub trait TlsWrapper {
    type Stream;

    fn wrap_stream(&self, stream: TcpStream, domain: &str, mode: Mode) -> Result<Self::Stream>;
}

#[derive(Clone, Copy, Debug)]
pub struct Wrapper;

impl TlsWrapper for Wrapper {
    type Stream = TcpStream;

    fn wrap_stream(
        &self,
        stream: TcpStream,
        _domain: &str,
        mode: Mode,
    ) -> Result<Self::Stream> {
        match mode {
            Mode::Plain => Ok(stream),
            Mode::Tls => Err(Error::Url("TLS support not compiled in.".into())),
        }
    }
}