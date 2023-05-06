use alloc::string::ToString;
use core::ffi::c_void;

use embedded_io::ErrorKind;
use embedded_nal_async::{AddrType, Dns, IpAddr, TcpConnect};
use embedded_nal_async::heapless::String;
use embedded_nal_async::SocketAddr;
use psp::{dprintln, sys};
use psp::sys::in_addr;
use reqwless::Error;

use crate::util;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Socket(i32);

impl Socket {
    /// Creates a new socket
    ///
    /// ## Return Value
    /// [Socket] on success, Err on failure
    pub fn open() -> Result<Socket, ()> {
        let sock = unsafe {
            sys::sceNetInetSocket(netc::AF_INET as i32, netc::SOCK_STREAM, 0)
        };
        if sock < 0 {
            return Err(());
        } else {
            return Ok(Socket(sock));
        }
    }

    /// Connects this socket to a remote address
    ///
    /// ## Arguments
    /// * `remote` - remote address to connect to
    pub fn _connect(&self, remote: SocketAddr) -> Result<(), Error> {
        match remote {
            SocketAddr::V4(v4) => {
                let octets = v4.ip().octets();
                let sin_addr = u32::from_le_bytes(octets);
                let port = v4.port().to_be();
                dprintln!("Connecting to IP: {}, port: {}", v4.ip(), v4.port());

                let sockaddr_in = netc::sockaddr_in {
                    sin_len: core::mem::size_of::<netc::sockaddr_in>() as u8,
                    sin_family: netc::AF_INET,
                    sin_port: port,
                    sin_addr: in_addr(sin_addr),
                    sin_zero: [0u8; 8],
                };

                let sockaddr = unsafe { core::mem::transmute::<netc::sockaddr_in, netc::sockaddr>(sockaddr_in) };

                if unsafe { sys::sceNetInetConnect(self.0, &sockaddr, core::mem::size_of::<netc::sockaddr_in>() as u32) } < 0 {
                    unsafe { dprintln!("0x{:x}", sys::sceNetInetGetErrno()); }
                    return Err(Error::Network(ErrorKind::Other));
                } else {
                    return Ok(());
                }
            }
            SocketAddr::V6(_) => {
                return Err(Error::Network(ErrorKind::Other));
            }
        }
    }

    /// Reads data from this socket
    ///
    /// ## Arguments
    /// * `buf` - buffer to read data into
    ///
    /// ## Return Value
    /// [usize] number of bytes read on success, Err on failure
    fn _read(self, buf: &mut [u8]) -> Result<usize, ()> {
        let result = unsafe { sys::sceNetInetRecv(self.0, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if (result as i32) < 0 {
            return Err(());
        } else {
            return Ok(result);
        }
    }

    /// Writes data to this socket
    ///
    /// ## Arguments
    /// * `buf` - buffer to read data from
    ///
    /// ## Return Value
    /// [usize] number of bytes sent on success, Err on failure
    fn _write(&self, buf: &[u8]) -> Result<usize, ()> {
        let result = unsafe { sys::sceNetInetSend(self.0, buf.as_ptr() as *const c_void, buf.len(), 0) };
        if (result) < 0 {
            return Err(());
        } else {
            return Ok(result as usize);
        }
    }
}

impl embedded_io::Io for Socket {
    type Error = Error;
}

impl embedded_io::asynch::Read for Socket {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        return self._read(buf).map_err(|_| {
            return Error::Network(ErrorKind::Other);
        });
    }
}

impl embedded_io::asynch::Write for Socket {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        return self._write(buf).map_err(|_| {
            return Error::Network(ErrorKind::Other);
        });
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        return Ok(());
    }
}

/// Basically just a thing that can make a TCP connection to a remote address
pub struct TcpConnector;

impl TcpConnect for TcpConnector {
    type Error = Error;
    type Connection<'a> = Socket;

    async fn connect<'a>(&'a self, remote: SocketAddr) -> Result<Self::Connection<'a>, Self::Error> where Self: 'a {
        let socket = Socket::open().expect("Failed to open socket");
        socket._connect(remote).expect("Failed to connect");
        return Ok(socket);
    }
}

/// Wrapper around the PSP's DNS resolver
pub struct PSPDns;

impl Dns for PSPDns {
    type Error = Error;

    async fn get_host_by_name(&self, host: &str, addr_type: AddrType) -> Result<IpAddr, Self::Error> {
        if addr_type == AddrType::IPv6 {
            return Err(Error::Dns);
        }
        let hostname = host.to_string() + "\0";
        let rid = unsafe { util::create_resolver() }.expect("failed to create resolver");
        let address = unsafe { util::resolve_hostname(&rid, hostname.as_bytes()) }.map_err(|_| {
            dprintln!("Error resolving hostname {}", host);
            return Error::Dns;
        });
        unsafe { sys::sceNetResolverDelete(rid); }
        return address;
    }

    async fn get_host_by_address(&self, addr: IpAddr) -> Result<String<256>, Self::Error> {
        return Err(Error::Dns); // unnecessary for this
    }
}

#[allow(nonstandard_style)]
pub mod netc {
    pub use psp::sys::in_addr;
    pub use psp::sys::sockaddr;

    pub const AF_INET: u8 = 2;
    pub const SOCK_STREAM: i32 = 1;

    #[repr(C)]
    pub struct sockaddr_in {
        pub sin_len: u8,
        pub sin_family: u8,
        pub sin_port: u16,
        pub sin_addr: in_addr,
        pub sin_zero: [u8; 8],
    }
}