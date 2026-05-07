use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    env,
    ffi::{CStr, CString, c_char},
    fmt,
    fs::File,
    io::{self, BufReader, IoSliceMut},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, RawFd},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use io_uring::{IoUring, cqueue, opcode, types};
use libc::{iovec, msghdr, sockaddr_in6, sockaddr_storage, socklen_t};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::unix::AsyncFd, runtime::Builder};

const DEFAULT_CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;
const LARGE_CONNECTION_WINDOW: u32 = 256 * 1024 * 1024;
const DEFAULT_STREAM_WINDOW: u32 = 64 * 1024 * 1024;
const LARGE_STREAM_WINDOW: u32 = 256 * 1024 * 1024;
const UDP_PAYLOAD_SIZE: u16 = 1500 - 40 - 8;
const ALPN: &[u8] = b"perf";
const BACKEND_SYSCALL: u32 = 0;
const BACKEND_IOURING: u32 = 1;
const IORING_ENTRIES: u32 = 256;
const IORING_SEND_TAG: u64 = 3;
const IORING_CANCEL_TAG: u64 = 4;
const IORING_PROVIDE_BUFFERS_TAG: u64 = 5;
const IORING_RECV_MULTI_TAG: u64 = 6;
const IORING_TAG_MASK: u64 = 0b111;
const IORING_RECVSEND_POLL_FIRST: u16 = 1;
const IORING_RECV_BUFFER_GROUP: u16 = 7;
const IORING_RECV_BUFFER_COUNT: u16 = 1024;
const IORING_RECV_BUFFER_SIZE: usize =
    128 + std::mem::size_of::<sockaddr_storage>() + UDP_PAYLOAD_SIZE as usize;
const AGGRESSIVE_INITIAL_CWND_PACKETS: u32 = 32;
const AGGRESSIVE_ACK_FREQUENCY_PACKETS: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetworkBackend {
    Syscall,
    Iouring,
}

impl NetworkBackend {
    fn from_ffi(value: u32) -> Result<Self> {
        match value {
            BACKEND_SYSCALL => Ok(Self::Syscall),
            BACKEND_IOURING => Ok(Self::Iouring),
            _ => Err(anyhow!("invalid Quinn network backend {value}")),
        }
    }
}

#[derive(Clone)]
struct ReceivedDatagram {
    addr: SocketAddr,
    bytes: Vec<u8>,
}

struct IouringState {
    ring: IoUring,
    recv_queue: Mutex<VecDeque<ReceivedDatagram>>,
    active_recvs: HashSet<u64>,
    active_sends: HashSet<u64>,
    error: Option<String>,
    shutdown: bool,
    recv_multi_msg: msghdr,
    recv_multi_buffers: Vec<u8>,
}

// The raw pointers inside `recv_multi_msg` are never dereferenced by Rust and
// the state is only accessed while held behind the mutex Quinn stores it in.
unsafe impl Send for IouringState {}

#[derive(Clone, Copy)]
struct BenchmarkProfiles {
    tls_verify_peer: bool,
    aggressive_congestion: bool,
    initial_cwnd_packets: u32,
    ack_frequency_packets: u32,
}

struct BoundUdpSocket {
    socket: std::net::UdpSocket,
    send_buffer_size: usize,
    recv_buffer_size: usize,
}

impl IouringState {
    fn new(ring: IoUring) -> Self {
        let mut recv_multi_msg: msghdr = unsafe { std::mem::zeroed() };
        recv_multi_msg.msg_namelen = std::mem::size_of::<sockaddr_storage>() as socklen_t;
        Self {
            ring,
            recv_queue: Mutex::new(VecDeque::new()),
            active_recvs: HashSet::new(),
            active_sends: HashSet::new(),
            error: None,
            shutdown: false,
            recv_multi_msg,
            recv_multi_buffers: vec![
                0;
                IORING_RECV_BUFFER_SIZE * usize::from(IORING_RECV_BUFFER_COUNT)
            ],
        }
    }

    fn stored_error(&self) -> Option<io::Error> {
        self.error
            .as_ref()
            .map(|message| io::Error::new(io::ErrorKind::Other, message.clone()))
    }

    fn store_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    fn provide_recv_buffers(&mut self, bid: u16, count: u16) -> io::Result<()> {
        let offset = usize::from(bid) * IORING_RECV_BUFFER_SIZE;
        let Some(end) = offset.checked_add(usize::from(count) * IORING_RECV_BUFFER_SIZE) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "io_uring provided buffer range overflow",
            ));
        };
        if end > self.recv_multi_buffers.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "io_uring provided buffer range exceeds pool",
            ));
        }

        let entry = opcode::ProvideBuffers::new(
            unsafe { self.recv_multi_buffers.as_mut_ptr().add(offset) },
            IORING_RECV_BUFFER_SIZE as i32,
            count,
            IORING_RECV_BUFFER_GROUP,
            bid,
        )
        .build()
        .user_data(IORING_PROVIDE_BUFFERS_TAG);
        push_entry(&mut self.ring, entry)
    }

    fn drain_setup_completions(&mut self) -> io::Result<()> {
        let completions: Vec<_> = self
            .ring
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result()))
            .collect();

        for (user_data, result) in completions {
            if user_data != IORING_PROVIDE_BUFFERS_TAG {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected io_uring setup completion",
                ));
            }
            if result < 0 {
                return Err(io::Error::from_raw_os_error(-result));
            }
        }

        Ok(())
    }

    fn arm_recv_multishot(&mut self, fd: RawFd) -> io::Result<()> {
        let entry = opcode::RecvMsgMulti::new(
            types::Fd(fd),
            &self.recv_multi_msg,
            IORING_RECV_BUFFER_GROUP,
        )
        .ioprio(IORING_RECVSEND_POLL_FIRST)
        .build()
        .user_data(IORING_RECV_MULTI_TAG);
        push_entry(&mut self.ring, entry)?;
        self.active_recvs.insert(IORING_RECV_MULTI_TAG);
        Ok(())
    }

    fn handle_recv_multishot(&mut self, fd: RawFd, result: i32, flags: u32) -> io::Result<()> {
        if !cqueue::more(flags) {
            self.active_recvs.remove(&IORING_RECV_MULTI_TAG);
        }

        if result < 0 {
            let error = io::Error::from_raw_os_error(-result);
            if (error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::ConnectionReset)
                && !self.shutdown
            {
            } else if error.kind() != io::ErrorKind::ConnectionReset
                && !expected_shutdown_completion(&error, self.shutdown)
            {
                return Err(error);
            }
        } else if result > 0 {
            let Some(bid) = cqueue::buffer_select(flags) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "io_uring multishot recv completed without selected buffer",
                ));
            };
            let offset = usize::from(bid) * IORING_RECV_BUFFER_SIZE;
            let available = usize::min(result as usize, IORING_RECV_BUFFER_SIZE);
            let buffer = &self.recv_multi_buffers[offset..offset + available];
            let parsed = types::RecvMsgOut::parse(buffer, &self.recv_multi_msg).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid io_uring recvmsg output",
                )
            })?;
            if parsed.is_name_data_truncated()
                || parsed.is_control_data_truncated()
                || parsed.is_payload_truncated()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated io_uring multishot datagram",
                ));
            }
            let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
            let name = parsed.name_data();
            let copy_len = usize::min(name.len(), std::mem::size_of::<sockaddr_storage>());
            unsafe {
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (&mut storage as *mut sockaddr_storage).cast(),
                    copy_len,
                );
            }
            let addr = addr_from_sockaddr(&storage)?;
            self.recv_queue.lock().unwrap().push_back(ReceivedDatagram {
                addr,
                bytes: parsed.payload_data().to_vec(),
            });
            self.provide_recv_buffers(bid, 1)?;
        }

        if !self.shutdown && !self.active_recvs.contains(&IORING_RECV_MULTI_TAG) {
            self.arm_recv_multishot(fd)?;
        }

        Ok(())
    }

    fn drain_completions(&mut self, fd: RawFd) -> io::Result<()> {
        let completions: Vec<_> = self
            .ring
            .completion()
            .map(|cqe| (cqe.user_data(), cqe.result(), cqe.flags()))
            .collect();

        for (user_data, result, flags) in completions {
            let (tag, ptr) = split_tagged_ptr(user_data);
            match tag {
                IORING_RECV_MULTI_TAG => {
                    self.handle_recv_multishot(fd, result, flags)?;
                }
                IORING_SEND_TAG => {
                    self.active_sends.remove(&user_data);
                    let op = unsafe { Box::from_raw(ptr.cast::<SendOp>()) };
                    if result < 0 {
                        let error = io::Error::from_raw_os_error(-result);
                        if error.kind() == io::ErrorKind::WouldBlock && !self.shutdown {
                            self.active_sends
                                .insert(submit_send(&mut self.ring, fd, op)?);
                        } else if !expected_shutdown_completion(&error, self.shutdown) {
                            return Err(error);
                        }
                    }
                }
                IORING_PROVIDE_BUFFERS_TAG => {
                    if result < 0 {
                        return Err(io::Error::from_raw_os_error(-result));
                    }
                }
                IORING_CANCEL_TAG => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown io_uring completion tag",
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
struct OwnedTransmit {
    destination: SocketAddr,
    contents: Vec<u8>,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[repr(C)]
pub struct QuinnFfiEndpointConfig {
    is_server: bool,
    address: *const u8,
    port: u16,
    cert_path: *const c_char,
    key_path: *const c_char,
    chain_path: *const c_char,
    backend: u32,
    tls_verify_peer: bool,
    aggressive_congestion: bool,
    initial_cwnd_packets: u32,
    ack_frequency_packets: u32,
}

pub struct QuinnFfiEndpoint {
    runtime: Arc<tokio::runtime::Runtime>,
    endpoint: quinn::Endpoint,
    send_buffer_size: usize,
    recv_buffer_size: usize,
}

pub struct QuinnFfiConnection {
    runtime: Arc<tokio::runtime::Runtime>,
    connection: quinn::Connection,
}

pub struct QuinnFfiBidiStream {
    runtime: Arc<tokio::runtime::Runtime>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

fn store_global_error(error: anyhow::Error) {
    let message = format!("{error:#}").replace('\0', " ");
    LAST_ERROR.with(|last_error| {
        *last_error.borrow_mut() =
            Some(CString::new(message).unwrap_or_else(|_| CString::new("quinn error").unwrap()));
    });
}

fn set_error(error: anyhow::Error) -> i32 {
    let message = format!("{error:#}").replace('\0', " ");
    let c_string = CString::new(message).unwrap_or_else(|_| CString::new("quinn error").unwrap());
    LAST_ERROR.with(|last_error| {
        *last_error.borrow_mut() = Some(c_string);
    });
    -1
}

fn ffi_status<F>(f: F) -> i32
where
    F: FnOnce() -> Result<()>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => set_error(error),
        Err(_) => set_error(anyhow!("panic in quinn ffi")),
    }
}

unsafe fn cstr(ptr: *const c_char) -> Result<String> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    Ok(CStr::from_ptr(ptr).to_str()?.to_owned())
}

unsafe fn socket_addr(address: *const u8, port: u16) -> Result<SocketAddr> {
    if address.is_null() {
        return Err(anyhow!("null address"));
    }

    let bytes = std::slice::from_raw_parts(address, 16);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(bytes);
    Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("open certificate {path}"))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse certificate {path}"))
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("open private key {path}"))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .with_context(|| format!("parse private key {path}"))?
        .context("no private key found")
}

fn transport_config(profiles: BenchmarkProfiles) -> quinn::TransportConfig {
    let (connection_window, stream_window) = window_sizes();
    let mut config = quinn::TransportConfig::default();
    config.max_idle_timeout(Some(Duration::from_millis(30_000).try_into().unwrap()));
    config.max_concurrent_bidi_streams(1u32.into());
    config.max_concurrent_uni_streams(0u32.into());
    config.stream_receive_window(stream_window.into());
    config.receive_window(connection_window.into());
    config.send_window(connection_window as u64);
    config.initial_mtu(UDP_PAYLOAD_SIZE);
    config.mtu_discovery_config(None);
    config.enable_segmentation_offload(false);
    let mut bbr_config = quinn::congestion::BbrConfig::default();
    if profiles.aggressive_congestion {
        let initial_cwnd_packets = profiles
            .initial_cwnd_packets
            .max(AGGRESSIVE_INITIAL_CWND_PACKETS);
        bbr_config.initial_window(u64::from(initial_cwnd_packets) * u64::from(UDP_PAYLOAD_SIZE));

        if profiles.ack_frequency_packets > 0 {
            let ack_frequency_packets = profiles
                .ack_frequency_packets
                .max(AGGRESSIVE_ACK_FREQUENCY_PACKETS);
            let mut ack_frequency = quinn::AckFrequencyConfig::default();
            ack_frequency.ack_eliciting_threshold(quinn::VarInt::from_u32(ack_frequency_packets));
            ack_frequency.max_ack_delay(Some(Duration::from_millis(25)));
            config.ack_frequency_config(Some(ack_frequency));
        }
    }
    config.congestion_controller_factory(Arc::new(bbr_config));
    config
}

fn window_sizes() -> (u32, u32) {
    if env::var("QUICPERF_WINDOW_PROFILE").as_deref() == Ok("large") {
        (LARGE_CONNECTION_WINDOW, LARGE_STREAM_WINDOW)
    } else {
        (DEFAULT_CONNECTION_WINDOW, DEFAULT_STREAM_WINDOW)
    }
}

fn udp_socket(addr: SocketAddr, nonblocking: bool) -> Result<BoundUdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    let (connection_window, _) = window_sizes();
    socket.set_send_buffer_size(connection_window as usize)?;
    socket.set_recv_buffer_size(connection_window as usize)?;
    let send_buffer_size = socket.send_buffer_size()?;
    let recv_buffer_size = socket.recv_buffer_size()?;
    socket.set_nonblocking(nonblocking)?;
    socket.bind(&addr.into())?;
    Ok(BoundUdpSocket {
        socket: socket.into(),
        send_buffer_size,
        recv_buffer_size,
    })
}

fn sockaddr_from_addr(addr: SocketAddr) -> io::Result<(sockaddr_storage, socklen_t)> {
    match addr {
        SocketAddr::V6(addr) => {
            let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
            let raw = sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut sockaddr_in6, raw);
            }
            Ok((storage, std::mem::size_of::<sockaddr_in6>() as socklen_t))
        }
        SocketAddr::V4(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv4 is unsupported by this IPv6-only benchmark socket",
        )),
    }
}

fn addr_from_sockaddr(storage: &sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET6 => {
            let raw = unsafe { &*(storage as *const _ as *const sockaddr_in6) };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)),
                u16::from_be(raw.sin6_port),
            ))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported socket family {family}"),
        )),
    }
}

fn tagged_ptr<T>(ptr: *mut T, tag: u64) -> u64 {
    debug_assert_eq!((ptr as u64) & IORING_TAG_MASK, 0);
    (ptr as u64) | tag
}

fn split_tagged_ptr(user_data: u64) -> (u64, *mut ()) {
    (
        user_data & IORING_TAG_MASK,
        (user_data & !IORING_TAG_MASK) as *mut (),
    )
}

struct SendOp {
    data: Vec<u8>,
    addr: sockaddr_storage,
    addr_len: socklen_t,
    iov: iovec,
    hdr: msghdr,
}

impl SendOp {
    fn boxed(transmit: OwnedTransmit) -> io::Result<Box<Self>> {
        let (addr, addr_len) = sockaddr_from_addr(transmit.destination)?;
        let mut op = Box::new(Self {
            data: transmit.contents,
            addr,
            addr_len,
            iov: iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            hdr: unsafe { std::mem::zeroed() },
        });
        op.refresh();
        Ok(op)
    }

    fn refresh(&mut self) {
        self.iov = iovec {
            iov_base: self.data.as_mut_ptr().cast(),
            iov_len: self.data.len(),
        };
        self.hdr = unsafe { std::mem::zeroed() };
        self.hdr.msg_name = (&mut self.addr as *mut sockaddr_storage).cast();
        self.hdr.msg_namelen = self.addr_len;
        self.hdr.msg_iov = &mut self.iov;
        self.hdr.msg_iovlen = 1;
    }
}

fn push_entry(ring: &mut IoUring, entry: io_uring::squeue::Entry) -> io::Result<()> {
    loop {
        let pushed = {
            let mut sq = ring.submission();
            unsafe { sq.push(&entry).is_ok() }
        };
        if pushed {
            return Ok(());
        }
        ring.submit()?;
    }
}

fn submit_send(ring: &mut IoUring, fd: RawFd, mut op: Box<SendOp>) -> io::Result<u64> {
    op.refresh();
    let ptr = Box::into_raw(op);
    let user_data = tagged_ptr(ptr, IORING_SEND_TAG);
    let entry = opcode::SendMsg::new(types::Fd(fd), unsafe { &(*ptr).hdr })
        .ioprio(IORING_RECVSEND_POLL_FIRST)
        .build()
        .user_data(user_data);
    if let Err(error) = push_entry(ring, entry) {
        unsafe {
            drop(Box::from_raw(ptr));
        }
        return Err(error);
    }
    Ok(user_data)
}

fn submit_cancel(ring: &mut IoUring, user_data: u64) -> io::Result<()> {
    let entry = opcode::AsyncCancel::new(user_data)
        .build()
        .user_data(IORING_CANCEL_TAG);
    push_entry(ring, entry)
}

fn expected_shutdown_completion(error: &io::Error, shutdown: bool) -> bool {
    shutdown && error.raw_os_error() == Some(libc::ECANCELED)
}

#[derive(Debug)]
struct IouringPollFd(RawFd);

impl AsRawFd for IouringPollFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

struct IouringUdpSocket {
    local_addr: SocketAddr,
    socket: std::net::UdpSocket,
    poll_fd: AsyncFd<IouringPollFd>,
    state: Arc<Mutex<IouringState>>,
}

impl fmt::Debug for IouringUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IouringUdpSocket")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl IouringUdpSocket {
    fn new(socket: std::net::UdpSocket) -> Result<Self> {
        socket.set_nonblocking(true)?;
        let local_addr = socket.local_addr()?;
        let fd = socket.as_raw_fd();
        let ring = IoUring::new(IORING_ENTRIES)?;
        let ring_fd = ring.as_raw_fd();
        let mut state = IouringState::new(ring);
        state.provide_recv_buffers(0, IORING_RECV_BUFFER_COUNT)?;
        state.ring.submit_and_wait(1)?;
        state.drain_setup_completions()?;
        state.arm_recv_multishot(fd)?;
        state.ring.submit()?;

        Ok(Self {
            local_addr,
            socket,
            poll_fd: AsyncFd::new(IouringPollFd(ring_fd))?,
            state: Arc::new(Mutex::new(state)),
        })
    }
}

impl Drop for IouringUdpSocket {
    fn drop(&mut self) {
        let fd = self.socket.as_raw_fd();
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.shutdown = true;
        let active: Vec<_> = state
            .active_recvs
            .iter()
            .chain(state.active_sends.iter())
            .copied()
            .collect();
        for user_data in active {
            let _ = submit_cancel(&mut state.ring, user_data);
        }
        let _ = state.ring.submit();

        for _ in 0..32 {
            if state.active_recvs.is_empty() && state.active_sends.is_empty() {
                break;
            }
            if state.ring.submit_and_wait(1).is_err() {
                break;
            }
            if state.drain_completions(fd).is_err() {
                break;
            }
        }
    }
}

impl quinn::AsyncUdpSocket for IouringUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn quinn::UdpSender>> {
        Box::pin(IouringUdpSender {
            fd: self.socket.as_raw_fd(),
            state: self.state.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut TaskContext,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let fd = self.socket.as_raw_fd();
        loop {
            {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = state.stored_error() {
                    return Poll::Ready(Err(error));
                }
                if let Err(error) = state.drain_completions(fd) {
                    state.store_error(error.to_string());
                    return Poll::Ready(Err(error));
                }

                {
                    let mut queue = state.recv_queue.lock().unwrap();
                    if !queue.is_empty() {
                        let mut count = 0;
                        while count < bufs.len() && count < meta.len() {
                            let Some(datagram) = queue.pop_front() else {
                                break;
                            };
                            if datagram.bytes.len() > bufs[count].len() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "received datagram exceeds Quinn buffer",
                                )));
                            }
                            bufs[count][..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
                            let mut recv_meta = quinn::udp::RecvMeta::default();
                            recv_meta.addr = datagram.addr;
                            recv_meta.len = datagram.bytes.len();
                            recv_meta.stride = datagram.bytes.len();
                            recv_meta.ecn = None;
                            recv_meta.dst_ip = None;
                            meta[count] = recv_meta;
                            count += 1;
                        }

                        return Poll::Ready(Ok(count));
                    }
                }
                if let Err(error) = state.ring.submit() {
                    state.store_error(error.to_string());
                    return Poll::Ready(Err(error));
                }
            }

            match self.poll_fd.poll_read_ready(cx) {
                Poll::Ready(Ok(mut guard)) => {
                    guard.clear_ready();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

struct IouringUdpSender {
    fd: RawFd,
    state: Arc<Mutex<IouringState>>,
}

impl fmt::Debug for IouringUdpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IouringUdpSender")
            .field("fd", &self.fd)
            .finish_non_exhaustive()
    }
}

impl quinn::UdpSender for IouringUdpSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &quinn::udp::Transmit<'_>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        if state.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "io_uring socket is shut down",
            )));
        }
        if let Some(error) = state.stored_error() {
            return Poll::Ready(Err(error));
        }
        if transmit.segment_size.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "segmented Quinn transmits are disabled for this harness",
            )));
        }

        if let Err(error) = state.drain_completions(self.fd) {
            state.store_error(error.to_string());
            return Poll::Ready(Err(error));
        }
        let op = match SendOp::boxed(OwnedTransmit {
            destination: transmit.destination,
            contents: transmit.contents.to_vec(),
        }) {
            Ok(op) => op,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let user_data = match submit_send(&mut state.ring, self.fd, op) {
            Ok(user_data) => user_data,
            Err(error) => return Poll::Ready(Err(error)),
        };
        state.active_sends.insert(user_data);
        match state.ring.submit() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

fn make_server_config(
    cert_path: &str,
    key_path: &str,
    profiles: BenchmarkProfiles,
) -> Result<quinn::ServerConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut crypto = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(load_certs(cert_path)?, load_key(key_path)?)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    config.transport = Arc::new(transport_config(profiles));
    Ok(config)
}

fn make_client_config(
    chain_path: &str,
    profiles: BenchmarkProfiles,
) -> Result<quinn::ClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut crypto = if profiles.tls_verify_peer {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(chain_path)? {
            roots.add(cert)?;
        }
        ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    config.transport_config(Arc::new(transport_config(profiles)));
    Ok(config)
}

unsafe fn output_handle<'a, T>(out: *mut *mut T) -> Result<&'a mut *mut T> {
    out.as_mut().context("null output handle")
}

unsafe fn ffi_slice<'a>(data: *const u8, len: usize) -> Result<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(anyhow!("null input buffer"));
    }
    Ok(std::slice::from_raw_parts(data, len))
}

unsafe fn ffi_slice_mut<'a>(data: *mut u8, len: usize) -> Result<&'a mut [u8]> {
    if len == 0 {
        return Ok(&mut []);
    }
    if data.is_null() {
        return Err(anyhow!("null output buffer"));
    }
    Ok(std::slice::from_raw_parts_mut(data, len))
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_endpoint_new(
    config: *const QuinnFfiEndpointConfig,
) -> *mut QuinnFfiEndpoint {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<QuinnFfiEndpoint> {
        let config = config.as_ref().context("null endpoint config")?;
        let runtime = Arc::new(Builder::new_current_thread().enable_all().build()?);
        let bind_addr = socket_addr(config.address, config.port)?;
        let backend = NetworkBackend::from_ffi(config.backend)?;
        let profiles = BenchmarkProfiles {
            tls_verify_peer: config.tls_verify_peer,
            aggressive_congestion: config.aggressive_congestion,
            initial_cwnd_packets: config.initial_cwnd_packets,
            ack_frequency_packets: config.ack_frequency_packets,
        };

        let (endpoint, send_buffer_size, recv_buffer_size) = {
            let _guard = runtime.enter();
            let quinn_runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
            let bound_socket = udp_socket(bind_addr, true)?;
            let send_buffer_size = bound_socket.send_buffer_size;
            let recv_buffer_size = bound_socket.recv_buffer_size;
            let socket = bound_socket.socket;

            let make_endpoint = |server_config| -> Result<quinn::Endpoint> {
                let endpoint_config = quinn::EndpointConfig::default();
                match backend {
                    NetworkBackend::Syscall => Ok(quinn::Endpoint::new(
                        endpoint_config,
                        server_config,
                        socket,
                        quinn_runtime,
                    )?),
                    NetworkBackend::Iouring => Ok(quinn::Endpoint::new_with_abstract_socket(
                        endpoint_config,
                        server_config,
                        Box::new(IouringUdpSocket::new(socket)?),
                        quinn_runtime,
                    )?),
                }
            };

            if config.is_server {
                let cert_path = cstr(config.cert_path)?;
                let key_path = cstr(config.key_path)?;
                (
                    make_endpoint(Some(make_server_config(&cert_path, &key_path, profiles)?))?,
                    send_buffer_size,
                    recv_buffer_size,
                )
            } else {
                let chain_path = cstr(config.chain_path)?;
                let endpoint = make_endpoint(None)?;
                endpoint.set_default_client_config(make_client_config(&chain_path, profiles)?);
                (endpoint, send_buffer_size, recv_buffer_size)
            }
        };

        Ok(QuinnFfiEndpoint {
            runtime,
            endpoint,
            send_buffer_size,
            recv_buffer_size,
        })
    }));

    match result {
        Ok(Ok(endpoint)) => Box::into_raw(Box::new(endpoint)),
        Ok(Err(error)) => {
            store_global_error(error);
            std::ptr::null_mut()
        }
        Err(_) => {
            store_global_error(anyhow!("panic in quinn ffi endpoint creation"));
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_endpoint_free(endpoint: *mut QuinnFfiEndpoint) {
    if !endpoint.is_null() {
        drop(Box::from_raw(endpoint));
    }
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_endpoint_send_buffer_size(
    endpoint: *const QuinnFfiEndpoint,
) -> usize {
    endpoint
        .as_ref()
        .map_or(0, |endpoint| endpoint.send_buffer_size)
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_endpoint_recv_buffer_size(
    endpoint: *const QuinnFfiEndpoint,
) -> usize {
    endpoint
        .as_ref()
        .map_or(0, |endpoint| endpoint.recv_buffer_size)
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_client_connect(
    endpoint: *mut QuinnFfiEndpoint,
    address: *const u8,
    port: u16,
    connection_out: *mut *mut QuinnFfiConnection,
) -> i32 {
    ffi_status(|| {
        let endpoint = endpoint.as_ref().context("null endpoint")?;
        let out = output_handle(connection_out)?;
        *out = std::ptr::null_mut();
        let server_addr = socket_addr(address, port)?;
        let connection = endpoint.runtime.block_on(async {
            endpoint
                .endpoint
                .connect(server_addr, "localhost")?
                .await
                .context("client handshake")
        })?;
        *out = Box::into_raw(Box::new(QuinnFfiConnection {
            runtime: endpoint.runtime.clone(),
            connection,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_server_accept(
    endpoint: *mut QuinnFfiEndpoint,
    connection_out: *mut *mut QuinnFfiConnection,
) -> i32 {
    ffi_status(|| {
        let endpoint = endpoint.as_ref().context("null endpoint")?;
        let out = output_handle(connection_out)?;
        *out = std::ptr::null_mut();
        let connection = endpoint.runtime.block_on(async {
            let incoming = endpoint
                .endpoint
                .accept()
                .await
                .context("accept connection")?;
            incoming.await.context("server handshake")
        })?;
        *out = Box::into_raw(Box::new(QuinnFfiConnection {
            runtime: endpoint.runtime.clone(),
            connection,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_connection_free(connection: *mut QuinnFfiConnection) {
    if !connection.is_null() {
        drop(Box::from_raw(connection));
    }
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_connection_close(connection: *mut QuinnFfiConnection) {
    if let Some(connection) = connection.as_ref() {
        connection.connection.close(0u32.into(), b"done");
    }
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_connection_closed(connection: *mut QuinnFfiConnection) -> i32 {
    ffi_status(|| {
        let connection = connection.as_ref().context("null connection")?;
        connection.runtime.block_on(async {
            let _ = connection.connection.closed().await;
            Ok(())
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_connection_open_bi(
    connection: *mut QuinnFfiConnection,
    stream_out: *mut *mut QuinnFfiBidiStream,
) -> i32 {
    ffi_status(|| {
        let connection = connection.as_ref().context("null connection")?;
        let out = output_handle(stream_out)?;
        *out = std::ptr::null_mut();
        let (send, recv) = connection.runtime.block_on(async {
            connection
                .connection
                .open_bi()
                .await
                .context("open bidi stream")
        })?;
        *out = Box::into_raw(Box::new(QuinnFfiBidiStream {
            runtime: connection.runtime.clone(),
            send,
            recv,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_connection_accept_bi(
    connection: *mut QuinnFfiConnection,
    stream_out: *mut *mut QuinnFfiBidiStream,
) -> i32 {
    ffi_status(|| {
        let connection = connection.as_ref().context("null connection")?;
        let out = output_handle(stream_out)?;
        *out = std::ptr::null_mut();
        let (send, recv) = connection.runtime.block_on(async {
            connection
                .connection
                .accept_bi()
                .await
                .context("accept bidi stream")
        })?;
        *out = Box::into_raw(Box::new(QuinnFfiBidiStream {
            runtime: connection.runtime.clone(),
            send,
            recv,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_bidi_stream_free(stream: *mut QuinnFfiBidiStream) {
    if !stream.is_null() {
        drop(Box::from_raw(stream));
    }
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_stream_send_all(
    stream: *mut QuinnFfiBidiStream,
    data: *const u8,
    len: usize,
) -> i32 {
    ffi_status(|| {
        let stream = stream.as_mut().context("null stream")?;
        let data = ffi_slice(data, len)?;
        stream
            .runtime
            .block_on(async { stream.send.write_all(data).await.context("stream send") })
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_stream_recv_exact(
    stream: *mut QuinnFfiBidiStream,
    data: *mut u8,
    len: usize,
) -> i32 {
    ffi_status(|| {
        let stream = stream.as_mut().context("null stream")?;
        let data = ffi_slice_mut(data, len)?;
        stream
            .runtime
            .block_on(async { stream.recv.read_exact(data).await.context("stream recv") })
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_stream_recv_finish(stream: *mut QuinnFfiBidiStream) -> i32 {
    ffi_status(|| {
        let stream = stream.as_mut().context("null stream")?;
        stream.runtime.block_on(async {
            while stream.recv.read_chunk(usize::MAX, false).await?.is_some() {}
            Ok(())
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_stream_finish(stream: *mut QuinnFfiBidiStream) -> i32 {
    ffi_status(|| {
        let stream = stream.as_mut().context("null stream")?;
        stream.send.finish().context("stream finish")
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_stream_drain_for(
    stream: *mut QuinnFfiBidiStream,
    timeout_ms: u32,
) -> i32 {
    ffi_status(|| {
        let stream = stream.as_mut().context("null stream")?;
        stream.runtime.block_on(async {
            let _ = tokio::time::timeout(
                Duration::from_millis(timeout_ms as u64),
                stream.send.stopped(),
            )
            .await;
            Ok(())
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn quinn_ffi_last_error() -> *const c_char {
    LAST_ERROR.with(|last_error| {
        last_error
            .borrow()
            .as_ref()
            .map(|message| message.as_ptr())
            .unwrap_or(std::ptr::null())
    })
}
