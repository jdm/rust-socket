// Last built with rust commit 9c98d0f99b44e1c57bdd60881518140e2593a5a4
import result = result::Result;
import core::rand;

export sockaddr, getaddrinfo, bind_socket, socket_handle, connect, listen, accept,
       send, recv, sendto, recvfrom, setsockopt, enablesockopt, disablesockopt,
       htons, htonl, ntohs, ntohl, sockaddr4_in, sockaddr6_in, sockaddr_basic,
       sockaddr_storage, inet_ntop, send_buf, create_socket;
export SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SO_DEBUG, SO_ACCEPTCONN, SO_REUSEADDR, 
       SO_KEEPALIVE, SO_DONTROUTE, SO_BROADCAST, SO_LINGER, SO_OOBINLINE, SO_SNDBUF, 
       SO_RCVBUF, SO_SNDLOWAT, SO_RCVLOWAT, SO_SNDTIMEO, SO_RCVTIMEO, SO_ERROR, SO_TYPE,
       AF_UNSPEC, AF_UNIX, AF_INET, AF_INET6, AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST,
       AI_NUMERICSERV, INET6_ADDRSTRLEN;
       
type c_str = *libc::c_char;

#[nolink]
extern mod c {
    fn socket(af: libc::c_int, typ: libc::c_int, protocol: libc::c_int) -> libc::c_int;
    fn bind(s: libc::c_int, name: *sockaddr_storage, namelen: socklen_t) -> libc::c_int;
    fn connect(s: libc::c_int, name: *sockaddr_storage, namelen: socklen_t) -> libc::c_int;
    fn listen(s: libc::c_int, backlog: libc::c_int) -> libc::c_int;
    fn accept(sockfd: libc::c_int, name: *sockaddr_storage, namelen: *socklen_t) -> libc::c_int;
    fn send(sd: libc::c_int, buf: *u8, len: libc::c_int, flags: libc::c_int) -> libc::c_int;
    fn recv(sd: libc::c_int, buf: *u8, len: libc::c_int, flags: libc::c_int) -> libc::c_int;
    fn sendto(s: libc::c_int, msg: *u8, len: libc::c_int, flags: libc::c_int,
              to: *sockaddr_storage, tolen: socklen_t) -> libc::c_int;
    fn recvfrom(s: libc::c_int, msg: *u8, len: libc::c_int, flags: libc::c_int,
                from: *sockaddr_storage, fromlen: *socklen_t) -> libc::c_int;
    fn close(s: libc::c_int);
    fn setsockopt(sockfd: libc::c_int, level: libc::c_int, optname: libc::c_int,
                  optval: *u8, optlen: socklen_t) -> libc::c_int;
    fn getsockopt(sockfd: libc::c_int, level: libc::c_int, optname: libc::c_int,
                  optval: *u8, optlen: socklen_t) -> libc::c_int;

    fn htons(hostshort: u16) -> u16;
    fn htonl(hostlong: u32) -> u32;
    fn ntohs(netshort: u16) -> u16;
    fn ntohl(netlong: u32) -> u32;

    fn inet_ntop(af: libc::c_int, src: *libc::c_void, dst: *u8, size: socklen_t) -> c_str;
    fn inet_pton(af: libc::c_int, src: c_str, dst: *libc::c_void) -> libc::c_int;

    fn gai_strerror(ecode: libc::c_int) -> c_str;
    fn getaddrinfo(node: c_str, service: c_str, hints: *addrinfo, res: **addrinfo) -> libc::c_int;
    fn freeaddrinfo(ai: *addrinfo);
}

const SOCK_STREAM: libc::c_int = 1_i32;
const SOCK_DGRAM: libc::c_int = 2_i32;
const SOCK_RAW: libc::c_int = 3_i32;

const SOL_SOCKET: libc::c_int = 0xffff_i32;

const SO_DEBUG: libc::c_int = 0x0001_i32;             // turn on debugging info recording
const SO_ACCEPTCONN: libc::c_int = 0x0002_i32;   // socket has had listen()
const SO_REUSEADDR: libc::c_int = 0x0004_i32;   // allow local address reuse
const SO_KEEPALIVE: libc::c_int = 0x0008_i32;   // keep connections alive
const SO_DONTROUTE: libc::c_int = 0x0010_i32;   // just use interface addresses
const SO_BROADCAST: libc::c_int = 0x0020_i32;   // permit sending of broadcast msgs
const SO_LINGER: libc::c_int = 0x1080_i32;   // linger on close if data present (in seconds)
const SO_OOBINLINE: libc::c_int = 0x0100_i32;   // leave received OOB data in line
const SO_SNDBUF: libc::c_int = 0x1001_i32;   // send buffer size
const SO_RCVBUF: libc::c_int = 0x1002_i32;   // receive buffer size
const SO_SNDLOWAT: libc::c_int = 0x1003_i32;   // send low-water mark
const SO_RCVLOWAT: libc::c_int = 0x1004_i32;   // receive low-water mark
const SO_SNDTIMEO: libc::c_int = 0x1005_i32;   // send timeout
const SO_RCVTIMEO: libc::c_int = 0x1006_i32;   // receive timeout
const SO_ERROR: libc::c_int = 0x1007_i32;   // get error status and clear
const SO_TYPE	: libc::c_int = 0x1008_i32;   // get socket type
// TODO: there are a bunch of Linux specific socket options that should be added

const AF_UNSPEC: libc::c_int = 0_i32;
const AF_UNIX: libc::c_int = 1_i32;
const AF_INET: libc::c_int = 2_i32;
const AF_INET6: libc::c_int = 30_i32;

const AI_PASSIVE: libc::c_int = 0x0001_i32;
const AI_CANONNAME: libc::c_int = 0x0002_i32;
const AI_NUMERICHOST: libc::c_int = 0x0004_i32;
const AI_NUMERICSERV: libc::c_int = 0x1000_i32;

const INET6_ADDRSTRLEN: u32 = 46;

// Type names are not CamelCase to match the C versions.
type socklen_t = u32;    // 32-bit on Mac (__darwin_socklen_t in _types.h) and Ubuntu Linux (__socklen_t in types.h)
type x = u8;

type sockaddr_basic = {sin_family: i16, padding: (x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x)};
type sockaddr4_in = {sin_family: i16, sin_port: u16, sin_addr: in4_addr,
                     sin_zero: (x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x)};
type in4_addr = {s_addr: libc::c_uint};
type sockaddr6_in = {sin6_family: u16, sin6_port: u16, sin6_flowinfo: u32, sin6_addr: in6_addr, sin6_scope_id: u32};
type in6_addr = {s6_addr: (x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x)};

enum sockaddr {
    unix(sockaddr_basic),
    ipv4(sockaddr4_in),
    ipv6(sockaddr6_in)
}

// TODO: think something like [u8]/128 is supported now, but not sure how to initialize it.
//
// On both Linux and Mac this struct is supposed to be 128 bytes. Rather than wrestle with
// alignment we simply make contents 128 bytes which should be fine because the C API
// always uses pointers to sockaddr_storage.
#[cfg(target_os = "freebsd")]
#[cfg(target_os = "macos")]
type sockaddr_storage = {ss_len: u8, ss_family: u8, contents: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8)};

#[cfg(target_os = "linux")]
type sockaddr_storage = {ss_family: libc::c_ushort, contents: (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8)};

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "win32")]
#[cfg(target_os = "macos")]
type addrinfo = {ai_flags: libc::c_int,
                 ai_family: libc::c_int,
                 ai_socktype: libc::c_int,
                 ai_protocol: libc::c_int,
                 ai_addrlen: socklen_t,
                 ai_canonname: *u8,
                 ai_addr: *sockaddr_storage,
                 ai_next: *u8}; //XXX ai_next should be *addrinfo
#[cfg(target_os = "linux")]
type addrinfo = {ai_flags: libc::c_int,
                 ai_family: libc::c_int,
                 ai_socktype: libc::c_int,
                 ai_protocol: libc::c_int,
                 ai_addrlen: socklen_t,
                 ai_addr: *sockaddr_storage,
                 ai_canonname: *u8,
                 ai_next: *u8}; //XXX ai_next should be *addrinfo

fn sockaddr_to_string(saddr: &sockaddr) -> ~str
{
    unsafe
    {
        match *saddr
        {
            unix(_basic) =>
            {
                ~"unix"		// TODO: is sockaddr_basic supposed to be a sockaddr_un?
            }
            ipv4(addr4) =>
            {
                let buffer = vec::from_elem(INET6_ADDRSTRLEN as uint + 1u, 0u8);
                c::inet_ntop(
                    AF_INET,
                    unsafe::reinterpret_cast(&ptr::addr_of(addr4.sin_addr)),
                    vec::unsafe::to_ptr(buffer),
                    INET6_ADDRSTRLEN);
                str::unsafe::from_buf(vec::unsafe::to_ptr(buffer))
            }
            ipv6(addr6) =>
            {
                let buffer = vec::from_elem(INET6_ADDRSTRLEN as uint + 1u, 0u8);
                c::inet_ntop(
                    AF_INET6,
                    unsafe::reinterpret_cast(&ptr::addr_of(addr6.sin6_addr)),
                    vec::unsafe::to_ptr(buffer),
                    INET6_ADDRSTRLEN);
                str::unsafe::from_buf(vec::unsafe::to_ptr(buffer))
            }
        }
    }
}

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "macos")]
fn mk_default_storage() -> sockaddr_storage {
    {ss_len: 0u8, ss_family: 0u8, contents: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)}
}

#[cfg(target_os = "linux")]
fn mk_default_storage() -> sockaddr_storage {
    {ss_family: 0, contents: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)}
}

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "win32")]
#[cfg(target_os = "macos")]
fn mk_default_addrinfo() -> addrinfo {
    {ai_flags: 0i32, ai_family: 0i32, ai_socktype: 0i32, ai_protocol: 0i32, ai_addrlen: 0u32,
     ai_canonname: ptr::null(), ai_addr: ptr::null(), ai_next: ptr::null()}
}

#[cfg(target_os = "linux")]
fn mk_default_addrinfo() -> addrinfo {
    {ai_flags: 0i32, ai_family: 0i32, ai_socktype: 0i32, ai_protocol: 0i32, ai_addrlen: 0u32,
     ai_addr: ptr::null(), ai_canonname: ptr::null(), ai_next: ptr::null()}
}

fn getaddrinfo(host: &str, port: u16, f: fn(addrinfo) -> bool) -> Option<~str> unsafe {
    let hints = {ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ..mk_default_addrinfo()};
    let servinfo: *addrinfo = ptr::null();
    let s_port = #fmt["%u", port as uint];
    let mut result = option::None;
    do str::as_c_str(host) |host| {
        do str::as_c_str(s_port) |port| {
            let status = c::getaddrinfo(host, port, ptr::addr_of(hints),
                                        ptr::addr_of(servinfo));
            if status == 0i32 {
                let mut p = servinfo;
                while p != ptr::null() {
                    if !f(*p) {
                        break;
                    }
                    p = unsafe::reinterpret_cast(&(*p).ai_next);
                }
            } else {
                warn!("getaddrinfo returned %? (%s)", status, str::unsafe::from_c_str(c::gai_strerror(status)));
                result = option::Some(~"getaddrinfo failed");
            }
        }
    }
    c::freeaddrinfo(servinfo); 
    result
}

fn inet_ntop(address: &addrinfo) -> ~str unsafe {
    let buffer = vec::from_elem(INET6_ADDRSTRLEN as uint + 1u, 0u8);
    c::inet_ntop(address.ai_family,
        if address.ai_family == AF_INET {
            let addr: *sockaddr4_in = unsafe::reinterpret_cast(&address.ai_addr);
            unsafe::reinterpret_cast(&ptr::addr_of((*addr).sin_addr))
        } else {
            let addr: *sockaddr6_in = unsafe::reinterpret_cast(&address.ai_addr);
            unsafe::reinterpret_cast(&ptr::addr_of((*addr).sin6_addr))
        },
        vec::unsafe::to_ptr(buffer), INET6_ADDRSTRLEN);
    
    str::unsafe::from_buf(vec::unsafe::to_ptr(buffer))
}

// TODO: there is no portable way to get errno from rust so, for now, we'll just write them to stderr
// See #2269.
fn log_err(mesg: &str)
{
    do str::as_c_str(mesg) |buffer| {libc::perror(buffer)};
}

// TODO: Isn't socket::socket_handle redundant?
struct socket_handle {
	sockfd: libc::c_int,
	drop {c::close(self.sockfd);}
}

fn socket_handle(x: libc::c_int) -> socket_handle
{
    socket_handle {sockfd: x}
}

fn bind_socket(host: &str, port: u16) -> result<@socket_handle, ~str> unsafe {
    let err = for getaddrinfo(host, port) |ai| {
        if ai.ai_family == AF_INET || ai.ai_family == AF_INET6    // TODO: should do something to support AF_UNIX
        {
            let sockfd = c::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if sockfd != -1_i32 {
                let val = 1;
                let _ = c::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,    // this shouldn't be critical so we'll ignore errors from it
                                      unsafe::reinterpret_cast(&ptr::addr_of(val)),
                                      sys::size_of::<int>() as socklen_t);
                
                if c::bind(sockfd, ai.ai_addr, ai.ai_addrlen) == -1_i32 {
                    c::close(sockfd);
                } else {
                    debug!("   bound to socket %?", sockfd);
                    return result::Ok(@socket_handle(sockfd));
                }
            } else {
                log_err(#fmt["socket(%s) error", inet_ntop(&ai)]);
            }
        }
    };
    match err
    {
    	    option::Some(mesg)  => {result::Err(copy(mesg))}
         option::None               => {result::Err(~"bind failed to find an address")}
    }
}

fn connect(host: &str, port: u16) -> result<@socket_handle, ~str> {
    info!("connecting to %s:%?", host, port);
    let err = for getaddrinfo(host, port) |ai| {
        if ai.ai_family == AF_INET || ai.ai_family == AF_INET6    // TODO: should do something to support AF_UNIX
        {
            debug!("   trying %s", inet_ntop(&ai));
            let sockfd = c::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
            if sockfd != -1_i32 {
                if c::connect(sockfd, ai.ai_addr, ai.ai_addrlen) == -1_i32 {
                    c::close(sockfd);
                } else {
                    info!("   connected to socket %?", sockfd);
                    return result::Ok(@socket_handle(sockfd));
                }
            } else {
                log_err(#fmt["socket(%s, %?) error", host, port]);
            }
        }
    };
    match err
    {
    	    option::Some(mesg)  => {result::Err(copy(mesg))}
         option::None            => {result::Err(~"connect failed to find an address")}
    }
}

fn listen(sock: @socket_handle, backlog: i32) -> result<@socket_handle, ~str> {
    if c::listen(sock.sockfd, backlog) == -1_i32 {
        log_err(~"listen error");
        result::Err(~"listen failed")
    } else {
        result::Ok(sock)
    }
}

// Returns a fd to allow multi-threaded servers to send the fd to a task.
fn accept(sock: @socket_handle) -> result<{fd: libc::c_int, remote_addr: ~str}, ~str> unsafe {
    info!("accepting with socket %?", sock.sockfd);
    let addr = mk_default_storage();
    let unused: socklen_t = sys::size_of::<sockaddr>() as socklen_t;
    let fd = c::accept(sock.sockfd, ptr::addr_of(addr), ptr::addr_of(unused));
    
    if fd == -1_i32 {
        log_err(#fmt["accept error"]);
        result::Err(~"accept failed")
    } else {
        let their_addr = if addr.ss_family as u8 == AF_INET as u8 {
                       ipv4(*(ptr::addr_of(addr) as *sockaddr4_in))
                   } else if addr.ss_family as u8 == AF_INET6 as u8 {
                       ipv6(*(ptr::addr_of(addr) as *sockaddr6_in))
                   } else {
                       unix(*(ptr::addr_of(addr) as *sockaddr_basic))
                   };
        info!("accepted socket %? (%s)", fd, sockaddr_to_string(&their_addr));
        result::Ok({fd: fd, remote_addr: sockaddr_to_string(&their_addr)})
    }
}

fn send(sock: @socket_handle, buf: &[u8]) -> result<uint, ~str> unsafe {
    let amt = c::send(sock.sockfd, vec::unsafe::to_ptr_slice(buf),
                      vec::len(buf) as libc::c_int, 0i32);
    if amt == -1_i32 {
        log_err(#fmt["send error"]);
        result::Err(~"send failed")
    } else {
        result::Ok(amt as uint)
    }
}

// Useful for sending str data (where you want to use as_buf instead of as_buffer).
fn send_buf(sock: @socket_handle, buf: *u8, len: uint) -> result<uint, ~str> unsafe {
    let amt = c::send(sock.sockfd, buf, len as libc::c_int, 0i32);
    if amt == -1_i32 {
        log_err(#fmt["send error"]);
        result::Err(~"send_buf failed")
    } else {
        result::Ok(amt as uint)
    }
}

fn recv(sock: @socket_handle, len: uint) -> result<{buffer: ~[u8], bytes: uint}, ~str> unsafe {
    let buf = vec::from_elem(len + 1u, 0u8);
    let bytes = c::recv(sock.sockfd, vec::unsafe::to_ptr(buf), len as libc::c_int, 0i32);
    if bytes == -1_i32 {
        log_err(#fmt["recv error"]);
        result::Err(~"recv failed")
    } else {
        result::Ok({buffer: buf, bytes: bytes as uint})
    }
}

fn sendto(sock: @socket_handle, buf: &[u8], to: &sockaddr)
    -> result<uint, ~str> unsafe {
    let (to_saddr, to_len) = match *to {
      ipv4(s)  => { (*(ptr::addr_of(s) as *sockaddr_storage),
                 sys::size_of::<sockaddr4_in>()) }
      ipv6(s)  => { (*(ptr::addr_of(s) as *sockaddr_storage),
                 sys::size_of::<sockaddr6_in>()) }
      unix(s)  => { (*(ptr::addr_of(s) as *sockaddr_storage),
                 sys::size_of::<sockaddr_basic>()) }
    };
    let amt = c::sendto(sock.sockfd, vec::unsafe::to_ptr_slice(buf), vec::len(buf) as libc::c_int, 0i32,
                        ptr::addr_of(to_saddr), to_len as u32);
    if amt == -1_i32 {
        log_err(#fmt["sendto error"]);
        result::Err(~"sendto failed")
    } else {
        result::Ok(amt as uint)
    }
}

fn recvfrom(sock: @socket_handle, len: uint)
    -> result<(~[u8], uint, sockaddr), ~str> unsafe {
    let from_saddr = mk_default_storage();
    let unused: socklen_t = 0u32;
    let buf = vec::from_elem(len + 1u, 0u8);
    let amt = c::recvfrom(sock.sockfd, vec::unsafe::to_ptr(buf), vec::len(buf) as libc::c_int, 0i32,
                          ptr::addr_of(from_saddr), ptr::addr_of(unused));
    if amt == -1_i32 {
        log_err(#fmt["recvfrom error"]);
        result::Err(~"recvfrom failed")
    } else {
        result::Ok((buf, amt as uint,
                   if from_saddr.ss_family as u8 == AF_INET as u8 {
                       ipv4(*(ptr::addr_of(from_saddr) as *sockaddr4_in))
                   } else if from_saddr.ss_family as u8 == AF_INET6 as u8 {
                       ipv6(*(ptr::addr_of(from_saddr) as *sockaddr6_in))
                   } else {
                       unix(*(ptr::addr_of(from_saddr) as *sockaddr_basic))
                   }))
    }
}

fn setsockopt(sock: @socket_handle, option: int, value: int)
    -> result<libc::c_int, ~str> unsafe {
    let val = value;
    let r = c::setsockopt(sock.sockfd, SOL_SOCKET, option as libc::c_int,
                          unsafe::reinterpret_cast(&ptr::addr_of(val)),
                          sys::size_of::<int>() as socklen_t);
    if r == -1_i32 {
        log_err(#fmt["setsockopt error"]);
        result::Err(~"setsockopt failed")
    } else {
        result::Ok(r)
    }
}

fn enablesockopt(sock: @socket_handle, option: int)
    -> result<libc::c_int, ~str> unsafe {
    setsockopt(sock, option, 1)
}

fn disablesockopt(sock: @socket_handle, option: int)
    -> result<libc::c_int, ~str> unsafe {
    setsockopt(sock, option, 0)
}

fn htons(hostshort: u16) -> u16 {
    c::htons(hostshort)
}

fn htonl(hostlong: u32) -> u32 {
    c::htonl(hostlong)
}

fn ntohs(netshort: u16) -> u16 {
    c::ntohs(netshort)
}

fn ntohl(netlong: u32) -> u32 {
    c::ntohl(netlong)
}

#[test]
fn test_server_client()
{
    fn run_client(test_str: &str, port: u16)
    {
         let ts = test_str.to_unique();
         do task::spawn {
             match connect(~"localhost", port)
             {
                 result::Ok(handle) =>
                 {
                     let res = str::as_buf(ts, |buf, _len| {send_buf(handle, buf, str::len(ts))});
                     assert result::is_ok(res);
                 }
                 result::Err(err) =>
                 {
                     error!("Error %s connecting", err);
                     assert false;
                 }
             }
         };
    }
    
    fn run_server(test_str: &str, s: @socket_handle)
    {
         match accept(s)
         {
             result::Ok(args) =>
             {
                 if !str::eq(&~"127.0.0.1", &args.remote_addr) && !str::eq(&~"::1", &args.remote_addr)
                 {
                     error!("Expected 127.0.0.1 or ::1 for remote addr but found %s", args.remote_addr);
                     assert false
                 }
                 let c = @socket_handle(args.fd);
                 match recv(c, 1024u)
                 {
                     result::Ok(res) =>
                     {
                         assert res.bytes == str::len(test_str);
                         assert vec::slice(res.buffer, 0u, res.bytes) == str::to_bytes(test_str);
                     }
                     result::Err(err) =>
                     {
                         error!("Error %s with recv", err);
                         assert false;
                     }
                 }
             }
             result::Err(err) =>
             {
                 error!("Error %s accepting", err);
                 assert false;
             }
         }
    }
    
    info!("---- test_server_client ------------------------");
    let port = 48006u16;
    let test_str = ~"testing";
    
    match bind_socket(~"localhost", port)
    {
        result::Ok(s) =>
        {
            match listen(s, 1i32)
            {
                result::Ok(s) =>
                {
                    run_client(test_str, port);
                    run_server(test_str, s);
                }
                result::Err(err) =>
                {
                    error!("Error %s listening", err);
                    assert false;
                }
            }
        }
        result::Err(err) =>
        {
            error!("Error %s binding", err);
            assert false;
        }
    }
}

#[test]
fn test_getaddrinfo_localhost() {
    info!("---- test_getaddrinfo_localhost ------------------------");
    let hints = {ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ..mk_default_addrinfo()};
    let servinfo: *addrinfo = ptr::null();
    let port = 48007u16;
    do str::as_c_str(~"localhost") |host| {
        do str::as_c_str(#fmt["%u", port as uint]) |p| {
            let status = c::getaddrinfo(host, p, ptr::addr_of(hints), ptr::addr_of(servinfo));
            assert status == 0_i32;
            unsafe {
                assert servinfo != ptr::null();
                let p = *servinfo;

                let ipstr = inet_ntop(&p);
                assert str::eq(&~"127.0.0.1", &ipstr) || str::eq(&~"::1", &ipstr)
            }
            c::freeaddrinfo(servinfo)
        }
    };
}
