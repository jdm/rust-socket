import result = result::result;
import std::rand;

export sockaddr, getaddrinfo, bind_socket, socket_handle, connect, listen, accept,
       send, recv, sendto, recvfrom, setsockopt, enablesockopt, disablesockopt,
       htons, htonl, ntohs, ntohl, sockaddr4_in, sockaddr6_in, sockaddr_basic;
export SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST,
       AF_UNSPEC, AF_UNIX, AF_INET, AF_INET6, AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST,
       AI_NUMERICSERV, INET6_ADDRSTRLEN;

#[nolink]
native mod c {
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

    fn inet_ntop(af: libc::c_int, src: *libc::c_void, dst: *u8, size: socklen_t) -> *u8;
    fn inet_pton(af: libc::c_int, src: *u8, dst: *libc::c_void) -> libc::c_int;

    fn getaddrinfo(node: *u8, service: *u8, hints: *addrinfo, res: **addrinfo) -> libc::c_int;
    fn freeaddrinfo(ai: *addrinfo);
}

const SOCK_STREAM: libc::c_int = 1_i32;
const SOCK_DGRAM: libc::c_int = 2_i32;
const SOCK_RAW: libc::c_int = 3_i32;

const SOL_SOCKET: libc::c_int = 0xffff_i32;

const SO_REUSEADDR: libc::c_int = 0x0004_i32;
const SO_KEEPALIVE: libc::c_int = 0x0008_i32;
const SO_BROADCAST: libc::c_int = 0x0020_i32;

const AF_UNSPEC: libc::c_int = 0_i32;
const AF_UNIX: libc::c_int = 1_i32;
const AF_INET: libc::c_int = 2_i32;
const AF_INET6: libc::c_int = 30_i32;

const AI_PASSIVE: libc::c_int = 0x0001_i32;
const AI_CANONNAME: libc::c_int = 0x0002_i32;
const AI_NUMERICHOST: libc::c_int = 0x0004_i32;
const AI_NUMERICSERV: libc::c_int = 0x1000_i32;

const INET6_ADDRSTRLEN: libc::c_int = 46_i32;

type socklen_t = libc::c_int;
type x = u8;
type sockaddr_storage = (i16, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x);
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

type addrinfo = {ai_flags: libc::c_int,
                 ai_family: libc::c_int,
                 ai_socktype: libc::c_int,
                 ai_protocol: libc::c_int,
                 ai_addrlen: socklen_t,
                 ai_canonname: *u8,
                 ai_addr: *sockaddr_storage,
                 ai_next: *u8}; //XXX ai_next should be *addrinfo

fn mk_default_addrinfo() -> addrinfo {
    {ai_flags: 0i32, ai_family: 0i32, ai_socktype: 0i32, ai_protocol: 0i32, ai_addrlen: 0i32,
     ai_canonname: ptr::null(), ai_addr: ptr::null(), ai_next: ptr::null()}
}

fn getaddrinfo(host: str, port: u16, f: fn(addrinfo) -> bool) unsafe {
    let hints = {ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM
                 with mk_default_addrinfo()};
    let servinfo: *addrinfo = ptr::null();
    let s_port = #fmt["%u", port as uint];
    str::as_buf(host) {|host|
        str::as_buf(s_port) {|port|
            let status = c::getaddrinfo(host, port, ptr::addr_of(hints),
                                        ptr::addr_of(servinfo));
            if status != -1_i32 {
                let mut p = servinfo;
                while p != ptr::null() {
                    if f(*p) {
                        break;
                    }
                    p = unsafe::reinterpret_cast((*p).ai_next);
                }
            }
        }
    }
    c::freeaddrinfo(servinfo);
}

resource socket_handle(sockfd: libc::c_int) {
    c::close(sockfd);
}

fn bind_socket(host: str, port: u16) -> result<@socket_handle, str> {
    let mut fd = option::none;
    getaddrinfo(host, port) {|ai|
        let sockfd = c::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
        if sockfd != -1_i32 {
            if c::bind(sockfd, ai.ai_addr, ai.ai_addrlen) == -1_i32 {
                c::close(sockfd);
                false
            } else {
                fd = option::some(sockfd);
                true
            }
        } else {
            false
        }
    }
    if option::is_some(fd) {
        result::ok(@socket_handle(option::get(fd)))
    } else {
        result::err("bind failed")
    }
}

fn connect(host: str, port: u16) -> result<@socket_handle, str> {
    let mut fd = option::none;
    getaddrinfo(host, port) {|ai|
        let sockfd = c::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
        if sockfd != -1_i32 {
            if c::connect(sockfd, ai.ai_addr, ai.ai_addrlen) == -1_i32 {
                c::close(sockfd);
                false
            } else {
                fd = option::some(sockfd);
                true
            }
        } else {
            false
        }
    }
    if option::is_some(fd) {
        result::ok(@socket_handle(option::get(fd)))
    } else {
        result::err("connect failed")
    }   
}

fn listen(sock: @socket_handle, backlog: i32) -> result<@socket_handle, str> {
    if c::listen(**sock, backlog) == -1_i32 {
        result::err("listen failed")
    } else {
        result::ok(sock)
    }
}

fn accept(sock: @socket_handle) -> result<@socket_handle, str> {
    let addr = (0i16, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8);
    let unused: socklen_t = sys::size_of::<sockaddr>() as socklen_t;
    let fd = c::accept(**sock, ptr::addr_of(addr), ptr::addr_of(unused));
    if fd == -1_i32 {
        result::err("accept failed")
    } else {
        result::ok(@socket_handle(fd))
    }
}

fn send(sock: @socket_handle, buf: [u8]) -> result<uint, str> unsafe {
    let amt = c::send(**sock, vec::unsafe::to_ptr(buf),
                      vec::len(buf) as libc::c_int, 0i32);
    if amt == -1_i32 {
        result::err("send failed")
    } else {
        result::ok(amt as uint)
    }
}

fn recv(sock: @socket_handle, len: uint) -> result<[u8], str> unsafe {
    let buf = vec::from_elem(len, 0u8);
    if c::recv(**sock, vec::unsafe::to_ptr(buf), len as libc::c_int, 0i32) == -1_i32 {
        result::err("recv failed")
    } else {
        result::ok(buf)
    }
}

fn sendto(sock: @socket_handle, buf: [u8], to: sockaddr)
    -> result<uint, str> unsafe {
    let (to_saddr, to_len) = alt to {
      ipv4(s) { (unsafe::reinterpret_cast::<sockaddr4_in, sockaddr_storage>(s),
                 sys::size_of::<sockaddr4_in>()) }
      ipv6(s) { (unsafe::reinterpret_cast::<sockaddr6_in, sockaddr_storage>(s),
                 sys::size_of::<sockaddr6_in>()) }
      unix(s) { (unsafe::reinterpret_cast::<sockaddr_basic, sockaddr_storage>(s),
                 sys::size_of::<sockaddr_basic>()) }
    };
    let amt = c::sendto(**sock, vec::unsafe::to_ptr(buf), vec::len(buf) as libc::c_int, 0i32,
                        ptr::addr_of(to_saddr), to_len as libc::c_int);
    if amt == -1_i32 {
        result::err("sendto failed")
    } else {
        result::ok(amt as uint)
    }
}

fn recvfrom(sock: @socket_handle, len: uint)
    -> result<([u8], sockaddr), str> unsafe {
    let from_saddr = (0i16, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8);
    let unused: socklen_t = 0i32;
    let buf = vec::from_elem(len, 0u8);
    let amt = c::recvfrom(**sock, vec::unsafe::to_ptr(buf), vec::len(buf) as libc::c_int, 0i32,
                          ptr::addr_of(from_saddr), ptr::addr_of(unused));
    if amt == -1_i32 {
        result::err("recvfrom failed")
    } else {
        let (family, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) = from_saddr; 
        result::ok((buf,
                   if family == AF_INET as i16 {
                       ipv4(unsafe::reinterpret_cast(from_saddr))
                   } else {
                       unix(unsafe::reinterpret_cast(from_saddr))
                   }))
    }
}

fn setsockopt(sock: @socket_handle, option: int, value: int)
    -> result<libc::c_int, str> unsafe {
    let val = value;
    let r = c::setsockopt(**sock, SOL_SOCKET, option as libc::c_int,
                          unsafe::reinterpret_cast(ptr::addr_of(val)),
                          sys::size_of::<int>() as socklen_t);
    if r == -1_i32 {
        result::err("setsockopt failed")
    } else {
        result::ok(r)
    }
}

fn enablesockopt(sock: @socket_handle, option: int)
    -> result<libc::c_int, str> unsafe {
    setsockopt(sock, option, 1)
}

fn disablesockopt(sock: @socket_handle, option: int)
    -> result<libc::c_int, str> unsafe {
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
fn test_server_client() {
    let mut port = 0u32;
    let rng = rand::rng();
    while (port < 1024u32 || port > 65535u32) {
        port = rng.next();
    }
    let test_str = "testing";

    let r = result::chain(bind_socket("localhost", port as u16)) {|s|
        result::chain(listen(s, 1i32)) {|s|

            task::spawn {||
                result::chain(connect("localhost", port as u16)) {|s|
                    let res = send(s, str::bytes(test_str));
                    assert result::success(res);
                    result::ok(s)
                };
            };

            result::chain(accept(s)) {|c|
                let res = recv(c, str::len(test_str));
                assert result::success(res);
                assert result::get(res) == str::bytes(test_str);
                result::ok(c)
            }
        }
    };
    assert result::success(r);
}

#[test]
fn test_getaddrinfo_localhost() {
    let hints = {ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM with mk_default_addrinfo()};
    let servinfo: *addrinfo = ptr::null();
    let mut port = 0u32;
    let rng = rand::rng();
    while (port < 1024u32 || port > 65535u32) {
        port = rng.next();
    }
    str::as_buf("localhost") {|host|
        str::as_buf(#fmt["%u", port as uint]) {|p|
            let status = c::getaddrinfo(host, p, ptr::addr_of(hints), ptr::addr_of(servinfo));
            assert status == 0_i32;
            unsafe {
                assert servinfo != ptr::null();
                let p = *servinfo;
                assert p.ai_next != ptr::null();

                let ipstr = vec::from_elem(INET6_ADDRSTRLEN as uint, 0u8);
                c::inet_ntop(p.ai_family,
                             if p.ai_family == AF_INET {
                                 let addr: *sockaddr4_in = unsafe::reinterpret_cast(p.ai_addr);
                                 unsafe::reinterpret_cast(ptr::addr_of((*addr).sin_addr))
                             } else {
                                 let addr: *sockaddr6_in = unsafe::reinterpret_cast(p.ai_addr);
                                 unsafe::reinterpret_cast(ptr::addr_of((*addr).sin6_addr))
                             },
                             vec::unsafe::to_ptr(ipstr), INET6_ADDRSTRLEN);
                let val = str::split_char(str::from_bytes(ipstr), 0 as char)[0];
                assert str::eq("127.0.0.1", val)
            }
            c::freeaddrinfo(servinfo)
        }
    };
}
