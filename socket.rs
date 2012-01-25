import std::rand;

#[nolink]
native mod c {
    fn socket(af: ctypes::c_int, typ: ctypes::c_int, protocol: ctypes::c_int) -> ctypes::c_int;
    fn bind(s: ctypes::c_int, name: *sockaddr, namelen: socklen_t) -> ctypes::c_int;
    fn connect(s: ctypes::c_int, name: *sockaddr, namelen: socklen_t) -> ctypes::c_int;
    fn listen(s: ctypes::c_int, backlog: ctypes::c_int) -> ctypes::c_int;
    fn accept(sockfd: ctypes::c_int, name: *sockaddr, namelen: *socklen_t) -> ctypes::c_int;
    fn send(sd: ctypes::c_int, buf: *u8, len: ctypes::c_int, flags: ctypes::c_int) -> ctypes::c_int;
    fn recv(sd: ctypes::c_int, buf: *u8, len: ctypes::c_int, flags: ctypes::c_int) -> ctypes::c_int;
    fn sendto(s: ctypes::c_int, msg: *u8, len: ctypes::c_int, flags: ctypes::c_int, to: *sockaddr, tolen: socklen_t) -> ctypes::c_int;
    fn recvfrom(s: ctypes::c_int, msg: *u8, len: ctypes::c_int, flags: ctypes::c_int, from: *sockaddr, fromlen: *socklen_t) -> ctypes::c_int;
    fn close(s: ctypes::c_int);
    fn setsockopt(sockfd: ctypes::c_int, level: ctypes::c_int, optname: ctypes::c_int, optval: *u8, optlen: socklen_t) -> ctypes::c_int;
    fn getsockopt(sockfd: ctypes::c_int, level: ctypes::c_int, optname: ctypes::c_int, optval: *u8, optlen: socklen_t) -> ctypes::c_int;

    fn htons(hostshort: u16) -> u16;
    fn htonl(hostlong: u32) -> u32;
    fn ntohs(netshort: u16) -> u16;
    fn ntohl(netlong: u32) -> u32;

    fn inet_ntop(af: ctypes::c_int, src: *ctypes::void, dst: *u8, size: socklen_t) -> *u8;
    fn inet_pton(af: ctypes::c_int, src: *u8, dst: *ctypes::void) -> ctypes::c_int;

    fn getaddrinfo(node: *u8, service: *u8, hints: *addrinfo, res: **addrinfo) -> ctypes::c_int;
    fn freeaddrinfo(ai: *addrinfo);
}

const SOCK_STREAM: ctypes::c_int = 1_i32;
const SOCK_DGRAM: ctypes::c_int = 2_i32;
const SOCK_RAW: ctypes::c_int = 3_i32;

const SOL_SOCKET: ctypes::c_int = 0xffff_i32;

const SO_REUSEADDR: ctypes::c_int = 0x0004_i32;
const SO_KEEPALIVE: ctypes::c_int = 0x0008_i32;
const SO_BROADCAST: ctypes::c_int = 0x0020_i32;

const AF_UNSPEC: ctypes::c_int = 0_i32;
const AF_UNIX: ctypes::c_int = 1_i32;
const AF_INET: ctypes::c_int = 2_i32;
const AF_INET6: ctypes::c_int = 30_i32;

const AI_PASSIVE: ctypes::c_int = 0x0001_i32;
const AI_CANONNAME: ctypes::c_int = 0x0002_i32;
const AI_NUMERICHOST: ctypes::c_int = 0x0004_i32;
const AI_NUMERICSERV: ctypes::c_int = 0x1000_i32;

const INET6_ADDRSTRLEN: ctypes::c_int = 46_i32;

type socklen_t = ctypes::c_int;
type sockaddr = {sa_family: u16, sa_data: *u8};
type sockaddr_in = {sin_family: i16, sin_port: u16, sin_addr: in_addr, sin_zero: *u8};
type in_addr = {s_addr: u32};
type sockaddr6_in = {sin6_family: u16, sin6_port: u16, sin6_flowinfo: u32, sin6_addr: in6_addr, sin6_scope_id: u32};
type in6_addr = {s6_addr: *u8};

type addrinfo = {ai_flags: ctypes::c_int,
                 ai_family: ctypes::c_int,
                 ai_socktype: ctypes::c_int,
                 ai_protocol: ctypes::c_int,
                 ai_addrlen: socklen_t,
                 ai_canonname: *u8,
                 ai_addr: *sockaddr,
                 ai_next: *u8}; //XXX ai_next should be *addrinfo

fn mk_default_addrinfo() -> addrinfo {
    {ai_flags: 0i32, ai_family: 0i32, ai_socktype: 0i32, ai_protocol: 0i32, ai_addrlen: 0i32,
     ai_canonname: ptr::null(), ai_addr: ptr::null(), ai_next: ptr::null()}
}

#[test]
fn test_getaddrinfo_localhost() {
    let hints = {ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM with mk_default_addrinfo()};
    let servinfo: *addrinfo = ptr::null();
    let port = 0u32;
    let rng = rand::mk_rng();
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

                let ipstr = vec::init_elt(0u8, INET6_ADDRSTRLEN as uint);
                c::inet_ntop(p.ai_family,
                             if p.ai_family == AF_INET {
                                 let addr: *sockaddr_in = unsafe::reinterpret_cast(p.ai_addr);
                                 unsafe::reinterpret_cast(ptr::addr_of((*addr).sin_addr))
                             } else {
                                 let addr: *sockaddr6_in = unsafe::reinterpret_cast(p.ai_addr);
                                 unsafe::reinterpret_cast(ptr::addr_of((*addr).sin6_addr))
                             },
                             vec::to_ptr(ipstr), INET6_ADDRSTRLEN);
                let val = str::split(str::unsafe_from_bytes(ipstr), 0u8)[0];
                assert str::eq("127.0.0.1", val)
            }
            c::freeaddrinfo(servinfo)
        }
    };
}

#[test]
fn test_bind() {
    let port = 0u32;
    let rng = rand::mk_rng();
    while (port < 1024u32 || port > 65535u32) {
        port = rng.next();
    }
    fn localhost_addrinfo(port: u32) -> *addrinfo {
        let hints = {ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_flags: AI_PASSIVE
                     with mk_default_addrinfo()};
        let servinfo: *addrinfo = ptr::null();
        str::as_buf("localhost") {|host|
            str::as_buf(#fmt["%u", port as uint]) {|port|
                let status = c::getaddrinfo(host, port, ptr::addr_of(hints), ptr::addr_of(servinfo));
                assert status == 0_i32
            }
        };
        servinfo
    }
    fn usable_addrinfo(server: bool,
                       port: u32,
                       attempt: fn(sockfd: ctypes::c_int, p: addrinfo) -> ctypes::c_int,
                       success: fn(sockfd: ctypes::c_int)) {
        dbg("getting addrinfo", port, server);
        let servinfo = localhost_addrinfo(port);
        let p;
        unsafe { p = *servinfo; }
        while true {
            let sockfd = c::socket(p.ai_family, p.ai_socktype, p.ai_protocol);
            unsafe {
                let yes = 1_i32;
                c::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
                              unsafe::reinterpret_cast(ptr::addr_of(yes)),
                              sys::size_of::<socklen_t>() as socklen_t);
            }
            assert sockfd != -1_i32;
            dbg("attempting", port, server);
            if attempt(sockfd, p) == -1_i32 {
                dbg("attempt failed", port, server);
                c::close(sockfd);
            } else {
                dbg("attempt succeeded", port, server);
                success(sockfd);
                c::close(sockfd);
                break;
            }
            if p.ai_next == ptr::null() {
                #error("couldn't use any addrinfo successfully");
                break;
            }
            unsafe { p = *unsafe::reinterpret_cast::<*u8, *addrinfo>(p.ai_next); }
        }
        c::freeaddrinfo(servinfo)
    }
    fn dbg(s: str, port: u32, server: bool) {
        #debug("%s (%u): %s", server ? "server" : "client", port as uint, s);
    }

    usable_addrinfo(true, port,
                    {|s, p| c::bind(s, p.ai_addr, p.ai_addrlen) },
                    {|s|
                        dbg("listening", port, true);
                        assert c::listen(s, 1_i32) != -1_i32;
                        dbg("listened", port, true);

                        task::spawn {||
                            usable_addrinfo(false, port,
                                            {|s, p| c::connect(s, p.ai_addr, p.ai_addrlen)},
                                            {|s|
                                                dbg("sending", port, false);
                                                str::as_buf("testing") {|buf|
                                                    c::send(s, buf, str::byte_len("testing") as ctypes::c_int, 0i32)
                                                };
                                                dbg("sent", port, false);
                                            });
                        };

                        let addr = {sa_family: 0u16, sa_data: ptr::null()};
                        let unused: socklen_t = 0i32;
                        dbg("accepting", port, true);
                        let fd = c::accept(s, ptr::addr_of(addr), ptr::addr_of(unused));
                        dbg("accepted", port, true);
                        let buf = vec::init_elt(0u8, 20u);
                        unsafe {
                            c::recv(fd, vec::unsafe::to_ptr(buf), vec::len(buf) as ctypes::c_int, 0i32);
                        }
                        c::close(fd);
                        let val = str::split(str::unsafe_from_bytes(buf), 0u8)[0];
                        assert val == "testing";
                    });
}