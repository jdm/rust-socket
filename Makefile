all:
	rustc socket.rc

test:
	rustc --test socket.rc
	export RUST_LOG=socket=3 && $(DEBUGGER) ./socket

test1:
	rustc --test socket.rc
	export RUST_LOG=socket=3 && $(DEBUGGER) ./socket test_socket_bind

clean:
	rm -rf libsocket-*
	rm -rf socket socket.dSYM
