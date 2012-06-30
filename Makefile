all:
	rustc socket.rc

test:
	rustc --test socket.rc
	export RUST_LOG=socket=3 && $(DEBUGGER) ./socket

clean:
	rm -rf libsocket-*
	rm -rf socket socket.dSYM
