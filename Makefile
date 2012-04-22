all:
	rustc socket.rc -g

test:
	rustc --test socket.rc -g
	export RUST_LOG=socket=1 && $(DEBUGGER) ./socket

clean:
	rm -rf libsocket-*
	rm -rf socket socket.dSYM
