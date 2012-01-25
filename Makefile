all:
	rustc socket.rc -g

test:
	rustc --test socket.rc -g
	$(DEBUGGER) ./socket

clean:
	rm -rf libsocket-*
	rm -rf socket socket.dSYM
