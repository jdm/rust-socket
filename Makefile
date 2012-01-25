all:
	rustc socket.rc

test:
	rustc --test socket.rc
	./socket

clean:
	rm -rf libsocket-*
	rm -rf socket socket.dSYM
