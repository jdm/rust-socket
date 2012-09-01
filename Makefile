RUSTC ?= rustc

dummy1 := $(shell mkdir bin 2> /dev/null)

all:
	$(RUSTC) -o bin/socket socket.rc

check:
	$(RUSTC) -o bin/test-socket --test socket.rc
	export RUST_LOG=socket=3 && $(DEBUGGER) bin/test-socket

check1:
	$(RUSTC) -o bin/test-socket --test socket.rc
	export RUST_LOG=socket::socket=3 && $(DEBUGGER) bin/test-socket test_server_client

clean:
	rm -rf bin
