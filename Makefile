RUSTC ?= rustc

dummy1 := $(shell mkdir bin 2> /dev/null)

all:
	$(RUSTC) -o bin/socket crate.rc

check:
	$(RUSTC) -o bin/test-socket --test crate.rc
	export RUST_LOG=socket=3 && $(DEBUGGER) bin/test-socket

check1:
	$(RUSTC) -o bin/test-socket --test crate.rc
	export RUST_LOG=socket::crate=3 && $(DEBUGGER) bin/test-socket test_server_client

clean:
	rm -rf bin
