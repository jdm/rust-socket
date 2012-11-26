RUSTC ?= rustc

dummy1 := $(shell mkdir bin 2> /dev/null)

all:
	$(RUSTC) -o bin/socket --lib crate.rc

check:
	$(RUSTC) -o bin/test-socket --test crate.rc
	export RUST_LOG=socket=3,::rt::backtrace=4 && $(DEBUGGER) bin/test-socket

check1:
	$(RUSTC) -o bin/test-socket --test crate.rc
	export RUST_LOG=test-socket::socket=3,::rt::backtrace=4 && $(DEBUGGER) bin/test-socket test_server_client

clean:
	rm -rf bin
