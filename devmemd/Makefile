CCOPTS=-O2 -g -Wall -Werror -Wpedantic -Wextra -Wabi

devmemd: devmemd.c devmemd.h
	$(CC) $(CCOPTS) -o $@ $<

run: devmemd
	sudo ./devmemd

strace: devmemd
	sudo strace ./devmemd

clean:
	rm -rf devmemd

