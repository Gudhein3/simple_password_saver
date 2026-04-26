.PHONY: local_install global_install

CFLAGS=-std=c11 # Requires minimum C11. If you don't like this fact, fork my repository and rewrite it for C89, C99, or whatever standard you want.

simple_password_saver: simple_password_saver.c
	$(CC) $(CFLAGS) -o simple_password_saver simple_password_saver.c third_party/aes.c

local_install: simple_password_saver
	mkdir -p $(HOME)/.local/bin
	cp simple_password_saver $(HOME)/.local/bin/sps

global_install: simple_password_saver
	cp simple_password_saver /usr/bin/sps
	chmod 755 /usr/bin/sps
