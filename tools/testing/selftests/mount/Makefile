# Makefile for mount selftests.
CFLAGS = -Wall \
         -O2
all: unprivileged-remount-test uidshift-mount-test

unprivileged-remount-test: unprivileged-remount-test.c
	$(CC) $(CFLAGS) unprivileged-remount-test.c -o unprivileged-remount-test

uidshift-mount-test: uidshift-mount-test.c
	$(CC) $(CFLAGS) uidshift-mount-test.c -o uidshift-mount-test

include ../lib.mk

override RUN_TESTS := if [ -f /proc/self/uid_map ] ; then \
	./unprivileged-remount-test || echo \"selftests: unprivileged-remount-test [FAIL]\" ; \
	sudo ./uidshift-mount-test 1000 || echo \"selftests: uidshift-mount-test [FAIL]\" ; fi

TEST_PROGS := unprivileged-remount-test uidshift-mount-test

override EMIT_TESTS := echo "$(RUN_TESTS)"

clean:
	rm -f unprivileged-remount-test uidshift-mount-test
