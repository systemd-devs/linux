# Makefile for mount selftests.
CFLAGS = -Wall \
         -O2
all: unprivileged-remount-test overlayfs-uidshift-mount-test

unprivileged-remount-test: unprivileged-remount-test.c
	$(CC) $(CFLAGS) unprivileged-remount-test.c -o unprivileged-remount-test

overlayfs-uidshift-mount-test: overlayfs-uidshift-mount-test.c
	$(CC) $(CFLAGS) overlayfs-uidshift-mount-test.c -o overlayfs-uidshift-mount-test

include ../lib.mk

TEST_PROGS := unprivileged-remount-test overlayfs-uidshift-mount-test
override RUN_TESTS := if [ -f /proc/self/uid_map ] ; \
		      then	\
				./unprivileged-remount-test ; \
		      else	\
				echo "WARN: No /proc/self/uid_map exist, test skipped." ; \
		      fi
override EMIT_TESTS := echo "$(RUN_TESTS)"

clean:
	rm -f unprivileged-remount-test overlayfs-uidshift-mount-test
