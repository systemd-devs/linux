#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <linux/sched.h>

#ifndef CLONE_NEWUSER
# define CLONE_NEWUSER 0x10000000
#endif

#define UID_INVALID ((uid_t) -1)

static int efd;
static int efd_userns_child;
static uid_t arg_uid_shift = UID_INVALID;
static uid_t arg_uid_range = 0x10000U;

static int vmaybe_write_file(bool enoent_ok, char *filename, char *fmt, va_list ap)
{
	char buf[4096];
	int fd;
        int ret;
	ssize_t written;
	int buf_len;

	buf_len = vsnprintf(buf, sizeof(buf), fmt, ap);
	if (buf_len < 0) {
                ret = -errno;
		printf("vsnprintf failed: %d (%m)\n", ret);
                return ret;
	}
	if (buf_len >= sizeof(buf)) {
                ret = -1;
		printf("vsnprintf output truncated\n");
                return ret;
	}

	fd = open(filename, O_WRONLY);
	if (fd < 0) {
		if ((errno == ENOENT) && enoent_ok)
			return 0;
                ret = -errno;
		printf("open of %s failed: %d (%m)\n",
		        filename, ret);
                return ret;
	}
	written = write(fd, buf, buf_len);
	if (written != buf_len) {
		if (written >= 0) {
			printf("short write to %s\n", filename);
                        return -1;
		} else {
                        ret = -errno;
			printf("write to %s failed: %d (%m)\n",
				filename, ret);
                        return ret;
		}
	}
	if (close(fd) != 0) {
                ret = -errno;
		printf("close of %s failed: %d (%m)\n",
			filename, ret);
                return ret;
	}

        return 0;
}

static int maybe_write_file(char *filename, char *fmt, ...)
{
        int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vmaybe_write_file(true, filename, fmt, ap);
	va_end(ap);

        return ret;
}

static int write_file(char *filename, char *fmt, ...)
{
        int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vmaybe_write_file(false, filename, fmt, ap);
	va_end(ap);

        return ret;
}

static int setup_userns(pid_t pid)
{
        int ret;
        char buf[64];

        snprintf(buf, sizeof(buf), "/proc/%d/setgroups", pid);
	ret = maybe_write_file(buf, "deny");
        if (ret < 0)
                goto err;

        snprintf(buf, sizeof(buf), "/proc/%d/uid_map", pid);
	ret = write_file(buf, "0 %u %u \n",
                         arg_uid_shift, arg_uid_range);
        if (ret < 0)
                goto err;

        snprintf(buf, sizeof(buf), "/proc/%d/gid_map", pid);
	ret = write_file(buf, "0 %u %u \n",
                         arg_uid_shift, arg_uid_range);
        if (ret < 0)
                goto err;

        return 0;

err:
        printf("setting up the user namespace failed\n");
        return ret;
}

static int update_uid_gid(void)
{
        int ret;
        uid_t uid = arg_uid_shift;

        /*ret = setgroups(0, NULL);
        if (ret < 0) {
                ret = -errno;
                printf("setgroups() failed: %d (%m)\n", ret);
                return ret;
        }*/

        ret = setresgid(uid, uid, uid);
        if (ret < 0) {
                ret = -errno;
                printf("setresgid() failed: %d (%m)\n", ret);
                return ret;
        }

        ret = setresuid(uid, uid, uid);
        if (ret < 0) {
                ret = -errno;
                printf("setresuid() failed: %d (%m)\n", ret);
                return ret;
        }

        return 0;
}

static int test_filesystems(void)
{
        /* TODO stat proc inode entries... */


        return 0;
}

static int outer_child(void)
{
        int ret;
        int status;
        pid_t pid, rpid;
	eventfd_t event_status = 0;

        pid = syscall(__NR_clone, SIGCHLD|
                      CLONE_NEWNS|CLONE_NEWUSER, NULL);
        if (pid < 0) {
                ret = -errno;
		printf("clone() failed: %d (%m)\n", -errno);
		return ret;
        }

        if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0) {
			ret = -errno;
			printf("error prctl(): %d (%m)\n", ret);
			_exit(EXIT_FAILURE);
		}

		ret = eventfd_read(efd_userns_child, &event_status);
		if (ret < 0 || event_status != 1) {
			printf("error eventfd_read() *** \n");
			_exit(EXIT_FAILURE);
		}

                ret = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
                if (ret < 0) {
                        ret = -errno;
                        printf("mount() failed: %d (%m)\n", ret);
                        _exit(EXIT_FAILURE);
                }

                ret = mount("/proc", "/proc", "bind", MS_BIND, NULL);
                if (ret < 0) {
                        ret = -errno;
                        printf("mount() procfs failed: %d (%m)\n", ret);
                        return ret;
                }

                ret = update_uid_gid();
                if (ret < 0)
                        _exit(EXIT_FAILURE);

                ret = test_filesystems();
                if (ret < 0) {
                        printf("failed at filesystems test\n");
                        _exit(EXIT_FAILURE);
                }
                        
                /* TODO: test here stats and other uidshift results */
                execle("/bin/sh", "-sh", NULL, NULL);
        }

	ret = eventfd_write(efd, pid);
	if (ret < 0) {
		ret = -errno;
		printf("error eventfd_write(): %d (%m)\n", ret);
		return ret;
	}

        rpid = waitpid(pid, &status, 0);
        if (rpid < 0) {
                ret = -errno;
                printf("waitpid() failed: %d (%m)\n", ret);
                return ret;
        } 

        if (rpid != pid) {
		printf("waited for %d got %d\n", pid, rpid);
                return -1;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                printf("child did not terminate cleanly\n");
                return -1;
        }

        return 0;
}

static void nop_handler(int sig) {}

static int test_uidshift_mount(void)
{
        int ret;
        int status;
        pid_t pid, rpid;
        struct sigaction oldsa;
        struct sigaction sa = {
                .sa_handler = nop_handler,
                .sa_flags = SA_NOCLDSTOP,
        };
	eventfd_t event_status = 0;

        efd = eventfd(0, EFD_CLOEXEC);
        if (efd < 0) {
                ret = -errno;
                printf("eventfd() failed: %d (%m)\n", ret);
                return ret;
        }

        efd_userns_child = eventfd(0, EFD_CLOEXEC);
        if (efd_userns_child < 0) {
                ret = -errno;
                printf("eventfd() failed: %d (%m)\n", ret);
                return ret;
        }

	ret = sigaction(SIGCHLD, &sa, &oldsa);
	if (ret < 0) {
		ret = -errno;
		printf("sigaction() failed: %d (%m)\n", ret);
		return ret;
	}

	pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWNS, NULL);
	if (pid < 0) {
                ret = -errno;
		printf("clone() failed: %d (%m)\n", -errno);
		return ret;
	}

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0) {
			ret = -errno;
			printf("error prctl(): %d (%m)\n", ret);
			_exit(EXIT_FAILURE);
		}

		/* reset sighandlers of childs */
		ret = sigaction(SIGCHLD, &oldsa, NULL);
		if (ret < 0) {
			ret = -errno;
			printf("sigaction() failed: %d (%m)\n", ret);
			_exit(EXIT_FAILURE);
		}

                ret = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
                if (ret < 0) {
                        ret = -errno;
                        printf("mount() failed: %d (%m)\n", ret);
                        _exit(EXIT_FAILURE);
                }

                ret = outer_child();
                _exit(ret);
        }

	ret = eventfd_read(efd, &event_status);
	if (ret < 0) {
                ret = -errno;
		printf("error eventfd_read()\n");
		return ret;
	}

        ret = setup_userns(event_status);
        if (ret < 0) {
                ret = -errno;
                printf("error mapping uid and gid in userns\n");
                return ret;
        }

	ret = eventfd_write(efd_userns_child, 1);
	if (ret < 0) {
		ret = -errno;
		printf("error eventfd_write(): %d (%m)\n", ret);
		return ret;
	}

        rpid = waitpid(pid, &status, 0);
        if (rpid < 0) {
                ret = -errno;
                printf("waitpid() failed: %d (%m)\n", ret);
                return ret;
        }

        if (rpid != pid) {
		printf("waited for %d got %d\n", pid, rpid);
                return -1;
        }

        close(efd);
        close(efd_userns_child);

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                printf("child did not terminate cleanly\n");
                return -1;
        }

        return 0;
}

static int parse_uid(const char *arg)
{
        int ret;
        unsigned long l;
        unsigned long long ll;
        const char *range, *shift;
        char *buffer = NULL, *x = NULL;

        range = strchr(arg, ':');
        if (range) {
                buffer = strndup(arg, range - arg);
                if (!buffer) {
                        ret = -errno;
                        printf("strndup() failed: %d (%m)\n", ret);
                        return ret;
                }

                shift = buffer;
                range++;

                errno = 0;
                l = strtoul(range, &x, 0);
                if (!x || x == range || *x || errno ||
                    (unsigned long) (unsigned) l != l || l == 0) {
                        printf("failed to parse UID range: %s\n", range);
                        return -ENXIO;
                }

                arg_uid_range = (unsigned) l;

        } else {
                shift = arg;
        }

        errno = 0;
        x = NULL;
        ll = strtoull(shift, &x, 0);
        if (!x || x == shift || *x || errno ||
            (unsigned long long) (unsigned) ll != ll ||
            (uid_t) ll == (uid_t) 0xFFFFFFFF || /* INVALID_UID is special */
            (uid_t) ll == (uid_t) 0xFFFF) {
                printf("Failed to parse UID: %s\n", shift);
                return -ENXIO;
        }

        arg_uid_shift = (unsigned) ll;

        free(buffer);

        return 0;
}

int main(int argc, char **argv)
{
        if (argc > 1) {
                if (parse_uid(argv[1]) < 0)
                        exit(EXIT_FAILURE);
        }

        if (test_uidshift_mount() < 0) {
                printf("uidshift mounting test failed\n");
                exit(EXIT_FAILURE);
        }

	return EXIT_SUCCESS;
}
