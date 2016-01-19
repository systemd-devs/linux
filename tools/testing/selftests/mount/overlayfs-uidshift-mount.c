#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/stat.h>
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
#include <linux/fs.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef CLONE_NEWUSER
# define CLONE_NEWUSER 0x10000000
#endif

#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

static int efd;
static int efd_userns_child;
static uid_t arg_uid_shift = UID_INVALID;
static uid_t arg_uid_range = 0x10000U;
static char *program_name;

enum {
	ARG_LOWER_DIR = 0x100,
	ARG_UPPER_DIR,
	ARG_WORK_DIR,
};

static char *arg_lower;
static char *arg_upper;
static char *arg_work;

typedef struct base_filesystem {
	const char *dir;
	mode_t mode;
	const char *target;
	const char *exists;
	bool ignore_failure;
} base_filesystem;

typedef struct mount_point {
	const char *what;
	const char *where;
	const char *type;
	const char *options;
	unsigned long flags;
	bool out_userns;	/* Before userns */
	bool in_userns;		/* mount inside userns */
	bool fatal;
} mount_point;

static const char root_fs_files[] =
	"/\0"
	"/root/\0"
	"/etc/passwd\0";

static const char proc_fs_files[] =
	"/proc/self/cmdline\0"
	"/proc/1/cmdline\0";

static const base_filesystem fs_table[] = {
	{ "bin",	0, "usr/bin\0",		NULL },
	{ "lib",	0, "usr/lib\0",		NULL },
	{ "root",	0755, NULL,		NULL, true },
	{ "sbin",	0, "usr/sbin\0",	NULL },
	{ "usr",	0755, NULL,		NULL },
	{ "var",	0755, NULL,		NULL },
	{ "etc",	0755, NULL,		NULL },
#if defined(__i386__) || defined(__x86_64__)
	{ "lib64",	0, "usr/lib/x86_64-linux-gnu\0"
			"usr/lib64\0",		"ld-linux-x86-64.so.2" },
#endif
};

static const mount_point mnt_table[] = {
	{
		"/proc", "/proc", "proc", NULL,
		MS_NOSUID|MS_NOEXEC|MS_NODEV, true, true, true,
	},
	{
		"/proc", "/proc", "bind", NULL,
		MS_BIND, false, true, true,
	},
	{
		"/proc/sys", "/proc/sys", NULL, NULL,
		MS_BIND, false, true, false,
	},	/* Bind mount first */
	{
		"/proc/sys", "/proc/sys", NULL, NULL,
		MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REMOUNT,
		false, true, false,
	},	/* Then, make it r/o */
	{
		"tmpfs", "/sys", "tmpfs", "mode=755",
		MS_NOSUID|MS_NOEXEC|MS_NODEV, true, false, false,
	},
	{
		"sysfs", "/sys", "sysfs", NULL,
		MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, true, false, false,
	},
	{
		"tmpfs", "/dev", "tmpfs", "mode=755",
		MS_NOSUID|MS_STRICTATIME, true, false, false,
	},
	{
		"tmpfs", "/dev/shm", "tmpfs", "mode=1777",
		MS_NOSUID|MS_NODEV|MS_STRICTATIME, true, false, false,
	},
	{
		"tmpfs", "/run", "tmpfs", "mode=755",
		MS_NOSUID|MS_NODEV|MS_STRICTATIME, true, false, false,
	},
	{
		"tmpfs", "/tmp", "tmpfs", "mode=1777",
		MS_STRICTATIME, true, false, false,
	},
};

static const struct option options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "users", optional_argument, NULL, 'u' },
	{ "lowerdir", required_argument, NULL, ARG_LOWER_DIR, },
	{ "upperdir", required_argument, NULL, ARG_UPPER_DIR, },
	{ "workdir", required_argument, NULL, ARG_WORK_DIR, },
};

static void help(void)
{
	printf("%s [OPTIONS...]\n\n\n"
	       "-h, --help		Show this help\n"
	       "-u, --users[=UIDBASE[:NUIDS]]	Set the user namespace shift\n"
	       "    --lowerdir=dir	Overlay lower directory\n"
	       "    --upperdir=dir	Overlay upper directory\n"
	       "    --workdir=dir	Overlay work directory\n",
	       program_name);
}

static int vmaybe_write_file(bool enoent_ok, char *filename,
			     char *fmt, va_list ap)
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

static int userns_lchown(const char *path, uid_t uid, gid_t gid)
{
	int ret;

	if (uid == UID_INVALID && gid == GID_INVALID)
		return 0;

	if (uid != UID_INVALID) {
		uid += arg_uid_shift;

		if (uid < arg_uid_shift || uid >= arg_uid_shift + arg_uid_range) {
			ret = -EOVERFLOW;
			printf("userns_lchown() failed: %d\n", ret);
			return ret;
		}
	}

	if (gid != GID_INVALID) {
		gid += arg_uid_shift;

		if (gid < arg_uid_shift || gid >= arg_uid_shift + arg_uid_range) {
			ret = -EOVERFLOW;
			printf("userns_lchown() failed: %d\n", ret);
			return ret;
		}
	}

	ret = lchown(path, uid, gid);
	if (ret < 0) {
		ret = -errno;
		printf("lchown() failed on %s: %d (%m)\n",
		       path, ret);
		return ret;
	}

	return 0;
}

static int copy_devnodes(const char *root)
{
	static const char devnodes[] =
		"null\0"
		"zero\0"
		"full\0"
		"random\0"
		"urandom\0"
		"tty\0";

	const char *d;
	int ret = 0;

	for (d = devnodes; (d) && *(d); (d) = strchr((d), 0)+1) {
		char *to;
		char *where;
		unsigned len;
		struct stat st;

		len = strlen(root) + 1 + strlen("/dev/") +
			strlen(d) + 1;
		to = alloca(len);
		where = alloca(len);
		if (!where || !to) {
			ret = -errno;
			printf("alloca() failed: %d (%m)\n", ret);
			return ret;
		}

		ret = snprintf(to, len, "/dev/%s", d);
		ret = snprintf(where, len, "%s/dev/%s", root, d);
		if (ret < 0) {
			ret = -errno;
			printf("snprintf() failed: %d (%m)\n", ret);
			return ret;
		}

		if (stat(to, &st) < 0) {
			ret = -errno;
			printf("stat() %s failed: %d (%m)\n", to, ret);
			return ret;
		} else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {
			ret = -EIO;
			printf("%s is not a char or block device\n", to);
			return ret;
		} else {
			int fd;

			ret = mknod(where, st.st_mode, st.st_rdev);
			if (!ret) {
				ret = userns_lchown(where, 0, 0);
				if (ret < 0) {
					printf("failed to chown() %s: %d (%m)\n",
					       where, ret);
					return ret;
				}
				continue;
			}

			fd = open(where, O_WRONLY|O_CREAT|
				  O_CLOEXEC|O_NOCTTY, 0644);
			if (ret < 0) {
				ret = -errno;
				printf("failed to open() %s: %d (%m)\n",
				       where, ret);
				return ret;
			}

			ret = fchown(fd, 0, 0);
			if (ret < 0) {
				ret = -errno;
				printf("failed to fchown() %s: %d (%m)\n",
				       where, ret);
				return ret;
			}

			ret = mount(to, where, NULL, MS_BIND, NULL);
			if (ret < 0) {
				ret = -errno;
				printf("failed to mount() %s: %d (%m)\n",
				       where, ret);
				return ret;
			}

			ret = userns_lchown(where, 0, 0);
			if (ret < 0) {
				printf("failed to chown() %s: %d (%m)\n",
				       where, ret);
				return ret;
			}
			close(fd);
		}
	}

	return ret;
}

static int dev_fd_setup(const char *root)
{
	return 0;
}

static int mount_overlay(const char *lower, const char *upper,
			 const char *work)
{
	int ret;
	char *options;

	options = alloca(1024);
	if (!options) {
		ret = -errno;
		printf("alloca() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = snprintf(options, 1024, "lowerdir=%s,upperdir=%s,workdir=%s,shift_uids,shift_gids",
		       lower, upper, work);
	if (ret < 0) {
		ret = -errno;
		printf("snprintf() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = mount("overlay", upper, "overlay", 0, options);
	if (ret < 0) {
		ret = -errno;
		printf("failed to mount() %s: %d (%m)\n", upper, ret);
		return ret;
	}

	return 0;
}

/* Setup a base file system */
static int setup_basic_filesystem(const char *root, uid_t uid,
				  gid_t gid, bool in_userns)
{
	int ret = 0;
	int fd;
	unsigned i;
	bool global = !in_userns;

	fd = open(root, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
	if (fd < 0) {
		ret = -errno;
		printf("open() %s failed: %d (%m)\n", root, ret);
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(fs_table); i++) {
		if (faccessat(fd, fs_table[i].dir,
			      F_OK, AT_SYMLINK_NOFOLLOW) < 0 &&
		    fs_table[i].ignore_failure) {
			ret = -errno;
			printf("faccessat() %s failed: %d (%m)\n",
			       fs_table[i].dir, ret);
			goto out;
		}
	}

	for (i = 0; i < ARRAY_SIZE(mnt_table); i++) {
		unsigned len;
		char *where;

		if (global != mnt_table[i].out_userns &&
		    in_userns != mnt_table[i].in_userns)
			continue;

		len = strlen(root) + 1 + strlen(mnt_table[i].where) + 1;
		where = alloca(len);
		if (!where) {
			ret = -errno;
			printf("alloca() failed: %d (%m)\n", ret);
			goto out;
		}

		ret = snprintf(where, len, "%s%s", root, mnt_table[i].where);
		if (ret < 0) {
			ret = -errno;
			printf("snprintf() failed: %d (%m)\n", ret);
			goto out;
		}

		/* TODO: test if path is a mount point */

		/* TODO: check mkdir() errors */
		ret = mkdir(where, 0755);

		printf("mounting %s   %s\n", where, mnt_table[i].options);
		ret = mount(mnt_table[i].what, where,
			    mnt_table[i].type,
			    mnt_table[i].flags,
			    mnt_table[i].options);
		if (ret < 0) {
			ret = -errno;
			printf("mount() %s options:%s failed: %d (%m)\n",
			       where, mnt_table[i].options, ret);
			if (mnt_table[i].fatal)
				goto out;
		}
	}

out:
	close(fd);
	return ret;
}

static int setup_move_root(const char *path)
{
	int ret;

	ret = chdir(path);
	if (ret < 0) {
		ret = -errno;
		printf("chdir() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = mount(path, "/", NULL, MS_MOVE, NULL);
	if (ret < 0) {
		ret = -errno;
		printf("mount() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = chroot(".");
	if (ret < 0) {
		ret = -errno;
		printf("chroot() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = chdir("/");
	if (ret < 0) {
		ret = -errno;
		printf("chdir() failed: %d (%m)\n", ret);
		return ret;
	}

	return 0;
}

static int access_inodes(void)
{
	return 0;
}

static int stat_inodes(const char *files, uid_t uid, gid_t gid)
{
	const char *f;
	int ret = 0;

	for (f = files; (f) && *(f); (f) = strchr((f), 0)+1) {
		struct stat sb;
		memset(&sb, 0, sizeof(sb));

		ret = syscall(__NR_lstat, f, &sb);
		if (ret < 0) {
			ret = -errno;
			printf("stat() %s failed: %d (%m)\n", f, ret);
			return ret;
		}

		printf("File: '%s'\n"
		       "Access: (%lo)   Uid: %ld   Gid: %ld\n",
		       f, (unsigned long) sb.st_mode,
		       (long) sb.st_uid, (long) sb.st_gid);

		if (sb.st_uid != uid || sb.st_gid != gid) {
			errno = EIO;
			printf("stat() %s Uid and Gid comparison failed\n",
			       f);
			return -errno;
		}
	}

	return 0;
}

static int setup_uid_map(pid_t pid)
{
	int ret;
	char buf[64];

	/*
	snprintf(buf, sizeof(buf), "/proc/%d/setgroups", pid);
	ret = maybe_write_file(buf, "deny");
	if (ret < 0)
		goto err;
	*/

	snprintf(buf, sizeof(buf), "/proc/%d/uid_map", pid);
	ret = write_file(buf, "0 %u %u\n",
			 arg_uid_shift, arg_uid_range);
	if (ret < 0)
		goto err;

	snprintf(buf, sizeof(buf), "/proc/%d/gid_map", pid);
	ret = write_file(buf, "0 %u %u\n",
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
	uid_t uid = 0; /* read them from /etc/passwd? */
	gid_t gid = 0;

	(void) fchown(STDIN_FILENO, uid, gid);
	(void) fchown(STDOUT_FILENO, uid, gid);
	(void) fchown(STDERR_FILENO, uid, gid);

	ret = setgroups(0, NULL);
	if (ret < 0) {
		ret = -errno;
		printf("setgroups() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = setresgid(gid, gid, gid);
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

static int child_test_filesystems(void)
{
	/* TODO stat proc inode entries... */

	int ret;
	uid_t uid = 0;
	gid_t gid = 0;

	ret = stat_inodes(root_fs_files, uid, gid);
	if (ret < 0) {
		printf("stat_inodes() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = access_inodes();
	if (ret < 0) {
		printf("access_inodes() failed: %d (%m)\n", ret);
		return ret;
	}

	return ret;
}

static int parent_test_filesystems(void)
{
	/* TODO stat inode entries from parent */

	return 0;
}

static int outer_child(void)
{
	int ret;
	eventfd_t event_status = 0;

	/* We entered the child we are ready */
	ret = eventfd_write(efd, 1);
	if (ret < 0) {
		ret = -errno;
		printf("error eventfd_write(): %d (%m)\n", ret);
		return ret;
	}

	ret = eventfd_read(efd_userns_child, &event_status);
	if (ret < 0 || event_status != 1) {
		printf("error eventfd_read() ***\n");
		return -1;
	}

	ret = update_uid_gid();
	if (ret < 0)
		return ret;

	ret = child_test_filesystems();
	if (ret < 0) {
		printf("failed at filesystems test\n");
		return ret;
	}

	/* TODO: test here stats and other uidshift results */
	execle("/bin/sh", "-sh", NULL, NULL);

	return -1;
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

	ret = mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
	if (ret < 0) {
		ret = -errno;
		printf("mount() failed: %d (%m)\n", ret);
		return ret;
	}

	/* Turn directory into bind mount */
	ret = mount(arg_lower, arg_lower, NULL,
		    MS_BIND|MS_REC, NULL);
	if (ret < 0) {
		ret = -errno;
		printf("mount() %s failed: %d (%m)\n",
		       arg_lower, ret);
		return ret;
	}

	ret = mount_overlay(arg_lower, arg_upper, arg_work);
	if (ret < 0) {
		printf("mount_overlay() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = userns_lchown(arg_upper, 0, 0);
	if (ret < 0) {
		printf("failed to lchown() %s : %d (%m)\n", arg_upper, ret);
		return ret;
	}

	ret = userns_lchown(arg_work, 0, 0);
	if (ret < 0) {
		printf("failed to lchown() %s: %d (%m)\n", arg_work, ret);
		return ret;
	}

	ret = setup_basic_filesystem(arg_upper, arg_uid_shift,
				     (gid_t) arg_uid_shift, false);
	if (ret < 0) {
		ret = -errno;
		printf("error failed to setup a basic filesystem\n");
		return ret;
	}

	ret = copy_devnodes(arg_upper);
	if (ret < 0) {
		ret = -errno;
		printf("copy_devnodes() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = dev_fd_setup(arg_upper);
	if (ret < 0) {
		ret = -errno;
		printf("dev_fs_setup() failed: %d (%m)\n", ret);
		return ret;
	}

	ret = setup_move_root(arg_upper);
	if (ret < 0) {
		ret = -errno;
		printf("setup_move_root() failed: %d (%m)\n", ret);
		return ret;
	}

	pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWUSER|
		      CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWPID|
		      CLONE_NEWUTS, NULL);
	if (pid < 0) {
		ret = -errno;
		printf("clone() failed: %d (%m)\n", ret);
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

		ret = setup_basic_filesystem("/", arg_uid_shift,
					     (gid_t) arg_uid_shift, true);
		if (ret < 0) {
			ret = -errno;
			printf("error failed to setup a basic filesystem\n");
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

	ret = setup_uid_map(pid);
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

	ret = parent_test_filesystems();
	if (ret < 0) {
		printf("Testing filesystem in parent failed\n");
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

	if (!arg)
		return -ENXIO;

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

int main(int argc, char *argv[])
{
	int ret;
	int c, dir_cnt = 0;
	int status;
	pid_t pid, rpid;

	program_name = strdup(argv[0]);
	if (!program_name) {
		printf("strdup() failed: %d (%m)\n", -errno);
		exit(EXIT_FAILURE);
	}

	program_name = basename(program_name);
	while ((c = getopt_long(argc, argv, "+hu:", options, NULL)) >= 0) {
		switch (c) {
		case 'h':
			help();
			return 0;

		case 'u':
			ret = parse_uid(optarg);
			if (ret < 0)
				return ret;

			break;

		case ARG_LOWER_DIR:
			arg_lower = strndup(optarg, strlen(optarg));
			if (arg_lower)
				dir_cnt++;
			break;

		case ARG_UPPER_DIR:
			arg_upper = strndup(optarg, strlen(optarg));
			if (arg_upper)
				dir_cnt++;
			break;

		case ARG_WORK_DIR:
			arg_work = strndup(optarg, strlen(optarg));
			if (arg_work)
				dir_cnt++;
			break;

		default:
			break;
		}
	}

	if (dir_cnt != 3) {
		fprintf(stderr, "failed to parse overlay dirs\n");
		exit(EXIT_FAILURE);
	}

	if (getuid() != 0) {
		printf("%s: can't map arbitrary uids, test skipped.\n",
		       program_name);
		exit(EXIT_SUCCESS);
	}

	pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWNS, NULL);
	if (pid < 0) {
		printf("clone() failed: %d (%m)\n", -errno);
		exit(EXIT_FAILURE);
	}

	if (pid == 0) {
		ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (ret < 0) {
			ret = -errno;
			printf("error prctl(): %d (%m)\n", ret);
			_exit(EXIT_FAILURE);
		}

		if (test_uidshift_mount() < 0) {
			printf("%s: uidshift mounting test failed.\n",
			       program_name);
			_exit(EXIT_FAILURE);
		}

		_exit(EXIT_SUCCESS);
	}

	rpid = waitpid(pid, &status, 0);
	if (rpid < 0) {
		ret = -errno;
		printf("waitpid() failed: %d (%m)\n", ret);
		exit(EXIT_FAILURE);
	}

	if (rpid != pid) {
		printf("waited for %d got %d\n", pid, rpid);
		exit(EXIT_FAILURE);
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("child did not terminate cleanly\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
