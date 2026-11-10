#include "lockdown.h"

#include <errno.h>
#include <linux/capability.h>
#include <linux/sockios.h>
#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static const int allowed[] = {
    SCMP_SYS(write),
    SCMP_SYS(writev), /* musl stdio */
    SCMP_SYS(pread64),
    SCMP_SYS(pwrite64),
    SCMP_SYS(ftruncate),
    SCMP_SYS(flock),
    SCMP_SYS(poll),
    SCMP_SYS(ppoll),           /* poll() where the kernel has no poll */
    SCMP_SYS(restart_syscall), /* poll resumed after SIGSTOP/SIGCONT */
    SCMP_SYS(recvfrom),
    SCMP_SYS(sendto),
    SCMP_SYS(clock_gettime), /* without a vDSO clock */
    SCMP_SYS(close),
    SCMP_SYS(exit_group),
};

static int allow(scmp_filter_ctx ctx, int sys) {
	int r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, sys, 0);
	/* -EDOM: the syscall does not exist on this architecture */
	return r == -EDOM ? 0 : r;
}

static scmp_filter_ctx build_filter(enum lockdown_mode mode) {
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (!ctx)
		return NULL;

	int r =
	    seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS);
	for (size_t i = 0; r == 0 && i < sizeof(allowed) / sizeof(allowed[0]); i++)
		r = allow(ctx, allowed[i]);
	if (r == 0 && mode == LOCKDOWN_WATCH) {
		/* signalfd */
		r = allow(ctx, SCMP_SYS(read));
		/* iface_alive; any other request (TIOCSTI on an inherited
		 * terminal) stays out */
		if (r == 0)
			r = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
			                     SCMP_A1(SCMP_CMP_EQ, SIOCGIFINDEX));
	}
	if (r < 0) {
		seccomp_release(ctx);
		return NULL;
	}
	return ctx;
}

static int drop_caps(void) {
	struct __user_cap_header_struct hdr = {
	    .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	memset(data, 0, sizeof(data));

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
		perror("PR_CAP_AMBIENT_CLEAR_ALL error");
		return -1;
	}
	if (syscall(SYS_capset, &hdr, data) < 0) {
		perror("capset error");
		return -1;
	}
	return 0;
}

int lockdown_enter(enum lockdown_mode mode) {
	scmp_filter_ctx ctx = build_filter(mode);
	if (!ctx) {
		fprintf(stderr, "could not build the seccomp filter\n");
		return -1;
	}
	if (drop_caps() < 0) {
		seccomp_release(ctx);
		return -1;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("PR_SET_NO_NEW_PRIVS error");
		seccomp_release(ctx);
		return -1;
	}
	int r = seccomp_load(ctx);
	if (r < 0) {
		fprintf(stderr, "seccomp_load error: %s\n", strerror(-r));
		seccomp_release(ctx);
		return -1;
	}
	/* ctx is not released: free() may trim the heap with brk or munmap,
	 * which the filter kills. */
	return 0;
}
