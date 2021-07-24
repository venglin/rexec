/*
 * rexec 1.2
 * noexec mechanism and execve() logging
 * 
 * (c) 2000-2011 Przemyslaw Frasunek <przemyslaw@frasunek.com>
 * Based on work by:
 *  (c) 2000 Zbyszek Sobiecki <kodzak@mtl.pl>
 *  (c) 2002-2003 Pawel Jakub Dawidek <nick@garage.freebsd.pl>
 *
 * Version 1.2 Sponsored by INTEN Jaroslaw Granat <http://www.inten.pl/>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>

#include "rexec.h"

unsigned int rexec_sysctl_logargs = 1;
int rexec_sysctl_logall = -1;
gid_t rexec_sysctl_exec_group = 666;
uid_t rexec_sysctl_max_bin_uid = 999;

static int rexec_copyin(struct execve_args *ea) {
	char **argv = ea->argv, **envv = ea->envv;
	char *argp = NULL, *envp = NULL, *argsbuf = NULL;
	size_t length = 0, space = ARG_MAX;
	int ret = 0;

	if (ea->fname == NULL || USPACE(ea->fname))
		return EFAULT;

	if (strlen(ea->fname) > PATH_MAX)
		return E2BIG;

	if (ea->argv == NULL)
		return EFAULT;

	if ((argsbuf = malloc(ARG_MAX, M_TEMP, M_WAITOK)) == NULL)
		return ENOMEM;


	while ((argp = (caddr_t) (intptr_t) fuword(argv++))) {
		if (argp == (caddr_t) -1) {
			ret = EFAULT;
			goto error;
		}

		if ((ret = copyinstr(argp, argsbuf, space, &length)) != 0) {
			if (ret == ENAMETOOLONG)
				ret = E2BIG;
			goto error;
		}
		space -= length;
	}

	if (envv)
		while ((envp = (caddr_t)(intptr_t)fuword(envv++))) {
			if (envp == (caddr_t)-1) {
				ret = EFAULT;
				goto error;
			}

			if ((ret = copyinstr(envp, argsbuf, space, &length)) != 0) {
				if (ret == ENAMETOOLONG)
					ret = E2BIG;
				goto error;
			}

			space -= length;
		}

error:
	if (argsbuf != NULL)
		free(argsbuf, M_TEMP);
	return ret;
}

static int rexec_noexec(struct thread *td) {
	int i = 0;

	if (td->td_ucred->cr_ruid == 0)
		return 0;

	for (i = 0; i < td->td_ucred->cr_ngroups; i++) {
		if (td->td_ucred->cr_groups[i] == (gid_t)rexec_sysctl_exec_group)
			return 0;
	}

	return 1;
}

static int rexec_envclean(char **envv) {
	char **bp = NULL, **q = NULL;
	
	for (bp = envv; *bp != NULL; bp++) {
		if (strncmp(*bp, "LD_", 3) == 0) {
			for(q = bp;; q++) {
				if ((*q = *(q + 1)) == NULL)
					break;
			}
			bp--;
		}
	}

	return 0;
}

static int rexec_fmtcaller(struct thread *td, char *buf, size_t length) {
	struct proc *p = td->td_proc;

	PROC_LOCK(p);
	snprintf(buf, length, "(called by %s [%d]) (uid=%d, gid=%d, euid=%d, egid=%d)",
		p->p_comm, p->p_pid, p->p_ucred->cr_ruid, p->p_ucred->cr_rgid,
		p->p_ucred->cr_uid,  p->p_ucred->cr_gid);
	PROC_UNLOCK(p);

	return 0;
}

static int rexec_execlog_args(struct thread *td, struct execve_args *ea, int denied) {
	char **argv = ea->argv;
	char *argp = NULL, *argsbuf = NULL;
	size_t args_size = 1;
	char caller[256];

	while ((argp = *argv++))
		args_size += strlen(argp) + 1;

	if ((argsbuf = malloc(args_size, M_TEMP, M_WAITOK)) == NULL)
		return ENOMEM;

	argsbuf[0] = '\0';

	argv = ea->argv;
	while ((argp = *argv++)) {
		strlcat(argsbuf, argp, args_size);
		strlcat(argsbuf, " ", args_size);
	}

	rexec_fmtcaller(td, caller, sizeof(caller));
	log(LOG_INFO, "rexec: %s[%s] %s%s\n", (denied == 0 ? "" : "Permission denied: "), ea->fname, argsbuf, caller);
	free(argsbuf, M_TEMP);

	return 0;
}

static int rexec_execlog(struct thread *td, struct execve_args *ea, int denied) {
	char caller[256];

	rexec_fmtcaller(td, caller, sizeof(caller));
	log(LOG_INFO, "rexec: %s[%s] %s\n", (denied == 0 ? "" : "Permission denied: "), ea->fname, caller);

	return 0;
}


static int rexec_execve(struct thread *td, struct execve_args *ea) {
	int ret = 0, noexec = 0;
	struct nameidata nd, *ndp = &nd;
	struct vattr va;

	if ((ret = rexec_copyin(ea)))
		return ret;

	if (rexec_noexec(td)) {
		if (ea->envv)
			rexec_envclean(ea->envv);

		NDINIT(ndp, LOOKUP, FOLLOW | SAVENAME, UIO_USERSPACE, ea->fname, td);
		if ((ret = namei(ndp)) != 0)
			return ret;
		ret = VOP_GETATTR(ndp->ni_vp, &va, td->td_ucred);
		if (ndp->ni_vp) {
			NDFREE(ndp, NDF_ONLY_PNBUF);
			vrele(ndp->ni_vp);
		}
		if (ret != 0)
			return ret;
		if (va.va_uid > rexec_sysctl_max_bin_uid)
			noexec = 1;
	}

	if (rexec_sysctl_logall > 0 || (rexec_sysctl_logall == 0 && td->td_ucred->cr_ruid > 0)) {
		if (rexec_sysctl_logargs)
			 ret = rexec_execlog_args(td, ea, noexec);
		else
			ret = rexec_execlog(td, ea, noexec);
	} else if (rexec_sysctl_logall < 0 && noexec != 0) {
		if (rexec_sysctl_logargs)
			ret = rexec_execlog_args(td, ea, noexec);
		else
			ret = rexec_execlog(td, ea, noexec);
	}

	if (ret != 0)
		return ret;

	if (noexec != 0)
		return EACCES;

	return sys_execve(td, ea);
}

static struct sysent rexec_execve_sysent = {
	(void *)rexec_execve,
	NULL,
	3
};

static int mod(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
		case MOD_LOAD:
			sysent[SYS_execve] = rexec_execve_sysent;
                        log(LOG_INFO, "rexec loaded.\n");
			break;

		case MOD_UNLOAD:
			sysent[SYS_execve].sy_call = (sy_call_t *)sys_execve;
                        log(LOG_INFO, "rexec unloaded.\n");
			break;

		default:
			error = EOPNOTSUPP;
			break;
	}

	return error;
}

static moduledata_t rexec_mod = {
	"rexec",
	&mod,
	NULL
};

DECLARE_MODULE(rexec, rexec_mod, SI_SUB_EXEC, SI_ORDER_MIDDLE);

SYSCTL_NODE(_security, OID_AUTO, rexec, CTLFLAG_RD, 0, "rexec configuration");

SYSCTL_UINT(_security_rexec, OID_AUTO, logargs, CTLFLAG_RW,
	&rexec_sysctl_logargs, 0, "Log all arguments");

SYSCTL_INT(_security_rexec, OID_AUTO, logall, CTLFLAG_RW,
        &rexec_sysctl_logall, 0, "Log all users (incl. root)");

SYSCTL_UINT(_security_rexec, OID_AUTO, exec_group, CTLFLAG_RW,
        &rexec_sysctl_exec_group, 0, "Group allowed to exec binaries");

SYSCTL_UINT(_security_rexec, OID_AUTO, max_bin_uid, CTLFLAG_RW,
        &rexec_sysctl_max_bin_uid, 0, "Last allowed UID for binaries called by user");
