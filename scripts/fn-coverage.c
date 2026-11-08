// Prints each function of a program the first time it runs, with one-shot breakpoints set from `nm` output.
// Used by scripts/hot-functions.sh. Usage: COV_OUT=<file> fn-coverage <nm-file> <program> [args...]
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

struct fn { unsigned long addr; char name[400]; unsigned char saved; char armed; };
static struct fn *fns;
static int count;

static int by_addr(const void *x, const void *y) {
	unsigned long a = ((const struct fn *)x)->addr, b = ((const struct fn *)y)->addr;
	return a < b ? -1 : a > b;
}
static struct fn *find(unsigned long a) {
	int lo = 0, hi = count - 1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (fns[m].addr == a) return &fns[m];
		if (fns[m].addr < a) lo = m + 1; else hi = m - 1;
	}
	return 0;
}
int main(int argc, char **argv) {
	FILE *out = fopen(getenv("COV_OUT"), "a"), *f = fopen(argv[1], "r");
	char type[8], name[4096], path[64], line[512];
	unsigned long a, base = 0;
	fns = calloc(200000, sizeof *fns);
	while (fscanf(f, "%lx %7s %4095s", &a, type, name) == 3) {
		if (strlen(name) < 400) { fns[count].addr = a; strcpy(fns[count].name, name); count++; }
	}
	qsort(fns, count, sizeof *fns, by_addr);
	int n = 0;
	for (int i = 0; i < count; i++) if (!n || fns[n - 1].addr != fns[i].addr) fns[n++] = fns[i];
	count = n;

	pid_t child = fork();
	if (!child) {
		personality(ADDR_NO_RANDOMIZE);
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		execv(argv[2], argv + 2);
		_exit(127);
	}
	int st;
	waitpid(child, &st, 0);
	sprintf(path, "/proc/%d/maps", child);
	f = fopen(path, "r");
	if (fgets(line, sizeof line, f)) sscanf(line, "%lx", &base);
	fclose(f);
	sprintf(path, "/proc/%d/mem", child);
	int mem = open(path, O_RDWR);
	for (int i = 0; i < count; i++) {
		unsigned char trap = 0xcc;
		fns[i].addr += base;
		if (pread(mem, &fns[i].saved, 1, fns[i].addr) == 1 && pwrite(mem, &trap, 1, fns[i].addr) == 1) fns[i].armed = 1;
	}
	ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL);
	ptrace(PTRACE_CONT, child, 0, 0);
	for (int live = 1; live > 0;) {
		pid_t w = waitpid(-1, &st, __WALL);
		if (w < 0) break;
		if (WIFEXITED(st) || WIFSIGNALED(st)) { live--; continue; }
		int sig = WSTOPSIG(st);
		if (sig == SIGTRAP) {
			if (st >> 16 == PTRACE_EVENT_CLONE) live++;
			else {
				struct user_regs_struct r;
				ptrace(PTRACE_GETREGS, w, 0, &r);
				struct fn *h = find(r.rip - 1);
				if (h) {
					// another thread can hit the same trap after it is removed, so step back in every case
					if (h->armed) { h->armed = 0; pwrite(mem, &h->saved, 1, h->addr); fprintf(out, "%s\n", h->name); fflush(out); }
					r.rip -= 1;
					ptrace(PTRACE_SETREGS, w, 0, &r);
				}
			}
			sig = 0;
		} else if (sig == SIGSTOP) sig = 0;
		ptrace(PTRACE_CONT, w, 0, sig);
	}
	return 0;
}
