// Test preemption by forking off a child process that just spins forever.
// Let it run for a couple time slices, then kill it.

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	envid_t env;

	cprintf("I am the parent.  Forking the child...\n");
	if ((env = fork()) == 0) {
		cprintf("I am the child.  Spinning...\n");
		while (1)
			/* do nothing */;
	}

	cprintf("I am the parent.  Running the child...\n");
	sys_yield();
	cprintf("1 yield!\n");
	sys_yield();
	cprintf("2 yield!\n");
	sys_yield();
	cprintf("3 yield!\n");
	sys_yield();
	cprintf("4 yield!\n");
	sys_yield();
	cprintf("5 yield!\n");
	sys_yield();
	cprintf("6 yield!\n");
	sys_yield();
	cprintf("7 yield!\n");
	sys_yield();
	cprintf("8 yield!\n");

	cprintf("I am the parent.  Killing the child...\n");
	sys_env_destroy(env);
}

