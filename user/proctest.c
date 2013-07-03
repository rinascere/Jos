// Ping-pong a counter between two processes.
// Only need to start one of these -- splits into two, crudely.

#include <inc/string.h>
#include <inc/lib.h>

envid_t dumbfork(void);
struct proc ps;

void
umain(int argc, char **argv)
{
	envid_t who;
	int i;
	int j;
	int r;

	// fork a child process
	who = dumbfork();

	
	 if(who){//parent
       	 for (i = 0; i < 10; i++){  
              
           	 cprintf("parent:%d round I am the parent!\n",i );  
            	if (i==1){  
                	if ((r=sys_proc_save(who, &ps)) <0)  
                    		panic("sys_env_save: %e", r);
			cprintf("parent:take a snapshot for child in %d round!\n",i);
           	 }
		if (i==5){  
                	if ((r=sys_proc_resume(who, &ps))<0)  
                   	 	panic("sys_env_restore: %e", r);
			cprintf("parent:resume child from snapshot in %d round!\n",i);
            	}  
      
            	sys_yield();  
	}  
    	}else{//child  
        	for(j=0; j<8; j++){  
            		cprintf("child:%d round I am the chlid\n",j);  
            		sys_yield();
        	}   
    	}
}

void
duppage(envid_t dstenv, void *addr)
{
	int r;

	// This is NOT what you should do in your fork.
	if ((r = sys_page_alloc(dstenv, addr, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_alloc: %e", r);
	if ((r = sys_page_map(dstenv, addr, 0, UTEMP, PTE_P|PTE_U|PTE_W)) < 0)
		panic("sys_page_map: %e", r);
	memmove(UTEMP, addr, PGSIZE);
	if ((r = sys_page_unmap(0, UTEMP)) < 0)
		panic("sys_page_unmap: %e", r);
}

envid_t
dumbfork(void)
{
	envid_t envid;
	uint8_t *addr;
	int r;
	extern unsigned char end[];

	// Allocate a new child environment.
	// The kernel will initialize it with a copy of our register state,
	// so that the child will appear to have called sys_exofork() too -
	// except that in the child, this "fake" call to sys_exofork()
	// will return 0 instead of the envid of the child.
	cprintf("[dumbfork]: in dumbfork!\n");
	envid = sys_exofork();
	cprintf("[dumbfork]:the envid is %d\n",envid);
	if (envid < 0)
		panic("sys_exofork: %e", envid);
	if (envid == 0) {
		// We're the child.
		// The copied value of the global variable 'thisenv'
		// is no longer valid (it refers to the parent!).
		// Fix it and return 0.
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}

	// We're the parent.
	// Eagerly copy our entire address space into the child.
	// This is NOT what you should do in your fork implementation.
	for (addr = (uint8_t*) UTEXT; addr < end; addr += PGSIZE)
		duppage(envid, addr);

	// Also copy the stack we are currently running on.
	duppage(envid, ROUNDDOWN(&addr, PGSIZE));

	// Start the child environment running
	if ((r = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
		panic("sys_env_set_status: %e", r);

	return envid;
}

