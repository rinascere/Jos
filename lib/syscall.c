// System call stubs.

#include <inc/syscall.h>
#include <inc/lib.h>

static int32_t
syscall(int num, int check, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5)
{
	int32_t ret;
	asm volatile("pushl %%ecx\n\t"
		 "pushl %%edx\n\t"
	         "pushl %%ebx\n\t"
		 "pushl %%esp\n\t"
		 "pushl %%ebp\n\t"
		 "pushl %%esi\n\t"
		 "pushl %%edi\n\t"
				 
                 //Lab 3: Your code here
		 "movl %%esp,%%ebp\n\t"
                 "leal .after_sysenter_label, %%esi\n\t"
                 "sysenter\n\t"
                 ".after_sysenter_label:\n\t"
	
                 "popl %%edi\n\t"
                 "popl %%esi\n\t"
                 "popl %%ebp\n\t"
                 "popl %%esp\n\t"
                 "popl %%ebx\n\t"
                 "popl %%edx\n\t"
                 "popl %%ecx\n\t"
                 
                 : "=a" (ret)
                 : "a" (num),
                   "d" (a1),
                   "c" (a2),
                   "b" (a3),
                   "D" (a4)
                 : "cc", "memory");


	if(check && ret > 0)
		panic("syscall %d returned %d (> 0)", num, ret);

	return ret;
}

void
sys_cputs(const char *s, size_t len)
{
	syscall(SYS_cputs, 0, (uint32_t)s, len, 0, 0, 0);
}

int
sys_cgetc(void)
{
	return syscall(SYS_cgetc, 0, 0, 0, 0, 0, 0);
}

int
sys_env_destroy(envid_t envid)
{
	return syscall(SYS_env_destroy, 1, envid, 0, 0, 0, 0);
}

envid_t
sys_getenvid(void)
{
	 return syscall(SYS_getenvid, 0, 0, 0, 0, 0, 0);
}

int
sys_map_kernel_page(void* kpage, void* va)
{
	 return syscall(SYS_map_kernel_page, 0, (uint32_t)kpage, (uint32_t)va, 0, 0, 0);
}

void
sys_yield(void)
{
	syscall(SYS_yield, 0, 0, 0, 0, 0, 0);
}

int
sys_page_alloc(envid_t envid, void *va, int perm)
{
	return syscall(SYS_page_alloc, 1, envid, (uint32_t) va, perm, 0, 0);
}

int
sys_page_map(envid_t srcenv, void *srcva, envid_t dstenv, void *dstva, int perm)
{
	uint32_t arglist[5];
	arglist[0] = (uint32_t) srcenv;
	arglist[1] = (uint32_t) srcva;
	arglist[2] = (uint32_t) dstenv;
	arglist[3] = (uint32_t) dstva;
	arglist[4] = (uint32_t) perm;
	//cprintf("in arg srcenv %p sircva %p dstenv %p dstva %p perm %p\n",srcenv,srcva,dstenv,dstva,perm);
	//cprintf("in arglist is %p\n",arglist);
	return syscall(SYS_page_map, 1, (uint32_t)arglist, 0, 0, 0, 0);
}

int
sys_page_unmap(envid_t envid, void *va)
{
	return syscall(SYS_page_unmap, 1, envid, (uint32_t) va, 0, 0, 0);
}

// sys_exofork is inlined in lib.h
/*envid_t
sys_exofork(void){
	return syscall(SYS_exofork,0,0,0,0,0,0);
}*/
int
sys_env_set_status(envid_t envid, int status)
{
	//cprintf("user in envid %p status %p\n",envid,status);
	return syscall(SYS_env_set_status, 1, envid, status, 0, 0, 0);
}

int
sys_env_set_pgfault_upcall(envid_t envid, void *upcall)
{
	return syscall(SYS_env_set_pgfault_upcall, 1, envid, (uint32_t) upcall, 0, 0, 0);
}

int
sys_ipc_try_send(envid_t envid, uint32_t value, void *srcva, int perm)
{
	return syscall(SYS_ipc_try_send, 0, envid, value, (uint32_t) srcva, perm, 0);
}

int
sys_ipc_recv(void *dstva)
{	
	//cprintf("in lib sys_ipc_recv!\n");
	return syscall(SYS_ipc_recv, 1, (uint32_t)dstva, 0, 0, 0, 0);
}
int  
sys_proc_save(envid_t envid, struct proc *ps)  
{  
    return syscall(SYS_proc_save, 1, envid, (uint32_t)ps, 0, 0, 0);  
}  
int  
sys_proc_resume(envid_t envid, const struct proc *ps)
{  
    return syscall(SYS_proc_resume, 1, envid, (uint32_t)ps, 0, 0, 0);  
} 

