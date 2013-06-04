// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at vpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.
	if ((err & FEC_WR) == 0) {
		panic("pgfault: not a write fault!");
	}

	if ((vpd[PDX(addr)] & PTE_P) == 0) {
		panic("pgfault: page directory not exists!");
	}
	// check PTE_COW
	if ((vpt[PGNUM(addr)] &  PTE_COW) == 0) {
		panic("pgfault: not a copy-on-write fault!");
	}
	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	// LAB 4: Your code here.

	//panic("pgfault not implemented");
	r = sys_page_alloc(0, (void *)PFTEMP, PTE_U | PTE_W | PTE_P);
	if (r < 0) {
		panic("pgfault: alloc temporary location failed %e", r);
	}
	void *va = (void *)ROUNDDOWN(addr, PGSIZE);
	memmove((void *)PFTEMP, va, PGSIZE);
	//move the new page to the old page's address
	r = sys_page_map(0, (void *)PFTEMP, 0, va, PTE_U | PTE_W | PTE_P);
	if (r < 0) 
		panic("pgfault: %e", r);
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
	
	// LAB 4: Your code here.
	//panic("duppage not implemented");
	void * addr = (void *) (pn * PGSIZE);
	if ((uint32_t)addr >= UTOP) {
		panic("duppage: duplicate page above UTOP!");
	}

	pde_t pde;
	pde = vpd[PDX(addr)];
	
	pte_t pte;
	pte = vpt[PGNUM(addr)];

	if ((pde & PTE_P) == 0)
		panic("duppage: page directory not present!");
	
	if ((pte & PTE_P) == 0)
		 panic("duppage: page table not present!");
	
	if ((pte & (PTE_W | PTE_COW)) != 0) {
		r = sys_page_map(0, addr, envid, addr, PTE_U | PTE_P | PTE_COW);
		if (r < 0) 
			panic("duppage map page copy on write %e", r);
				
		r = sys_page_map(0, addr,     0, addr, PTE_U | PTE_P | PTE_COW);
		if (r < 0) 
			panic("duppage map page copye on write %e", r);
			
	}else {
		r = sys_page_map(0, addr, envid, addr, PTE_U | PTE_P);
		if (r < 0) 
			panic("duppage map page in read only %e", r);
			
	}
	
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use vpd, vpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
	//panic("fork not implemented");
	//cprintf("in lib fork!\n");
	set_pgfault_handler(pgfault);
	
	envid_t childid;
	childid = sys_exofork();
	
	if(childid == 0){
		thisenv = &envs[ENVX(sys_getenvid())];
		return 0;
	}
	if(childid < 0){
		panic("fork error:%e",childid);
	}
	
		
	int r;
	int pno;
	for (pno = UTEXT/PGSIZE; pno < UTOP/PGSIZE; pno++) {
		if (pno == (UXSTACKTOP - PGSIZE)/PGSIZE) {
			continue;
		}
		if (((vpd[pno/NPTENTRIES] & PTE_P) != 0) && ((vpt[pno] & PTE_P) != 0) && ((vpt[pno] & PTE_U) != 0)) {
			duppage(childid, pno);
		}
	}

	r = sys_page_alloc(childid,(void *)(UXSTACKTOP-PGSIZE),PTE_U|PTE_W|PTE_P);
	if(r < 0)
		panic("set child exception stack error %e\n",r);	
	
	extern void _pgfault_upcall (void);
	r = sys_env_set_pgfault_upcall(childid, (void *)_pgfault_upcall);
	if(r < 0)
		panic("set child pgfault_upcall error %e\n",r);
	
	r = sys_env_set_status(childid,ENV_RUNNABLE);
	if(r < 0)
		panic("set child status error %e\n",r);
	//cprintf("finish lib fork!\n");
	return childid;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
