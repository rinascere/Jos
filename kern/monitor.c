// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr)); 
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
	// You should use a techique similar to buffer overflow
	// to invoke the do_overflow function and
	// the procedure must return normally.

    // And you must use the "cprintf" function with %n specifier
    // you augmented in the "Exercise 9" to do this job.

    // hint: You can use the read_pretaddr function to retrieve 
    //       the pointer to the function call return address;
    char str[256] = {};
    int nstr = 0;
    char *pret_addr;
	// Your code here.
    pret_addr = (char *)read_pretaddr();
    int i;	
    for(i=0;i<256;i++){
	str[i] = '0';
    }
    void (*dofp)();  
    dofp = do_overflow;
    uint32_t subaddr = (uint32_t)dofp+3;
    //from low to high copy 8bytes each time to overwrite the value pre_addr pointed to
    int j;
    char jtc;
    for(j = 0;j < 4;j++)
    {
        jtc= subaddr>>(8*j) ;
	nstr =  jtc &  0x000000ff;
	str[nstr] = '\0';
        cprintf("%s%n\n",str,pret_addr+j);
	str[nstr] = '0';
    }

}

void
overflow_me(void)
{
        start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    // Your code here.
    unsigned int ebp = read_ebp();
    unsigned int eip;
    cprintf("Stack backtrace:\n");
    do{
      //cprintf("ebp %x eip %x args %x %x %x %x %x\n",ebp,(unsigned int)*(ebp+1),*(ebp+2),*(ebp+3),*(ebp+4),*(ebp+5),*(ebp+6));
      eip = *((unsigned int*)ebp+1);
      cprintf("ebp %08x eip %08x args %08x %08x %08x %08x %08x\n",ebp,eip,*((unsigned int*)ebp+2),
	*((unsigned int*)ebp+3),*((unsigned int*)ebp+4),*((unsigned int*)ebp+5),*((unsigned int*)ebp+6));
      struct Eipdebuginfo dinfo;
      if(debuginfo_eip(eip, &dinfo) == 0){
         char fn[dinfo.eip_fn_namelen+1];
         int i;
         for(i=0;i<dinfo.eip_fn_namelen;i++){
              fn[i] = dinfo.eip_fn_name[i];
         }
         fn[dinfo.eip_fn_namelen]='\0';
         cprintf("%s:%d: %s+%x\n",dinfo.eip_file,dinfo.eip_line,fn,(eip-dinfo.eip_fn_addr));
         //cprintf("%x\n",(eip-dinfo.eip_fn_addr));
      }
      ebp = *((unsigned int *)ebp);
    }while(ebp);
    overflow_me();
    cprintf("Backtrace success\n");
    return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
