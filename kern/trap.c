#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>


/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};
#define SEG_INIT(NUM, PLV){\
	    extern void entry##NUM(); \
	    SETGATE(idt[NUM], 0, GD_KT, entry##NUM, PLV); \
}

#define IRQ_INIT(NUM, PLV){\
	    extern void irq##NUM(); \
	    SETGATE(idt[IRQ_OFFSET+NUM], 0, GD_KT, irq##NUM, PLV); \
}
static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",
		"Debug",
		"Non-Maskable Interrupt",
		"Breakpoint",
		"Overflow",
		"BOUND Range Exceeded",
		"Invalid Opcode",
		"Device Not Available",
		"Double Fault",
		"Coprocessor Segment Overrun",
		"Invalid TSS",
		"Segment Not Present",
		"Stack Fault",
		"General Protection",
		"Page Fault",
		"(unknown trap)",
		"x87 FPU Floating-Point Error",
		"Alignment Check",
		"Machine-Check",
		"SIMD Floating-Point Exception"
	};

	if (trapno < sizeof(excnames)/sizeof(excnames[0]))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}
#define wrmsr(msr,val1,val2) \
	__asm__ __volatile__("wrmsr" \
	: /* no outputs */ \
	: "c" (msr), "a" (val1), "d" (val2))
void
trap_init(void)
{
	extern struct Segdesc gdt[];

	// LAB 3: Your code here.
	SEG_INIT(0,0);
	SEG_INIT(1,0);
	SEG_INIT(2,0);
	SEG_INIT(3,3);
	SEG_INIT(4,0);
	SEG_INIT(5,0);
	SEG_INIT(6,0);
	SEG_INIT(7,0);
	SEG_INIT(8,0);
	SEG_INIT(10,0);
	SEG_INIT(11,0);
	SEG_INIT(12,0);
	SEG_INIT(13,0);
	SEG_INIT(14,0);
	SEG_INIT(16,0);
	SEG_INIT(17,0);
	SEG_INIT(18,0);
	SEG_INIT(19,0);
	//SEG_INIT(48,3);
	//SETGATE(idt[T_SYSCALL],0,GD_KT,sysenter_handler,3)
	// Per-CPU setup 
	/*wrmsr(0x174, GD_KT, 0);
	
   	wrmsr(0x175, KSTACKTOP, 0);

    	wrmsr(0x176, sysenter_handler, 0);*/
	
	//for irq
	IRQ_INIT(0,0);
	IRQ_INIT(1,0);
	IRQ_INIT(2,0);
	IRQ_INIT(3,0);
	IRQ_INIT(4,0);
	IRQ_INIT(5,0);
	IRQ_INIT(6,0);
	IRQ_INIT(7,0);
	IRQ_INIT(8,0);
	IRQ_INIT(9,0);
	IRQ_INIT(10,0);
	IRQ_INIT(11,0);
	IRQ_INIT(12,0);
	IRQ_INIT(13,0);
	IRQ_INIT(14,0);
	IRQ_INIT(15,0);
	
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct Cpu;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:
	struct Taskstate *ts = &(thiscpu->cpu_ts);
	int cpu_i = thiscpu->cpu_id;
	extern void sysenter_handler();
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	
	ts->ts_esp0 = KSTACKTOP-cpu_i*(KSTKSIZE+KSTKGAP);
	ts->ts_ss0 = GD_KD;
	
	wrmsr(0x174, GD_KT, 0);
	
   	wrmsr(0x175, ts->ts_esp0, 0);

    	wrmsr(0x176, sysenter_handler, 0);
	
	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3)+cpu_i] = SEG16(STS_T32A, (uint32_t)ts,
					sizeof(struct Taskstate), 0);
	gdt[(GD_TSS0 >> 3)+cpu_i].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	
	ltr(GD_TSS0+(cpu_i << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	//cprintf("in trap_dispatch and number is %d\n",tf->tf_trapno);
	struct PushRegs *regs;
	int ret;
	switch(tf->tf_trapno){
		case T_PGFLT:
			//cprintf("page fault number is %d\n",tf->tf_trapno);
			page_fault_handler(tf);
			break;
		case T_BRKPT:
			monitor(tf);
			break;
		default:
			break;
	}

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
	if(tf->tf_trapno == IRQ_OFFSET+0 ){ //clock interrupts
		//cprintf("a clock interrupts!\n");
		lapic_eoi();
		//cprintf("clock interrupts schend_yield!\n");
		sched_yield();
	}
	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	//cprintf("in trap and trapno is %d\n",tf->tf_trapno);
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		lock_kernel();
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			cprintf("in trap schend_yield 1 !\n");
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING){
		env_run(curenv);
	}else{
		cprintf("in trap schend_yield 2 !\n");
		sched_yield();
	}
}


void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if((tf->tf_cs & 3) == 0){
		panic("kernel-mode page fault!\n");
	}
	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// The trap handler needs one word of scratch space at the top of the
	// trap-time stack in order to return.  In the non-recursive case, we
	// don't have to worry about this because the top of the regular user
	// stack is free.  In the recursive case, this means we have to leave
	// an extra word between the current top of the exception stack and
	// the new stack frame because the exception stack _is_ the trap-time
	// stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.
	void * upcall = curenv -> env_pgfault_upcall;
	if(curenv->env_pgfault_upcall != NULL){
		//cprintf("[page_fault_handler]:begin!\n");
		struct UTrapframe *uptf;
		uint32_t trap_esp = tf->tf_esp;
		//cprintf("before set uptf address! uptf is %p\n",trap_esp);
		int utsize = sizeof(struct UTrapframe);
		//cprintf("the size of UTrapframe is %d\n", utsize);
		if((trap_esp>=UXSTACKTOP-PGSIZE) && (trap_esp<UXSTACKTOP)){
			uptf = (struct UTrapframe *)(trap_esp-utsize-4);
			//cprintf("the uptf address is %p\n",uptf);
		}else{
			uptf = (struct UTrapframe *)(UXSTACKTOP-utsize);
			//cprintf("the uptf address is %p\n",uptf);
		}
		//cprintf("after 1 set uptf address! uptf is %p\n",uptf);
		user_mem_assert(curenv,(void *)uptf,utsize,PTE_U|PTE_W);

		uptf->utf_esp = tf->tf_esp;
		uptf->utf_eflags = tf->tf_eflags;
		uptf->utf_eip = tf->tf_eip;
		uptf->utf_regs = tf->tf_regs;
		uptf->utf_err = tf->tf_err;
		uptf->utf_fault_va = fault_va;
		//cprintf("after 2 set uptf address! uptf is %p\n",uptf);
		curenv->env_tf.tf_eip = (uint32_t) curenv->env_pgfault_upcall;
		curenv->env_tf.tf_esp = (uint32_t) uptf;
		//cprintf("[page_fault_handler]:run exception func!\n");
		env_run(curenv);
		//cprintf("curenv has run!\n");
	}
	// Destroy the environment that caused the fault.
	cprintf("[%08x] user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}

