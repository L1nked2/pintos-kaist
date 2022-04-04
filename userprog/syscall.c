#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "filesys/filesys.h" // for file system call.

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	/* System calls that return a value can do so by
	modifying the rax member of struct intr_frame */
	switch ((f->R).rax) {
		case SYS_HALT:
			break;	
		case SYS_EXIT:
			break;
		case SYS_FORK:
			break;
		case SYS_EXEC:
			break;
		case SYS_WAIT:
			break;
		case SYS_CREATE:
			break;
		case SYS_REMOVE:
			break;
		case SYS_OPEN:
			break;
		case SYS_FILESIZE:
			break;
		case SYS_READ:
			break;
		case SYS_WRITE:
			break;
		case SYS_SEEK:
			break;
		case SYS_TELL:
			break;
		case SYS_CLOSE:
	}
	thread_exit ();
}

/* addr must be in user space. */
void validate_addr(const uint64_t *addr) {
	if ((addr == NULL)
	|| (pml4_get_page(thread_current()->pml4, addr) == NULL)
	|| !(is_user_vaddr(addr))) {
		exit(-1);
	}
}

void halt(void) {
	power_off();
}

void exit(int status) {
	struct thread *cur_thread = thread_current();
	cur_thread->exit_status = status;
	printf("%s: exit(%d)\n", cur_thread->name, status);
	thread_exit();
}

uint64_t fork(const char *thread_name) {
	return;
}

int exec(const char *cmd_line) {
	return;
}

int wait(uint64_t pid) {
	return;
}

bool create(const char *file, unsigned initial_size) {
	validate_addr(file);
	bool success = filesys_create(file, initial_size);
	return success;
}

bool remove(const char *file) {
	validate_addr(file);
	bool success = filesys_remove(file);
	return success;
}

int open(const char *file) {
	validate_addr(file);
	return;
}

int filesize(int fd) {
	return;
}

int read(int fd, void *buffer, unsigned size) {
	return;
}

int write(int fd, const void *buffer, unsigned size) {
	return;
}

void seek(int fd, unsigned position) {
	return;
}

unsigned tell(int fd) {
	return;
}

void close(int fd) {
	return;
}