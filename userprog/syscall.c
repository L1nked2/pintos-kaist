#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "userprog/process.h"
#include "filesys/filesys.h"	// for file system call.
#include "filesys/file.h"		// for file system call.

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

  // init filesys_lock
  lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	/* System calls that return a value can do so by
	modifying the rax member of struct intr_frame */

  // check address depending on syscall argc
	switch ((f->R).rax) {
		case SYS_HALT:
      sys_halt();
			break;	
		case SYS_EXIT:
      validate_addr((f->R).rdi);
      sys_exit((f->R).rdi);
			break;
		case SYS_FORK:
      validate_addr((f->R).rdi);
      (f->R).rax = sys_fork((f->R).rdi, f);
			break;
		case SYS_EXEC:
      validate_addr((f->R).rdi);
      if(sys_exec((f->R).rdi) == -1) {
        sys_exit(-1);
      }
			break;
		case SYS_WAIT:
      validate_addr((f->R).rdi);
      sys_wait((f->R).rdi);
			break;
		case SYS_CREATE:
      validate_addr((f->R).rdi);
      validate_addr((f->R).rsi);
      sys_create((f->R).rdi, (f->R).rsi);
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
      break;
	}
	thread_exit ();
}

/* addr must be in user space. */
void validate_addr(const uint64_t *addr) {
	if ((addr == NULL)
	|| (pml4_get_page(thread_current()->pml4, addr) == NULL)
	|| !(is_user_vaddr(addr))) {
		sys_exit(-1);
	}
}

/* check whether file descriptor is valid or not*/
bool validate_fd(int fd) {
	if (fd < 0 || fd >= FD_MAX_INDEX) {
		return false;
	}
	else {
		return true;
	}
}

/* search the file with file discriptor */
static struct file *search_file(int fd) {
	if (validate_fd(fd)) {
		return (thread_current()->fd)[fd];
	}
	else {
		return NULL;
	}
}

void sys_halt(void) {
	power_off();
}

void sys_exit(int status) {
	struct thread *cur_thread = thread_current();
	cur_thread->exit_status = status;
	thread_exit();
}

tid_t sys_fork(const char *thread_name, struct intr_frame *if_) {
  return process_fork(thread_name, if_);
}

int sys_exec(const char *cmd_line) {
  int result;
  // need to add filesys_lock inside of precess_exec
	return process_exec(cmd_line);
}

int sys_wait(tid_t pid) {
  process_wait(pid);
  return;
}

bool sys_create(const char *file, unsigned initial_size) {
  bool result;
  lock_acquire(&filesys_lock);
	result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return result;
}

bool sys_remove(const char *file) {
  bool result;
  lock_acquire(&filesys_lock);
	result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;
}

int sys_open(const char *file) {
  struct file *open_file = filesys_open(file);
  if(open_file == NULL) {
    return -1;
  }
  else {
    for (int i=FD_NR_START_INDEX; i<128; i++) {
      if (thread_current()->fd[i] == NULL) {
        thread_current()->fd[i] = open_file; 
        return i;
      }
    }
  }
	return -1; // fd table is full
}

int sys_filesize(int fd) {
	return file_length(search_file(fd));
}

int sys_read(int fd, void *buffer, unsigned size) {
  int result;
  lock_acquire(&filesys_lock);
  if(fd == 0) {
    for(int i=0; i<size; i++)
    {
        ((char*)buffer)[i] = (char)input_getc();
        result = i;
        if(((char*)buffer)[i] == '\0') {
          break;
        }
    }
  }
  else {
  
  }
  lock_release(&filesys_lock);
	return result;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  int result;
  lock_acquire(&filesys_lock);
  if(fd == 1) {
    putbuf(buffer, size);
		result = size;
	}
  else {
    if( != NULL) {
			result = file_write(fd, buffer, size);
		}
		else {
			result = -1;
		}
  }
  lock_release(&filesys_lock);
	return;
}

void sys_seek(int fd, unsigned position) {
	search_file(fd)->pos = position;
}

unsigned sys_tell(int fd) {
	return file_tell(seach_file(fd));
}

void sys_close(int fd) {
	if (validate_fd(fd)) {
		thread_current()->fd[fd] = NULL;
	}
	return;
}
