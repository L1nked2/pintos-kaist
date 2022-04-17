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
#include "threads/palloc.h" // for exec system call

#define STDIN 1
#define STDOUT 2

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

  // init file_lock
  lock_init(&file_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	/* System calls that return a value can do so by
	modifying the rax member of struct intr_frame */

  // check address depending on syscall argc
	switch ((f->R).rax) {
		case SYS_HALT:
      sys_halt();
			break;	
		case SYS_EXIT:
      sys_exit((f->R).rdi);
			break;
		case SYS_FORK:
      (f->R).rax = sys_fork((f->R).rdi, f);
			break;
		case SYS_EXEC:
      if(sys_exec((f->R).rdi) == -1) {
        sys_exit(-1);
      }
			break;
		case SYS_WAIT:
      (f->R).rax = sys_wait((f->R).rdi);
			break;
		case SYS_CREATE:
      (f->R).rax = sys_create((f->R).rdi, (f->R).rsi);
			break;
		case SYS_REMOVE:
      (f->R).rax = sys_remove((f->R).rdi);
			break;
		case SYS_OPEN:
      (f->R).rax = sys_open((f->R).rdi);
			break;
		case SYS_FILESIZE:
      (f->R).rax = sys_filesize((f->R).rdi);
			break;
		case SYS_READ:
      (f->R).rax = sys_read((f->R).rdi, (f->R).rsi, (f->R).rdx);
			break;
		case SYS_WRITE:
      (f->R).rax = sys_write((f->R).rdi, (f->R).rsi, (f->R).rdx);
			break;
		case SYS_SEEK:
      sys_seek((f->R).rdi, (f->R).rsi);
			break;
		case SYS_TELL:
      (f->R).rax = sys_tell((f->R).rdi);
			break;
		case SYS_CLOSE:
      sys_close((f->R).rdi);
      break;
    case SYS_DUP2:
      (f->R).rax = sys_dup2((f->R).rdi, (f->R).rsi);
      break;
    default:
      sys_exit(-1);
      break;
	}
  return;
}

/* addr must be in user space. */
void validate_addr(const uint64_t *addr) {
	if ((addr == NULL)
  || !(is_user_vaddr(addr))
	|| (pml4_get_page(thread_current()->pml4, addr) == NULL)) {
		sys_exit(-1);
	}
  return;
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
  struct list_elem *e;
  struct list* fdt = &(thread_current()->fdt);
	if (validate_fd(fd)) {
		for(e=list_begin(fdt); e!=list_end(fdt); e=list_next(e)) {
      struct fd *fd_entry = list_entry(e, struct fd, fd_elem);
      if(fd_entry->index == fd) {
        return fd_entry->fp;
      }
    }
	}
	return NULL;
}

void remove_file(int fd) {
  if (validate_fd(fd)) {
    struct list_elem *e;
    struct list *fdt = &(thread_current()->fdt);
    for (e = list_begin(fdt); e != list_end(fdt);) {
      struct fd *fd_entry = list_entry(e, struct fd, fd_elem);
      if (fd_entry->index == fd) {
        file_close(fd_entry->fp);
        e = list_remove(e);
        free(fd_entry);
        break;
      }
      else {
        e = list_next(e);
      }
    }
  }
  return;
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
  validate_addr(thread_name);
  return process_fork(thread_name, if_);
}

int sys_exec(const char *cmd_line) {
  validate_addr(cmd_line);
  // duplicate cmd_line
	char *cmd_line_copy = palloc_get_page(PAL_ZERO);
	if (cmd_line_copy == NULL) {
		sys_exit(-1);
	}
	strlcpy(cmd_line_copy, cmd_line, strlen(cmd_line)+1);
	return process_exec(cmd_line_copy);
}

int sys_wait(tid_t pid) {
  return process_wait(pid);
}

bool sys_create(const char *file, unsigned initial_size) {
  validate_addr(file);
  bool result;
  lock_acquire(&file_lock);
	result = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return result;
}

bool sys_remove(const char *file) {
  validate_addr(file);
  bool result;
  lock_acquire(&file_lock);
	result = filesys_remove(file);
  lock_release(&file_lock);
  return result;
}

int sys_open(const char *file) {
  validate_addr(file);
  if(!validate_fd(list_size(&thread_current()->fdt))) {
    // fd table is too big
		return;
  }
  struct file *open_file = filesys_open(file);
  struct fd* fd;
  if(open_file == NULL) {
    return -1;
  }
  else {
    fd = (struct fd*)malloc(sizeof(struct fd));
    if(fd == NULL) {
      // cannot allocate more using malloc()
      file_close(open_file);
      return -1; 
    }
    fd->fp = open_file;
    fd->index = thread_current()->fdt_index;
    list_push_back(&thread_current()->fdt, &fd->fd_elem);
    thread_current()->fdt_index += 1;
    // deny write to executable
    if(!strcmp(thread_current() -> name, file)) {
      file_deny_write(open_file);
    }
  }
  return fd->index;
}

int sys_filesize(int fd) {
  int result;
  lock_acquire(&file_lock);
	result = file_length(search_file(fd));
  lock_release(&file_lock);
  return result;
}

int sys_read(int fd, void *buffer, unsigned size) {
  validate_addr(buffer);
  int result;
  lock_acquire(&file_lock);
  struct file* file = search_file(fd);
  if(file == STDIN) {
    if (thread_current()->stdin_cnt == 0){
      remove_file(fd);
      result = -1;
    }
    else {
      for(int i=0; i<size; i++)
      {
        ((char*)buffer)[i] = (char)input_getc();
        result = i;
        if(((char*)buffer)[i] == '\0') {
          break;
        }
      }
    }
  }
  else if (file == NULL || fd == STDOUT) {
		result = -1;
	}
  else {
    result = file_read(search_file(fd), buffer, size);
  }
  lock_release(&file_lock);
	return result;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  validate_addr(buffer);
  int result;
	lock_acquire(&file_lock);
	struct file* file = search_file(fd);
  if (file == STDOUT) {
    if (thread_current()->stdout_cnt == 0) {
      remove_file(fd);
      result = -1;
    }
    else {
		  putbuf(buffer, size);
		  result = size;
    }
	}
	else if (file == NULL || file == STDIN) {
		result = -1;
	}
  else {
		result = file_write(file, buffer, size);
	}
  lock_release(&file_lock);
	return result;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire(&file_lock);
  if(fd >= FD_NR_START_INDEX) {
	  search_file(fd)->pos = position;
  }
  lock_release(&file_lock);
}

unsigned sys_tell(int fd) {
  unsigned result = 0;
  lock_acquire(&file_lock);
  if(fd >= FD_NR_START_INDEX) {
	  result = file_tell(search_file(fd));
  }
  lock_release(&file_lock);
  return result;
}

void sys_close(int fd) {
  lock_acquire(&file_lock);
  // if(!validate_fd(fd)) {
  //   lock_release(&file_lock);
	// 	return;
  // }
  struct file *file = search_file(fd);
  if (fd == 0 || file == STDIN) {
    thread_current()->stdin_cnt -= 1;
    remove_file(fd);
    return;
  }
  else if (fd == 1 || file == STDOUT) {
    thread_current()->stdout_cnt -= 1;
    remove_file(fd);
    return;
  }
	remove_file(fd);
  if (file->dup_cnt != 0) {
    file->dup_cnt -= 1;
  }
  lock_release(&file_lock);
	return;
}

int sys_dup2(int oldfd, int newfd) {
  struct file *file = search_file(oldfd);
  if (file == NULL) {
    return -1;                              /* newfd is not closed */
  }
  if (oldfd == newfd) {
    return newfd;
  }
  if (file == STDIN) {
    thread_current()->stdin_cnt += 1;
  }
  else if (file == STDOUT) {
    thread_current()->stdout_cnt += 1;
  }
  else {
    file->dup_cnt += 1;
  }
  sys_close(newfd);
  struct list_elem *e;
  struct list *cur_fdt = &(thread_current()->fdt);
  for (e = list_begin(cur_fdt); e != list_end(cur_fdt); e = list_next(e)) {
    struct fd *fd = list_entry(e, struct fd, fd_elem);
    if (fd->index == newfd) {
      fd->fp = file;
      return newfd;
    }
    else {
      continue;
    }
  }
  struct fd *fd;
  fd->fp = file;
  fd->index = newfd;
  list_push_back(&cur_fdt, &(fd->fd_elem));
  thread_current()->fdt_index += 1;
  return newfd;
}