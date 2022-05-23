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

/* for VM */
#include "threads/vaddr.h"
#include "vm/vm.h"

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
    case SYS_MMAP:
      (f->R).rax = sys_mmap((f->R).rdi, (f->R).rsi, (f->R).rdx, (f->R).r10, (f->R).r8);
      break;
    case SYS_MUNMAP:
      sys_munmap((f->R).rdi);
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
  || (is_kernel_vaddr(addr))
  || (spt_find_page(&thread_current()->spt, addr) == NULL)) {
		sys_exit(-1);
	}
  return;
}

/* addr must be in user space. */
//TIP: uint8_t for correct iteration
void validate_buffer(const uint8_t *addr, unsigned size, bool to_write) {
  for(int i=0; i<size; i++) {
    validate_addr(addr+i);
    struct page* page = spt_find_page(&thread_current()->spt, addr+i);
    if(page == NULL) {
      sys_exit(-1);
    }
    if(to_write == true && page->writable == false) {
      sys_exit(-1);
    }
  }
  return;
}

// fd_dup search helper
struct fd_dup *search_fd_dup(int fd) {
  struct list_elem *e;
	struct list* fdt_dup = &(thread_current()->fdt_dup);
  for(e=list_begin(fdt_dup); e!=list_end(fdt_dup); e=list_next(e)) {
    struct fd_dup *fd_dup_entry = list_entry(e, struct fd_dup, fd_dup_elem);
    if(fd_dup_entry->index == fd) {
      return fd_dup_entry;
    }
  }
	return NULL;
}

// fd search helper
struct fd *search_fd(int fd) {
  struct list_elem *e;
  struct list* fdt = &(thread_current()->fdt);
  struct fd_dup *fd_dup = search_fd_dup(fd);
  if(fd_dup == NULL) {
    return NULL;
  }
  for(e=list_begin(fdt); e!=list_end(fdt); e=list_next(e)) {
    struct fd *fd_entry = list_entry(e, struct fd, fd_elem);
    if(fd_entry->index == fd_dup->origin_index) {
      return fd_entry;
    }
  }
	return NULL;
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
  if(list_size(&thread_current()->fdt_dup) > FD_MAX_INDEX) {
    // fd table is too big
		return -1;
  }
  // allocate required fields
  struct fd* fd = (struct fd*)malloc(sizeof(struct fd));
  struct fd_dup *fd_dup = (struct fd_dup *)malloc(sizeof(struct fd_dup));
  struct file *open_file = filesys_open(file);
  ///struct fd* fd = (struct fd*)palloc_get_page(PAL_ZERO);
  ///struct fd_dup *fd_dup = (struct fd_dup *)palloc_get_page(PAL_ZERO);
  if(fd == NULL || open_file == NULL || fd_dup == NULL) {
      // cannot allocate more
      file_close(open_file);
      free(fd);
      free(fd_dup);
      ///palloc_free_page(fd);
      ///palloc_free_page(fd_dup);
      return -1; 
  }
  // add actual file to fdt
  fd->fp = open_file;
  fd->index = thread_current()->fdt_index;
  fd->dup_cnt = 1;
  fd->fp_secure = true;
  list_push_back(&thread_current()->fdt, &fd->fd_elem);
  thread_current()->fdt_index += 1;
  // deny write to executable
  if(!strcmp(thread_current() -> name, file)) {
    file_deny_write(open_file);
  }
  // add mapping to fdt_dup
  fd_dup->index = thread_current()->fdt_dup_index;
  fd_dup->origin_index = fd->index;
  list_push_back(&thread_current()->fdt_dup, &fd_dup->fd_dup_elem);
  thread_current()->fdt_dup_index += 1;
  return fd_dup->index;
}

int sys_filesize(int fd) {
  int result;
  lock_acquire(&file_lock);
	result = file_length(search_fd(fd)->fp);
  lock_release(&file_lock);
  return result;
}

int sys_read(int fd, void *buffer, unsigned size) {
  validate_buffer(buffer, size, true);
  int result;
  lock_acquire(&file_lock);
  struct fd* fd_entry = search_fd(fd);
  if(fd_entry == NULL) {
    result = -1;
  }
  else if(fd_entry->fp == STDIN) {
    if (thread_current()->stdin_cnt <= 0){
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
  else if (fd_entry->fp == NULL || fd_entry->fp == STDOUT) {
		result = -1;
	}
  else {
    result = file_read(fd_entry->fp, buffer, size);
  }
  lock_release(&file_lock);
	return result;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  validate_buffer(buffer, size, false);
  int result;
	lock_acquire(&file_lock);
	struct fd* fd_entry = search_fd(fd);
  if(fd_entry == NULL) {
    result = -1;
  }
  else if (fd_entry->fp == STDOUT) {
    if (thread_current()->stdout_cnt <= 0) {
      result = -1;
    }
    else {
		  putbuf(buffer, size);
		  result = size;
    }
	}
	else if (fd_entry->fp == NULL || fd_entry->fp == STDIN) {
		result = -1;
	}
  else {
		result = file_write(fd_entry->fp, buffer, size);
	}
  lock_release(&file_lock);
	return result;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire(&file_lock);
  struct fd* fd_entry = search_fd(fd);
  if(fd_entry != NULL && fd_entry->fp_secure == true) {
	  fd_entry->fp->pos = position;
  }
  lock_release(&file_lock);
}

unsigned sys_tell(int fd) {
  unsigned result = 0;
  lock_acquire(&file_lock);
  struct fd* fd_entry = search_fd(fd);
  if(fd_entry != NULL && fd_entry->fp_secure == true) {
	  result = file_tell(fd_entry->fp);
  }
  lock_release(&file_lock);
  return result;
}

void sys_close(int fd) {
  lock_acquire(&file_lock);
  struct fd_dup *fd_dup_entry = search_fd_dup(fd);
  struct fd *fd_entry = search_fd(fd);
  // return if fd_dup is not found
  if(fd_dup_entry == NULL || fd_entry == NULL) {
    lock_release(&file_lock);
	  return;
  }
  // STDIN, STDOUT case
  else if (fd_entry->fp == STDIN) {
    thread_current()->stdin_cnt -= 1;
    list_remove(&fd_dup_entry->fd_dup_elem);
    free(fd_dup_entry);
    ///palloc_free_page(fd_dup_entry);
  }
  else if (fd_entry->fp == STDOUT) {
    thread_current()->stdout_cnt -= 1;
    list_remove(&fd_dup_entry->fd_dup_elem);
    free(fd_dup_entry);
    ///palloc_free_page(fd_dup_entry);
  }
  // normal fd_dup case
  else {
    // reduce dup_cnt and close fd if zero
    fd_entry->dup_cnt -= 1;
    if(fd_entry->dup_cnt == 0) {
      file_close(fd_entry->fp);
      list_remove(&fd_entry->fd_elem);
      free(fd_entry);
      ///palloc_free_page(fd_entry);
    }
    // delete fd_dup
    list_remove(&fd_dup_entry->fd_dup_elem);
    free(fd_dup_entry);
    ///palloc_free_page(fd_dup_entry);
  } 
  lock_release(&file_lock);
	return;
}

int sys_dup2(int oldfd, int newfd) {
  if(list_size(&thread_current()->fdt_dup) > FD_MAX_INDEX) {
    // fd table is too big
		return -1;
  }
  // check oldfd validity
  struct fd *old_fd = search_fd(oldfd);
  if (old_fd == NULL) {
    return -1;
  }
  // check if newfd is identical to oldfd
  if (oldfd == newfd) {
    return newfd;
  }
  // make new_fd_dup using old_fd and add to fdt_dup
  struct fd_dup *fd_dup = (struct fd_dup *)malloc(sizeof(struct fd_dup));
  ///struct fd_dup *fd_dup = (struct fd_dup *)palloc_get_page(PAL_ZERO);
  if(fd_dup == NULL) {
    return -1;
  }
  // check newfd is opened and close if true
  sys_close(newfd);

  //fd_dup->index = thread_current()->fdt_dup_index;
  fd_dup->index = newfd;
  fd_dup->origin_index = old_fd->index;
  list_push_back(&thread_current()->fdt_dup, &fd_dup->fd_dup_elem);
  thread_current()->fdt_dup_index =
   thread_current()->fdt_dup_index > newfd ? thread_current()->fdt_dup_index : newfd;
  thread_current()->fdt_dup_index += 1;
  // increase stdin_cnt or stdout_cnt is it is the case that
  if(old_fd->fp == STDIN) {
    thread_current()->stdin_cnt += 1;
  }
  else if(old_fd->fp == STDOUT) {
    thread_current()->stdout_cnt += 1;
  }
  // increase dup_cnt of old_fd
  else {
    old_fd->dup_cnt += 1;
  }
  // return result
  return newfd;
}

void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
  validate_addr(addr);
  // check if console input and output
  if (fd < FD_NR_START_INDEX) {
    return NULL;
  }
  // check if addr is page-aligned
  if ((offset%PGSIZE != 0)||(addr != pg_round_down(addr))||(length <= 0))
    return NULL;
  // get fd and call do_mmap
  struct fd *fd_entry = search_fd(fd);
  if (fd_entry == NULL)
    return NULL;
  struct file *file = fd_entry->fp;
  if (file == NULL)
    return NULL;
  return do_mmap(addr, length, writable, file, offset);
}

void sys_munmap(void *addr){
  do_munmap(addr);
  return;
}