#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

#include "userprog/syscall.h"

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
  sema_up(&current->load_sema);
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
	
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
  /* save name for exit message */
  char *f_name_copy = palloc_get_page(PAL_ZERO);
  char *save_ptr;
  strlcpy(f_name_copy, f_name, strlen(f_name)+1);
  char* name = strtok_r(f_name_copy, " ", &save_ptr);
  strlcpy(&thread_current()->name, name, strlen(name)+1);
  palloc_free_page(f_name_copy);

  /* build up STDIN & STDOUT file descriptor*/
  //struct fd *stdin_fd = (struct fd*)malloc(sizeof(struct fd));
	//struct fd *stdout_fd = (struct fd*)malloc(sizeof(struct fd));
  //struct fd_dup *stdin_fd_dup = (struct fd_dup*)malloc(sizeof(struct fd_dup));
	//struct fd_dup *stdout_fd_dup = (struct fd_dup*)malloc(sizeof(struct fd_dup));
  struct fd *stdin_fd = (struct fd*)palloc_get_page(PAL_ZERO);
  struct fd *stdout_fd = (struct fd*)palloc_get_page(PAL_ZERO);
  struct fd_dup *stdin_fd_dup = (struct fd_dup*)palloc_get_page(PAL_ZERO);
	struct fd_dup *stdout_fd_dup = (struct fd_dup*)palloc_get_page(PAL_ZERO);

	stdin_fd->fp = STDIN;
	stdin_fd->index = 0;
  stdin_fd->fp_secure = false;
	stdout_fd->fp = STDOUT;
	stdout_fd->index = 1;
  stdout_fd->fp_secure = false;
	list_push_back(&thread_current()->fdt, &stdin_fd->fd_elem);
	list_push_back(&thread_current()->fdt, &stdout_fd->fd_elem);
  
  stdin_fd_dup->origin_index = 0;
  stdin_fd_dup->index = 0;
  stdout_fd_dup->origin_index = 1;
  stdout_fd_dup->index = 1;
  list_push_back(&thread_current()->fdt_dup, &stdin_fd_dup->fd_dup_elem);
	list_push_back(&thread_current()->fdt_dup, &stdout_fd_dup->fd_dup_elem);

  // load is done
  sema_up(&thread_current()->load_sema);

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	/* Clone current thread to new thread.*/
  struct thread *child;
  tid_t child_tid;

  thread_current()->user_if = if_;
  child_tid = thread_create (name, PRI_DEFAULT, __do_fork, thread_current ());
  if (child_tid == TID_ERROR) {
		return TID_ERROR;
	}
  child = get_child_thread(child_tid);
  sema_down(&child->load_sema);
  if (child->exit_status == -1) {
	  return TID_ERROR;
  }
  return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the va is kernel address, then return immediately. */ // fixed comments, parent_page -> va
  if(is_kernel_vaddr(va)) {
    return true;
  }
	/* 2. Resolve parent_page from the parent's page map level 4. */ // fixed comments, va -> parent_page
	if ((parent_page = pml4_get_page (parent->pml4, va)) == NULL) {
		return false;
	}
  // parent_page now holds the address of page and it is
  // traslated address of user virtual address to kernel virtual address.
  // we need translation because concating parent->pml4 and va gives only physical frame info.
  // Thus, we need kernel virtual address pointing to target physical frame info.

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
  //newpage = palloc_get_page(PAL_USER | PAL_ZERO);
  // newpage holds kernel virtual addresses
  // and it is page of user pool.
  // it is pointing to empty physical frame(zerofilled).
  if((newpage = palloc_get_page(PAL_USER | PAL_ZERO)) == NULL) {
    return false;
  }

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
  memcpy(newpage, parent_page, PGSIZE);
  writable = is_writable(pte);
  // information in parent_page is duplicated, 
  // from now dereferencing newpage gives result
  // identical to dereferencing parent page.

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
    // now we add mapping, current->pml4 to newpage
    // but we should use same va for correct duplication.
    // this function gives that feature, from now
    // concating current->pml4 and va gives physical frame
    // identical to physical frame refered by newpage. 
		/* 6. TODO: if fail to insert page, do error handling. */
      palloc_free_page(newpage);
      return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
  struct intr_frame *parent_if = parent->user_if;
	bool succ = true;
  bool debug = false;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));
  /* return value of child process is 0 */
  if_.R.rax = 0;

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL) {
    if(debug)
      printf("error on pml4_create\n");
		goto error;
  }

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) {
    if(debug)
      printf("error on pml4_for_each\n");
		goto error;
  }
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

  // duplicate file objects
  struct list_elem *e;
  struct list* parent_fdt = &(parent->fdt);
  struct list* parent_fdt_dup = &(parent->fdt_dup);
  struct list* current_fdt = &(current->fdt);
  struct list* current_fdt_dup = &(current->fdt_dup);
  current->fdt_index = parent->fdt_index;
  current->fdt_dup_index = parent->fdt_dup_index;
  current->stdin_cnt = parent->stdin_cnt;
  current->stdout_cnt = parent->stdout_cnt;

  // deep-copy parent fdt to current_fdt
  for(e=list_begin(parent_fdt); e!=list_end(parent_fdt); e=list_next(e)) {
    struct fd *src_fd = list_entry(e, struct fd, fd_elem);
    ///struct fd *dst_fd = (struct fd*)malloc(sizeof(struct fd));
    struct fd *dst_fd = (struct fd*)palloc_get_page(PAL_ZERO);
    if(dst_fd == NULL) {
      // malloc failed
      if(debug)
        printf("error on malloc 1\n");
      goto error;
    }
    // handle stdin and stdout
    if(src_fd->fp == STDIN || src_fd->fp == STDOUT) {
      dst_fd->fp = src_fd->fp;
      dst_fd->fp_secure = false;
    }
    // or just duplicate file
    else {
      dst_fd->fp = file_duplicate(src_fd->fp);
      dst_fd->fp_secure = true;
      // check if file_duplicate failed
      if(dst_fd->fp == NULL) {
        //free(dst_fd);
        palloc_free_page(dst_fd);
        if(debug)
          printf("error on file_duplicate\n");
        goto error;
      }
    }
    dst_fd->index = src_fd->index;
    dst_fd->dup_cnt = src_fd->dup_cnt;
    list_push_back(current_fdt, &(dst_fd->fd_elem));
  }

  // shallow-copy parent fdt_dup to current_fdt_dup
  for(e=list_begin(parent_fdt_dup); e!=list_end(parent_fdt_dup); e=list_next(e)) {
    struct fd_dup *src_fd_dup = list_entry(e, struct fd_dup, fd_dup_elem);
    //struct fd_dup *dst_fd_dup = (struct fd_dup*)malloc(sizeof(struct fd_dup));
    struct fd_dup *dst_fd_dup = (struct fd_dup*)palloc_get_page(PAL_ZERO);
    if(dst_fd_dup == NULL) {
      if(debug)
        printf("error on malloc 2\n");
      goto error;
    }
    dst_fd_dup->index = src_fd_dup->index;
    dst_fd_dup->origin_index = src_fd_dup->origin_index;
    list_push_back(current_fdt_dup, &(dst_fd_dup->fd_dup_elem));
  }

	sema_up(&thread_current()->load_sema);

  // copy is_user_thread flag
  current->is_user_thread = parent->is_user_thread;

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	current->exit_status = TID_ERROR;
	sema_up(&current->load_sema);
	thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;
	int argc = 0;
	char *argv[64];

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
  struct thread *cur = thread_current();
	process_cleanup ();
	supplemental_page_table_init(&cur->spt);

	/* Parse the given command, and let file name
	   be the program */
	argc = parse_args(file_name, argv);

	/* And then load the binary */
  // need to add file_lock inside of precess_exec
	success = load(file_name, &_if);

	/* Insert arguments to stack */
  if(success) {
	  insert_args(argc, argv, &_if);
  }
  palloc_free_page (file_name);
  
	/* If load failed, quit. */
	if (!success)
		return -1;

  /* user_thread flag set to true */
  cur->is_user_thread = true;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

/* codes for project 2 */
/* parse raw command to program and arguments. returns argc*/
int parse_args(char *raw_text, char **argv)
{
	char *token, *save_ptr;
	int argc = 0;
	// extract program name first
	token = strtok_r(raw_text, " ", &save_ptr);
	// parse rest argument
	while(token != NULL)
	{
    argv[argc] = token;
		token = strtok_r(NULL, " ", &save_ptr);
		argc++;
	}
	return argc;
}

void insert_args(int argc, char **argv, struct intr_frame *_if)
{
	int argv_len;
	char *argv_ptr[64];
	// first, insert raw parsed command line to stack
	for(int i = argc-1; i >= 0; i--) {
		// move stack pointer
		argv_len = strlen(argv[i]);
		_if->rsp -= argv_len + 1;
		// copy raw command to stack
		memcpy(_if->rsp, argv[i], argv_len + 1);
		// and save stack pointer
		argv_ptr[i] = _if->rsp;
	}
	// second, insert padding for word-align
	while (_if->rsp % sizeof(char*)) {
		_if->rsp -= 1;
		memset(_if->rsp, 0, sizeof(uint8_t));
	}
	// third, insert pointers of argv
	// note That argv[argc] inserted as 0 by memset
	_if->rsp -= sizeof(char*);
	memset(_if->rsp, 0, sizeof(char*));
	for(int i = argc-1; i >= 0; i--) {
		// move stack pointer
		_if->rsp -= sizeof(char*);
		// copy stack pointer to stack
		memcpy(_if->rsp, &argv_ptr[i], sizeof(char*));
	}
	// fourth, point %rsi to argv and set %rdi to argc
	(_if->R).rsi = _if->rsp;
	(_if->R).rdi = argc;
	// finally, set fake return address
	_if->rsp -= sizeof(char*);
	memset(_if->rsp, 0, sizeof(char*));
	return;
}

/* find child_thread from child thread list of current thread by tid.
 * returns pointer to target if success, otherwise return NULL. */
struct thread* get_child_thread (tid_t tid) {
  struct thread *t;
  struct list_elem *e;
  struct list* child_list = &(thread_current()->child_tids);
  for (e=list_begin(child_list); e!=list_end(child_list); e=list_next(e)) {
    t = list_entry(e, struct thread, child_elem);
    if(tid == t->tid) {
      return t;
    }
  }
  return NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
  struct thread *child = get_child_thread(child_tid);
  int exit_status = -1;

  // return if thread not exists on child list
  if (child == NULL)
		return exit_status;
  
  // parent thread waits for child
  sema_down(&child->wait_sema);
  exit_status = child->exit_status;
  // remove child from child list
  list_remove(&child->child_elem);
  // let child to exit
  sema_up(&child->exit_sema);
	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

  // print termination message
  if(curr->is_user_thread) {
    printf("%s: exit(%d)\n", curr->name, curr->exit_status);
  }
  // free fdt here? lets try
  struct list* fdt = &(curr->fdt);
  struct list* fdt_dup = &(curr->fdt_dup);
  lock_acquire(&file_lock);
  while (!list_empty(fdt))
  {
    struct list_elem *e = list_pop_front (fdt);
    struct fd *fd_entry = list_entry(e, struct fd, fd_elem);
    if(fd_entry->fp != STDIN && fd_entry->fp != STDOUT) {
      file_close(fd_entry->fp);
    }
    //free(fd_entry);
    palloc_free_page(fd_entry);
  }
   while (!list_empty(fdt_dup))
  {
    struct list_elem *e = list_pop_front (fdt_dup);
    struct fd_dup *fd_dup_entry = list_entry(e, struct fd_dup, fd_dup_elem);
    //free(fd_dup_entry);
    palloc_free_page(fd_dup_entry);
  }
  lock_release(&file_lock);
  //printf("fdt for %s is clean now?: %d, fdt_index = %d\n", curr->name,list_size(fdt),curr->fdt_index);

  // process cleanup
  process_cleanup ();
  // let all child threads can exit
  struct list_elem *e;
  struct list* child_list = &(curr->child_tids);
  if(!list_empty(child_list)) {
    for (e=list_begin(child_list); e!=list_end(child_list); e=list_next(e)) {
     struct thread *t = list_entry(e, struct thread, child_elem);
     sema_up(&t->exit_sema);
     //process_wait(t->tid);
    }
  }
  // wakeup parent thread
  sema_up(&curr->wait_sema);
  // wait until parent get exit_status info
  sema_down(&curr->exit_sema);
  return;
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();
#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif
	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */


	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

struct segment_info {
  struct file *file;
  size_t page_read_bytes;
  off_t ofs;
};

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
//   struct segment_info *info = (struct segment_info *) aux;
//   struct file *file = info->file;
//   size_t page_read_bytes = info->page_read_bytes;
//   size_t page_zero_bytes = PGSIZE - page_read_bytes;
//   off_t ofs = info->ofs;
  
//   struct frame *frame = page->frame;
//   /* Load this page. */
//   file_seek (file, ofs);
//   int file_read_count = file_read (file, frame->kva, page_read_bytes);
//   if (file_read_count != (int) page_read_bytes) {
//     // palloc_free_page(frame->kva);
//     vm_dealloc_page(page);
//     printf("file_read failed, file: %d, kva: %d, page_read_bytes: %d\n",file, frame->kva, page_read_bytes);///test
//     printf("actually read: %d\n",file_read_count);///tests
//     printf("file_info: {inode: %d, pos: %d} @ %d\n",file->inode, file->pos, file);
//     return false;
//   }
//   memset(frame->kva + page_read_bytes, 0, page_zero_bytes);
//   free(info);
//   return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
    // segment information for lazy_load_segment
    // struct segment_info *segment_info;
    // segment_info = (struct segment_info *)malloc(sizeof(struct segment_info));
    // segment_info->file = file;
    // segment_info->page_read_bytes = page_read_bytes;
    // segment_info->ofs = ofs;
    // printf("reserved_file_info: {inode: %d, ofs: %d} @ %d\n",file->inode, ofs, file);///test

	// 	if (!vm_alloc_page_with_initializer (VM_ANON, upage,
    //   writable, lazy_load_segment, segment_info)) {
    //   free(segment_info);
    //   return false;
    // }
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
  if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true)) {
		success = vm_claim_page(stack_bottom);
		if (success) {
        if_->rsp = USER_STACK;
        thread_current()->stack_bottom = stack_bottom;
		  }
  	}
	return success;
}
#endif /* VM */
