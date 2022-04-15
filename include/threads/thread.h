#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/fixed-point.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* Default value when running in mlfqs */
#define NICE_DEFAULT 0
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0
int load_avg, prev_load_avg;

/* Default value for file descriptors */
#define FD_NR_START_INDEX 3
#define FD_MAX_INDEX 128

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[32];                     /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	
	/* Owned by timer.c. */
	int64_t wakeup_tick; 				        /* wakeup tick */

	/* Owned by synch.c. */
	int init_priority;					        /* initial priority for priority recovery */
	struct lock *wait_on_lock; 			    /* A lock which the thread is waiting on */
	struct list holding_locks;			    /* Locks which the thread holds. */
	
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	/* Used for mlfqs */
	int nice;
	int recent_cpu,prev_recent_cpu;

  /* fields for Project 2 */
  /* Owned by process.c. */
  struct thread *parent_thread;       /* parent thread id. */
  struct list child_tids;             /* child thread id list. */
  struct list_elem child_elem;        /* list element of child threads */
  struct intr_frame *user_if;         /* intr_frame of userland */
  struct list fdt;                    /* file descriptor table. */
  int fdt_index;	                    /* index of current file descriptor (for open) */
  bool is_user_thread;	              /* flag for user thread */

  struct semaphore load_sema;
  struct semaphore wait_sema;
  struct semaphore exit_sema;
  int exit_status;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

/* Idle thread. */
static struct thread *idle_thread;

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

// intr wrapping functions and macros
#define intr_disable_wrapper(func) \
	enum intr_level old_level = intr_disable ();\
	int value = func;\
	intr_set_level (old_level);

static inline int unsafe_thread_get_load_avg (void){return fp_to_n_rounded(fp_mul_n(prev_load_avg, 100));}
static inline int unsafe_thread_get_nice (void){return thread_current ()->nice;}
static inline int unsafe_thread_set_nice (int nice){thread_current()->nice = nice;return nice;}
static inline int unsafe_thread_get_recent_cpu (void){return fp_to_n_rounded(fp_mul_n(thread_current()->prev_recent_cpu, 100));}

void do_iret (struct intr_frame *tf);

/* funtions for priority scheduling */
bool compare_thread_priority(struct list_elem* a,
	struct list_elem* b, void* aux UNUSED);
void schedule_preemptively(void);

/* functions for mlfqs */
void mlfqs_update_priority(struct thread *thread);
void mlfqs_update_recent_cpu(struct thread *thread);
void mlfqs_update_load_avg(void);
void mlfqs_update_priority_all(void);
void mlfqs_update_recent_cpu_all(void);
void mlfqs_increment_recent_cpu(void);

#endif /* threads/thread.h */