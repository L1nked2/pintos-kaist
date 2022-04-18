#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/malloc.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

/* codes for project 2 */
int parse_args (char *raw_text, char**argv);
void insert_args(int argc, char **argv, struct intr_frame *_if);
struct thread* get_child_thread (tid_t tid);
/* file descriptor object
 * file* fp, int index, bool fp_secure, int dup_cnt,
 * struct list_elem fd_elem exists
 */
struct fd{
  struct file* fp;            /* file pointer */
  int index;                  /* index of file descriptor */
  bool fp_secure;             /* is fp is safely mounted? */
  int dup_cnt;                /* dup_cnt that number of reference from fd_dup_table */
  struct list_elem fd_elem;   /* file descriptor table list element */
};

/* file descriptor duplicated object
 * int origin_index, int index, struct list_elem fd_dup_elem exists
 */
struct fd_dup{
  int origin_index;           /* index of original file descriptor */
  int index;                  /* index of file descriptor */
  struct list_elem fd_dup_elem;   /* file descriptor table list element */
};

#endif /* userprog/process.h */
