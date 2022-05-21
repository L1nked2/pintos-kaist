#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"

#define STDIN 1
#define STDOUT 2

/* for using rw */
struct lock file_lock;

void syscall_init (void);

/* codes for project 2 */
// void validate_addr(const uint64_t *addr);
struct page *validate_addr(void *addr);
struct fd_dup *search_fd_dup(int fd);
struct fd *search_fd(int fd);
void sys_halt();
void sys_exit(int status);
tid_t sys_fork(const char *thread_name, struct intr_frame *if_);
int sys_exec (const char *cmd_line);
int sys_wait (tid_t tid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
int sys_dup2(int oldfd, int newfd);
#endif /* userprog/syscall.h */
