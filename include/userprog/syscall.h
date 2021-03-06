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
void validate_addr(const uint64_t *addr);
//struct page *validate_addr(void *addr);
struct fd_dup *search_fd_dup(int fd);
struct fd *search_fd(int fd);
void sys_halt();
void sys_exit(int status);
int sys_fork(const char *thread_name, struct intr_frame *if_);
int sys_exec (const char *cmd_line);
int sys_wait (int tid);
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

// syscall for pj3
void *sys_mmap(void *addr, size_t length, int writable, int fd, int32_t offset);
void sys_munmap(void *addr);

// syscall for pj4
bool sys_chdir(const char *dir);
bool sys_mkdir(const char *dir);
bool sys_readdir(int fd, char *name);
bool sys_isdir(int fd);
int sys_inumber(int fd);
int sys_symlink(const char *target, const char *linkpath);
#endif /* userprog/syscall.h */
