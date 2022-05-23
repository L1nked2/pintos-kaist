/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
/* similar with load_segment in process.c */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	void *ret_addr = addr;
	off_t file_len = file_length(file);
	size_t read_bytes = length < file_len ? length : file_len;
	size_t zero_bytes = PGSIZE - read_bytes%PGSIZE;

	while ((read_bytes > 0)||(zero_bytes >0)) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct file *reopen_file = file_reopen(file);

		struct segment_info *info = (struct segment_info *)malloc(sizeof(struct segment_info));
		info->file = reopen_file;
		info->page_read_bytes;
		info->ofs = offset;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
				writable, file_lazy_load_segment, info)) {
			free(info);
			file_close(reopen_file);
			return NULL;
		}
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		offset += page_read_bytes;
		uint8_t *tmp_addr = (uint8_t *)addr; // for void pointer calculating
		tmp_addr += PGSIZE;
		addr = (void *)tmp_addr;
	}
	return ret_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}

static bool
file_lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
  struct segment_info *info = (struct segment_info *) aux;
  struct file *file = info->file;
  size_t page_read_bytes = info->page_read_bytes;
  size_t page_zero_bytes = PGSIZE - page_read_bytes;
  off_t ofs = info->ofs;
  
  struct frame *frame = page->frame;
  /* Load this page. */
  file_seek (file, ofs);
  int file_read_count = file_read_at(file, frame->kva, page_read_bytes, ofs);
  // int file_read_count = file_read_at(file, page->va, page_read_bytes, ofs);
  if (file_read_count != (int) page_read_bytes) {
    // palloc_free_page(page);
    vm_dealloc_page(page);
    //printf("file_read failed, file: %d, kva: %d, page_read_bytes: %d\n",file, frame->kva, page_read_bytes);///test
    //printf("actually read: %d\n",file_read_count);///tests
    //printf("file_info: {inode: %d, pos: %d} @ %d\n",file->inode, file->pos, file);
    return false;
  } else {
    memset(frame->kva + page_read_bytes, 0, page_zero_bytes);
    // memset(page->va + page_read_bytes, 0, page_zero_bytes);
  }
  return true;
}