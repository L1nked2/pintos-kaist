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
  file_page->segment_info = page->uninit.aux;
  return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
  struct segment_info *info = file_page->segment_info;
  // read file contents
  file_seek(info->file, info->ofs);
	off_t read_bytes = file_read(info->file, kva, info->page_read_bytes);
	if (read_bytes != info->page_read_bytes)
      return false;
  // fill zero to rest space
	if (read_bytes < PGSIZE)
		memset(kva + read_bytes, 0, PGSIZE - read_bytes);
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
  struct segment_info *info = file_page->segment_info;
  struct thread* cur = thread_current ();
  // check if page is dirty
	if (pml4_is_dirty (cur->pml4, page->va)) {
		file_seek (info->file, info->ofs);
		file_write(info->file, page->va, info->page_read_bytes);
		pml4_set_dirty (cur->pml4, page->va, false);
	}
	// make "not present" for given page
	pml4_clear_page (cur->pml4, page->va);
	page->frame = NULL;
	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
  struct file_page *file_page = &page->file;
  struct segment_info *info = file_page->segment_info;
  // if dirty, write back
  if(pml4_is_dirty(thread_current()->pml4, page->va)) {
    file_seek(info->file, info->ofs);
    file_write(info->file, page->va, info->page_read_bytes);
  }
  file_close (info->file);
  // free the physical frame
  if (page->frame != NULL) {
    list_remove (&page->frame->frame_elem);
    free (page->frame);
  }
  free(info);
}

/* Do the mmap */
/* similar with load_segment in process.c */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
  // save begin address of pages
	void *begin_addr = addr;
  //printf("mmap started, %d\n",begin_addr);///test
  // calculate number of bytes to read and zero-filled.
	off_t file_len = file_length(file);
	size_t read_bytes = length < file_len ? length : file_len;
	size_t zero_bytes = PGSIZE - read_bytes%PGSIZE;
	
	while ((read_bytes > 0)||(zero_bytes > 0)) {
		// manage overlapping
		if ((!is_user_vaddr(addr))||(spt_find_page(&thread_current()->spt, addr))) {
			void *tmp_addr = addr;
			while (addr > tmp_addr) {
				struct supplemental_page_table *spt = &thread_current()->spt;
				spt_remove_page(spt, spt_find_page(spt, tmp_addr));
				tmp_addr = (void *)((uint8_t *)addr + PGSIZE);
			}
			return NULL;
		}
		
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct file *file = file_reopen(file);

		struct segment_info *info = (struct segment_info *)malloc(sizeof(struct segment_info));
		info->file = file;
		info->page_read_bytes = page_read_bytes;
		info->ofs = offset;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
				writable, file_lazy_load_segment, info)) {
      printf("file page allocation failed\n");///test
			free(info);
			file_close(file);
			return NULL;
		}
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		offset += page_read_bytes;
		addr = (void *)((uint8_t *)addr + PGSIZE);
	}
  //printf("mmap finished, %d\n",begin_addr);///test
	return begin_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct thread *t = thread_current();
	while (true) {
    // get target page from spt
    struct page *page = spt_find_page(&t->spt, addr);
    if (page == NULL)
		  return;
    // get segment_info
		struct segment_info *info = page->file.segment_info;
		struct file *file = info->file;
		size_t page_read_bytes = info->page_read_bytes;
		off_t ofs = info->ofs;
    // check dirty bit and writeback if dirty
		if (pml4_is_dirty(thread_current()->pml4, page->va)) {
      file_write_at(file, addr, page_read_bytes, ofs);
      pml4_set_dirty (thread_current()->pml4, page->va, 0);
    }
    // remove page from table
    pml4_clear_page(thread_current()->pml4, page->va);
		spt_remove_page(&thread_current()->spt, page);
    // preoceed the addr
		addr = (void *)((uint8_t *)addr + PGSIZE);
	}
  return;
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
  bool succ = false;
  struct frame *frame = page->frame;
  /* Load this page. */
  file_seek (file, ofs);
  int file_read_count = file_read_at(file, frame->kva, page_read_bytes, ofs);
  if (file_read_count != (int) page_read_bytes) {
    printf("spt_remove_page, actually read %d bytes\n", file_read_count);///test
	  spt_remove_page(&thread_current()->spt, page);
  } else {
    memset(frame->kva + page_read_bytes, 0, page_zero_bytes);
    succ = true;
  }
  //file_close(file);
  return succ;
}
