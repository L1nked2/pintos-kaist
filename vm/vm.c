/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

static struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

  // initialize frame_table
  list_init (&frame_table);

  return;
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
    struct page *page = (struct page *)malloc(sizeof(struct page));
    if (page == NULL) {
      goto err;
    }
    switch(VM_TYPE(type)) { 
      case VM_ANON: 
        uninit_new(page, upage, init, type, aux, anon_initializer);
        break;
      case VM_FILE:
        uninit_new(page, upage, init, type, aux, file_backed_initializer);
        break;
    }
    page->writable = writable;
		/* TODO: Insert the page into the spt. */
    spt_insert_page(spt, page);
    return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	/* TODO: Fill this function. */
  // malloc dummy page for hash_find(), because it takes page as argument.
	struct page *page = (struct page *)malloc(sizeof(struct page));
	struct hash_elem *h_e;
  // Alignment to get proper page address.
	page->va = pg_round_down(va);
  // find page from spt
	h_e = hash_find(&spt->pages, &page->hash_elem);
  // free dummy page
	free(page);
  // return result
  if (h_e == NULL) {
    return NULL;
  }
  else {
    return hash_entry(h_e, struct page, hash_elem);
  }
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	// int succ = false;
	/* TODO: Fill this function. */
  // find page from spt
	struct hash_elem *h_e = hash_find(&spt->pages, &page->hash_elem);
  if (h_e != NULL) { // spt has the page already
		return false;
	} else {
    hash_insert(&spt->pages, &page->hash_elem);
    return true;
  }
}

/* Remove PAGE from spt and deallocate it. */
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
  // remove page from spt, return false if page is not exists in spt
  if (hash_delete(&spt->pages, &page->hash_elem) == NULL) {
    return false; 
  }
  // deallocate page
	vm_dealloc_page (page);
	return true; 
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */


	// clock algorithm is recommended


	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	/* TODO: Fill this function. */
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	ASSERT (frame != NULL);
  // get new physical page by palloc(PAL_USER)
	frame->kva = palloc_get_page(PAL_USER);
  frame->page = NULL;
  // if palloc fails(no available page), evict frame
  // and return empty frame.
	if (frame->kva == NULL) {
    // PANIC("todo: swap_in and out");
		frame = vm_evict_frame();
    return frame;
	}
  // add frame to frame_table
  list_push_back (&frame_table, &frame->frame_elem);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
  if (vm_alloc_page(VM_ANON|VM_MARKER_0, addr, true)) {
    vm_claim_page(addr);
    thread_current()->stack_bottom -= PGSIZE;
  }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present UNUSED) {
	struct supplemental_page_table *spt= &thread_current ()->spt;
	/* TODO: Validate the fault */
  if (is_kernel_vaddr(addr)) {
        return false;
	}
	/* TODO: Your code goes here */
  void *rsp = user ? f->rsp : thread_current ()->stack_ptr;
  printf("user: %d, write: %d, not_present: %d\n", user, write, not_present);///test
  //user: 1, write: 0, not_present: 1
  if (not_present){
    if (!vm_claim_page(addr)) {
      // vm_claim_page failed,
      // check if stack growth can solve the problem
      if (rsp - 8 <= addr && USER_STACK - 0x100000 <= addr && addr <= USER_STACK) {
        printf("stack_growth\n");///test
        vm_stack_growth(thread_current()->stack_bottom - PGSIZE);
        return true;
      }
      printf("page_fault handling failed_1\n");///test
      return false;
    }
    else {
      // page is properly claimed
      printf("vm_claim success\n");///test
      return true;
    }
  }
  // cannot handle page_fault (writing to r/o, etc,.)
  printf("page_fault handling failed (not claim case)\n");///test
  return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocated on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
  // Find page on supplemental_page_table and call
  // do_claim_page. If page is not found, return false.
  page = spt_find_page(&thread_current()->spt, va);
  // If page is not found on supplemental_page_table, return false.
	if (page == NULL) {
    printf("page not found on supplemental table\n");///test
		return false;
	}
  // call do_claim_page to do rest job.
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
  struct frame *frame = vm_get_frame ();
  bool page_table_inserted = false;
	/* Set links, doubly linked */
	frame->page = page;
	page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
  // if failed to insert, return false.
	page_table_inserted = pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable);
  if (page_table_inserted == false) {
    return false;
  }
  // swap_in page and return result
  printf("going to swap_in on page %d, frame %d\n", page->va, frame->kva);///test
	return swap_in (page, frame->kva);
}

/* Implementation of supplemental_page_table,
 * based on hash table */
// Hash function for hash_table.
// get page from hash element, convert page->va to hash value and return it.
uint64_t page_hash_func(const struct hash_elem *h_e, void *aux UNUSED) {
	const struct page *p = hash_entry(h_e, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}

// Less funtion for hash_table
// compare function for find element, h1==h2 if h1>h2 and h1<h2 both false.
bool page_less_func(const struct hash_elem *h_e1, const struct hash_elem *h_e2,
		void *aux UNUSED) {
	const struct page *p1 = hash_entry(h_e1, struct page, hash_elem);
	const struct page *p2 = hash_entry(h_e2, struct page, hash_elem);
	return p1->va < p2->va; 
}

/* Initialize new supplemental page table */
/* This function is called when a new process starts (in initd of userprog/process.c) */
/* and when a process is being forked (in __do_fork of userprog/process.c). */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
  hash_init(&spt->pages, page_hash_func, page_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
  return true;///test
  // Iterate src and copy the contents to dst
  struct hash_iterator i;
  hash_first (&i, src);
  while (hash_next (&i))
  {
    struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
    enum vm_type type = page_get_type(src_page);
    void *upage = src_page->va;
    bool writable = src_page->writable;
    vm_initializer *init = src_page->uninit.init;
    void* aux = src_page->uninit.aux;
    // TODO: need to allocate uninit page and claim them immediately.

    // if page is stack page
    // if (src_page->uninit.type & VM_MARKER_0) {
    //   setup_stack(&thread_current()->tf);
    // }
    // if page is UNINIT page
    if(src_page->operations->type == VM_UNINIT) {
      if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux))
        return false;
    }
    // if page is anon or file
    else {
      if(!vm_alloc_page(type, upage, writable))
        return false;
      if(!vm_claim_page(upage))
        return false;
    }
    if (src_page->operations->type != VM_UNINIT) {
      struct page* dst_page = spt_find_page(dst, upage);
      memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
  }
  return true;
}

/* Helper function for supplemental_page_table_kill */
void
page_destructor (struct hash_elem *e, void* aux UNUSED) {
  const struct page *page = hash_entry(e, struct page, hash_elem);
  if (page->frame != NULL){
    page->frame->page = NULL;
	}
  vm_dealloc_page(page);
  return;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
  // writeback will be implemented in each page type
  if(hash_empty(&spt->pages)) {
    hash_destroy(&spt->pages, NULL);
  } else {
    hash_destroy(&spt->pages, page_destructor);
  }
  return;
}
