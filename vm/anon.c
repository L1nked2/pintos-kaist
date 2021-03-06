/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

static struct bitmap *swap_table;
#define SECTORS_PER_PAGE PGSIZE/DISK_SECTOR_SIZE //4096/512 = 8


/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	swap_table = bitmap_create((size_t)disk_size(swap_disk)/SECTORS_PER_PAGE);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
  
  /* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
  // allocate SIZE_MAX for swap sector as sentinel
  anon_page->swap_disk_sector = SIZE_MAX;
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	disk_sector_t swap_disk_sector = anon_page->swap_disk_sector;

  // validate disk sector
	if (anon_page->swap_disk_sector == SIZE_MAX)
		return false;
	if (!bitmap_test(swap_table, swap_disk_sector))
		return false;
	
	disk_rw_repeatedly(swap_disk_sector, kva, 'r');
	//bitmap_set_multiple(swap_table, anon_page->swap_disk_sector, SECTORS_PER_PAGE, false);
	bitmap_set(swap_table, anon_page->swap_disk_sector, false);

  // mark swap disk sector as default
	anon_page->swap_disk_sector = SIZE_MAX;
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	disk_sector_t swap_disk_sector = bitmap_scan_and_flip(swap_table, 0, 1, false);
	
	if (swap_disk_sector == BITMAP_ERROR) // bitmap_scan can return BITMAP_ERROR
		return false;
	
	anon_page->swap_disk_sector = swap_disk_sector;
	disk_rw_repeatedly(swap_disk_sector, page->frame->kva, 'w');
	pml4_clear_page(thread_current()->pml4, page->va);
	page->frame = NULL;
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* Helper function for anon swap IO */
void disk_rw_repeatedly(uint32_t swap_disk_sector, void *kva, char cond) {
	for(int sector = 0; sector < SECTORS_PER_PAGE; sector++) {
		disk_sector_t sec_no = (disk_sector_t)(swap_disk_sector * SECTORS_PER_PAGE) + sector;
		void *buffer = (void *)((uint8_t *)kva + DISK_SECTOR_SIZE*sector);
		if (cond == 'r') {
			disk_read(swap_disk, sec_no, buffer);
		} else if (cond == 'w') {
			disk_write(swap_disk, sec_no, buffer);
		} else {
			return NULL;
		}
	}
	return;
}