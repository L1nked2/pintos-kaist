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

<<<<<<< HEAD
static struct bitmap *swap_table;
const size_t page_sector = PGSIZE/DISK_SECTOR_SIZE; // 4096/512 = 8
=======
#define SECTORS_PER_PAGE PGSIZE/DISK_SECTOR_SIZE
struct bitmap *swap_table;
>>>>>>> e177703bbdba738c2a4645089cf171dc8f7cf1ed

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
<<<<<<< HEAD
	swap_table = bitmap_create((size_t)disk_size(swap_disk)/page_sector);
=======
	swap_table = bitmap_create(disk_size(swap_disk) / SECTORS_PER_PAGE);
>>>>>>> e177703bbdba738c2a4645089cf171dc8f7cf1ed
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
  
  /* Set up the handler */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
  return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	uint32_t swap_disk_sector = anon_page->swap_disk_sector;
	size_t idx = swap_disk_sector/page_sector;
	page->frame->kva = kva;
	if (anon_page->swap_disk_sector == SIZE_MAX)
		return false;
	if (!bitmap_test(swap_table, idx))
		return false;
	
	disk_rw_repeatedly(swap_disk_sector, page->frame->kva, 'r');
	bitmap_set_multiple(swap_table, anon_page->swap_disk_sector, page_sector, false);
	
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* Helper function for anon swap IO */
void disk_rw_repeatedly(uint32_t swap_disk_sector, void *kva, char cond) {
	for(int sector = 0; sector < page_sector; sector++) {
		disk_sector_t sec_no = swap_disk_sector + sector;
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