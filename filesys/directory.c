#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	#ifdef EFILESYS
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry), true, false);
	#else
	return inode_create (sector, entry_cnt * sizeof (struct dir_entry));
	#endif
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
	return dir_open (inode_open (ROOT_DIR_SECTOR));
}

struct dir *dir_open_from_path(char *path) {
	struct dir *ret_dir;
	int path_len = strlen(path);
	char *tmp_path = (char *)calloc(path_len + 1, sizeof(char *));
	memcpy(tmp_path, path, path_len + 1);
	if ((*tmp_path == '/') && (path_len == 1)) {
		// case of root
		free(tmp_path);
		return dir_open_root();
	}
	if (*tmp_path == '/') {
		// case of absolute path
		ret_dir = dir_open_root();
		tmp_path += 1;
	} else {
		// case of relative path
		ret_dir = dir_reopen(thread_current()->cur_dir);
	}
	char *token, *save_ptr;
	token = strtok_r(tmp_path, '/', &save_ptr);
	
	// not finished yet
	return;
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);
  //printf("lookup started\n");///test

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
    //printf("lookup, e.name = %s\n", e.name);///test
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
  //printf("dir_add, success=%d\n", success);///test
done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (!lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}

bool dir_change(const char *dir) {
	// changes the current working directory of the process to dir.
	// returns true if successful, false on failure.
	if (strlen(dir) > NAME_MAX)
		return false;
	
	return;
}

bool dir_make(const char *dir) {
	// creates the directory named dir.
	// returns true if successful, false on failure.
	// fails if dir already exists or if any directory name in dir,
	// besides the last, does not already exist.
	return;
}

bool dir_read(int fd, char *name) {
	// reads a directory entry from file descriptor fd.
	// if successful, stores the null-terminated file name in name,
	// which must have room for READDIR_MAX_LEN + 1 bytes, and returns true.
	// if no entries are left in the directory, returns false.
	return;
}

bool isdir(int fd) {
	// returns true if fd represents a directory.
	// false if it represents an ordinary file.
	return;
}

bool inumber(int fd) {
	// returns the inode number of the inode associated with fd,
	// which may represent an ordinary file or a directory.
	return;
}

bool parse_path(char *src, char *dst) {
	bool success = true;
	int src_len = strlen(src);
	char *tmp_src = (char *)calloc(src_len + 1, sizeof(char));
	memcpy(tmp_src, src, src_len + 1);
	char *token, *save_ptr;
	token = strtok_r(tmp_src, '/', &save_ptr);
	if (token == NULL) {
		memcpy(dst, src, src_len + 1);
		free(tmp_src);
		return !success;
	} else {
		token = strtok_r(NULL, '/', &save_ptr);
		char *cur;
		while (token != NULL) {
			cur = token;
			token = strtok_r(NULL, '/', &save_ptr);
		}
		memcpy(dst, cur, src_len + 1);
		free(tmp_src);
		return success;
	}
}