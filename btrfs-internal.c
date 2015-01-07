/*
 * btrfs-internal.c
 *
 * Code taken from btrfs. Keep this seperate to make it easier to push
 * these functions into libbtrfs at a later date.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <linux/magic.h>
#include <linux/btrfs.h>

#include "kernel.h"
#include "btrfs-internal.h"

#include "rbtree.h"
#include "debug.h"

/*
 * test if path is a subvolume:
 * this function return
 * 0-> path exists but it is not a subvolume
 * 1-> path exists and it is  a subvolume
 * -1 -> path is unaccessible
 */
int test_issubvolume(char *path)
{
	struct stat	st;
	int		res;

	res = stat(path, &st);
	if(res < 0 )
		return -1;

	return (st.st_ino == 256) && S_ISDIR(st.st_mode);
}

/* pass in a directory id and this will return
 * the full path of the parent directory inside its
 * subvolume root.
 *
 * It may return NULL if it is in the root, or an ERR_PTR if things
 * go badly.
 */
static char *__ino_resolve(int fd, u64 dirid)
{
	struct btrfs_ioctl_ino_lookup_args args;
	int ret;
	char *full;
	int e;

	memset(&args, 0, sizeof(args));
	args.objectid = dirid;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	e = errno;
	if (ret) {
		fprintf(stderr, "ERROR: Failed to lookup path for dirid %llu - %s\n",
			(unsigned long long)dirid, strerror(e) );
		return ERR_PTR(ret);
	}

	if (args.name[0]) {
		/*
		 * we're in a subdirectory of ref_tree, the kernel ioctl
		 * puts a / in there for us
		 */
		full = strdup(args.name);
		if (!full) {
			perror("malloc failed");
			return ERR_PTR(-ENOMEM);
		}
	} else {
		/* we're at the root of ref_tree */
		full = NULL;
	}
	return full;
}

/*
 * simple string builder, returning a new string with both
 * dirid and name
 */
static char *build_name(char *dirid, char *name)
{
	char *full;
	if (!dirid)
		return strdup(name);

	full = malloc(strlen(dirid) + strlen(name) + 1);
	if (!full)
		return NULL;
	strcpy(full, dirid);
	strcat(full, name);
	return full;
}

/*
 * given an inode number, this returns the full path name inside the subvolume
 * to that file/directory.  cache_dirid and cache_name are used to
 * cache the results so we can avoid tree searches if a later call goes
 * to the same directory or file name
 */
static char *ino_resolve(int fd, u64 ino, u64 *cache_dirid, char **cache_name)

{
	u64 dirid;
	char *dirname;
	char *name;
	char *full;
	int ret;
	struct btrfs_ioctl_search_args args;
	struct btrfs_ioctl_search_key *sk = &args.key;
	struct btrfs_ioctl_search_header *sh;
	unsigned long off = 0;
	int namelen;
	int e;

	memset(&args, 0, sizeof(args));

	sk->tree_id = 0;

	/*
	 * step one, we search for the inode back ref.  We just use the first
	 * one
	 */
	sk->min_objectid = ino;
	sk->max_objectid = ino;
	sk->max_type = BTRFS_INODE_REF_KEY;
	sk->max_offset = (u64)-1;
	sk->min_type = BTRFS_INODE_REF_KEY;
	sk->max_transid = (u64)-1;
	sk->nr_items = 1;

	ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args);
	e = errno;
	if (ret < 0) {
		fprintf(stderr, "ERROR: can't perform the search - %s\n",
			strerror(e));
		return NULL;
	}
	/* the ioctl returns the number of item it found in nr_items */
	if (sk->nr_items == 0)
		return NULL;

	off = 0;
	sh = (struct btrfs_ioctl_search_header *)(args.buf + off);

	if (sh->type == BTRFS_INODE_REF_KEY) {
		struct btrfs_inode_ref *ref;
		dirid = sh->offset;

		ref = (struct btrfs_inode_ref *)(sh + 1);
		namelen = btrfs_stack_inode_ref_name_len(ref);

		name = (char *)(ref + 1);
		name = strndup(name, namelen);

		/* use our cached value */
		if (dirid == *cache_dirid && *cache_name) {
			dirname = *cache_name;
			goto build;
		}
	} else {
		return NULL;
	}
	/*
	 * the inode backref gives us the file name and the parent directory id.
	 * From here we use __ino_resolve to get the path to the parent
	 */
	dirname = __ino_resolve(fd, dirid);
build:
	full = build_name(dirname, name);
	if (*cache_name && dirname != *cache_name)
		free(*cache_name);

	*cache_name = dirname;
	*cache_dirid = dirid;
	free(name);

	return full;
}

int print_one_extent(int fd, struct btrfs_ioctl_search_header *sh,
		     struct btrfs_file_extent_item *item,
		     u64 found_gen, u64 *cache_dirid,
		     char **cache_dir_name, u64 *cache_ino,
		     char **cache_full_name)
{
	u64 len = 0;
	u64 disk_start = 0;
	u64 disk_offset = 0;
	u8 type;
	int compressed = 0;
	int flags = 0;
	char *name = NULL;

	if (sh->objectid == *cache_ino) {
		name = *cache_full_name;
	} else if (*cache_full_name) {
		free(*cache_full_name);
		*cache_full_name = NULL;
	}
	if (!name) {
		name = ino_resolve(fd, sh->objectid, cache_dirid,
				   cache_dir_name);
		*cache_full_name = name;
		*cache_ino = sh->objectid;
	}
	if (!name)
		return -EIO;

	type = btrfs_stack_file_extent_type(item);
	compressed = btrfs_stack_file_extent_compression(item);

	if (type == BTRFS_FILE_EXTENT_REG ||
	    type == BTRFS_FILE_EXTENT_PREALLOC) {
		disk_start = btrfs_stack_file_extent_disk_bytenr(item);
		disk_offset = btrfs_stack_file_extent_offset(item);
		len = btrfs_stack_file_extent_num_bytes(item);
	} else if (type == BTRFS_FILE_EXTENT_INLINE) {
		disk_start = 0;
		disk_offset = 0;
		len = btrfs_stack_file_extent_ram_bytes(item);
	} else {
		printf("unhandled extent type %d for inode %llu "
		       "file offset %llu gen %llu\n",
			type,
			(unsigned long long)sh->objectid,
			(unsigned long long)sh->offset,
			(unsigned long long)found_gen);

		return -EIO;
	}
	printf("inode %llu file offset %llu len %llu disk start %llu "
	       "offset %llu gen %llu flags ",
	       (unsigned long long)sh->objectid,
	       (unsigned long long)sh->offset,
	       (unsigned long long)len,
	       (unsigned long long)disk_start,
	       (unsigned long long)disk_offset,
	       (unsigned long long)found_gen);

	if (compressed) {
		printf("COMPRESS");
		flags++;
	}
	if (type == BTRFS_FILE_EXTENT_PREALLOC) {
		printf("%sPREALLOC", flags ? "|" : "");
		flags++;
	}
	if (type == BTRFS_FILE_EXTENT_INLINE) {
		printf("%sINLINE", flags ? "|" : "");
		flags++;
	}
	if (!flags)
		printf("NONE");

	printf(" %s\n", name);
	return 0;
}


/* finding the generation for a given path is a two step process.
 * First we use the inode loookup routine to find out the root id
 *
 * Then we use the tree search ioctl to scan all the root items for a
 * given root id and spit out the latest generation we can find
 */
u64 find_root_gen(int fd)
{
	struct btrfs_ioctl_ino_lookup_args ino_args;
	int ret;
	struct btrfs_ioctl_search_args args;
	struct btrfs_ioctl_search_key *sk = &args.key;
	struct btrfs_ioctl_search_header sh;
	unsigned long off = 0;
	u64 max_found = 0;
	int i;
	int e;

	memset(&ino_args, 0, sizeof(ino_args));
	ino_args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	/* this ioctl fills in ino_args->treeid */
	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &ino_args);
	e = errno;
	if (ret) {
		fprintf(stderr, "ERROR: Failed to lookup path for dirid %llu - %s\n",
			(unsigned long long)BTRFS_FIRST_FREE_OBJECTID,
			strerror(e));
		return 0;
	}

	memset(&args, 0, sizeof(args));

	sk->tree_id = 1;

	/*
	 * there may be more than one ROOT_ITEM key if there are
	 * snapshots pending deletion, we have to loop through
	 * them.
	 */
	sk->min_objectid = ino_args.treeid;
	sk->max_objectid = ino_args.treeid;
	sk->max_type = BTRFS_ROOT_ITEM_KEY;
	sk->min_type = BTRFS_ROOT_ITEM_KEY;
	sk->max_offset = (u64)-1;
	sk->max_transid = (u64)-1;
	sk->nr_items = 4096;

	while (1) {
		ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args);
		e = errno;
		if (ret < 0) {
			fprintf(stderr, "ERROR: can't perform the search - %s\n",
				strerror(e));
			return 0;
		}
		/* the ioctl returns the number of item it found in nr_items */
		if (sk->nr_items == 0)
			break;

		off = 0;
		for (i = 0; i < sk->nr_items; i++) {
			struct btrfs_root_item *item;

			memcpy(&sh, args.buf + off, sizeof(sh));
			off += sizeof(sh);
			item = (struct btrfs_root_item *)(args.buf + off);
			off += sh.len;

			sk->min_objectid = sh.objectid;
			sk->min_type = sh.type;
			sk->min_offset = sh.offset;

			if (sh.objectid > ino_args.treeid)
				break;

			if (sh.objectid == ino_args.treeid &&
			    sh.type == BTRFS_ROOT_ITEM_KEY) {
				max_found = max(max_found,
						btrfs_root_generation(item));
			}
		}
		if (sk->min_offset < (u64)-1)
			sk->min_offset++;
		else
			break;

		if (sk->min_type != BTRFS_ROOT_ITEM_KEY)
			break;
		if (sk->min_objectid != ino_args.treeid)
			break;
	}
	return max_found;
}

int btrfs_list_find_updated_files(int fd, u64 root_id, u64 oldest_gen)
{
	int ret;
	struct btrfs_ioctl_search_args args;
	struct btrfs_ioctl_search_key *sk = &args.key;
	struct btrfs_ioctl_search_header sh;
	struct btrfs_file_extent_item *item;
	unsigned long off = 0;
	u64 found_gen;
	u64 max_found = 0;
	int i;
	int e;
	u64 cache_dirid = 0;
	u64 cache_ino = 0;
	char *cache_dir_name = NULL;
	char *cache_full_name = NULL;
	struct btrfs_file_extent_item backup;

	memset(&backup, 0, sizeof(backup));
	memset(&args, 0, sizeof(args));

	sk->tree_id = root_id;

	/*
	 * set all the other params to the max, we'll take any objectid
	 * and any trans
	 */
	sk->max_objectid = (u64)-1;
	sk->max_offset = (u64)-1;
	sk->max_transid = (u64)-1;
	sk->max_type = BTRFS_EXTENT_DATA_KEY;
	sk->min_transid = oldest_gen;
	/* just a big number, doesn't matter much */
	sk->nr_items = 4096;

	max_found = find_root_gen(fd);
	while(1) {
		ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH, &args);
		e = errno;
		if (ret < 0) {
			fprintf(stderr, "ERROR: can't perform the search- %s\n",
				strerror(e));
			break;
		}
		/* the ioctl returns the number of item it found in nr_items */
		if (sk->nr_items == 0)
			break;

		off = 0;

		/*
		 * for each item, pull the key out of the header and then
		 * read the root_ref item it contains
		 */
		for (i = 0; i < sk->nr_items; i++) {
			memcpy(&sh, args.buf + off, sizeof(sh));
			off += sizeof(sh);

			/*
			 * just in case the item was too big, pass something other
			 * than garbage
			 */
			if (sh.len == 0)
				item = &backup;
			else
				item = (struct btrfs_file_extent_item *)(args.buf +
								 off);
			found_gen = btrfs_stack_file_extent_generation(item);
			if (sh.type == BTRFS_EXTENT_DATA_KEY &&
			    found_gen >= oldest_gen) {
				print_one_extent(fd, &sh, item, found_gen,
						 &cache_dirid, &cache_dir_name,
						 &cache_ino, &cache_full_name);
			}
			off += sh.len;

			/*
			 * record the mins in sk so we can make sure the
			 * next search doesn't repeat this root
			 */
			sk->min_objectid = sh.objectid;
			sk->min_offset = sh.offset;
			sk->min_type = sh.type;
		}
		sk->nr_items = 4096;
		if (sk->min_offset < (u64)-1)
			sk->min_offset++;
		else if (sk->min_objectid < (u64)-1) {
			sk->min_objectid++;
			sk->min_offset = 0;
			sk->min_type = 0;
		} else
			break;
	}
	free(cache_dir_name);
	free(cache_full_name);
	printf("transid marker was %llu\n", (unsigned long long)max_found);
	return ret;
}
