/*
 * btrfs-util.c
 *
 * Copyright (C) 2014 SUSE.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Some parts of this taken from btrfs-progs, which is also GPLv2
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/statfs.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <linux/magic.h>
#include <linux/btrfs.h>

#include "btrfs-internal.h"
#include "btrfs-util.h"
#include "debug.h"

/* For some reason linux/btrfs.h doesn't define this. */
#define	BTRFS_FIRST_FREE_OBJECTID	256ULL

/*
 * For a given:
 * - file or directory return the containing tree root id
 * - subvolume return its own tree id
 * - BTRFS_EMPTY_SUBVOL_DIR_OBJECTID (directory with ino == 2) the result is
 *   undefined and function returns -1
 */
int lookup_btrfs_subvolid(int fd, uint64_t *subvolid)
{
	int ret;
	struct btrfs_ioctl_ino_lookup_args args;

	memset(&args, 0, sizeof(args));
	args.objectid = BTRFS_FIRST_FREE_OBJECTID;

	ret = ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args);
	if (ret)
		return errno;

	*subvolid = args.treeid;

	return 0;
}

int check_file_btrfs(int fd, int *btrfs)
{
	int ret;
	struct statfs fs;

	*btrfs = 0;

	ret = fstatfs(fd, &fs);
	if (ret)
		return errno;

	if (fs.f_type == BTRFS_SUPER_MAGIC)
		*btrfs = 1;

	return ret;
}

struct name_lookup_cache {
	u64	ino;
	u64	dirid;
	char	*dir_name;
	char	*full_name;
};
typedef int (subvol_changed_cb)(uint64_t subvolid, int fd,
				struct btrfs_ioctl_search_header *sh,
				struct btrfs_file_extent_item *item,
				u64 found_gen,
				struct name_lookup_cache *cache);
static int subvol_find_updated_extents(int fd, u64 root_id, u64 oldest_gen,
				       u64 *max_gen_found,
				       subvol_changed_cb *callback)
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
	struct name_lookup_cache cache = { 0ULL, };
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
				callback(root_id, fd, &sh, item,
					 found_gen, &cache);
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
	if (cache.dir_name)
		free(cache.dir_name);
	if (cache.full_name)
		free(cache.full_name);
	*max_gen_found = max_found;
	return ret;
}

#ifdef	BTRFS_UTIL_TEST
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>

/*
 * Simple wrapper for BTRFS_IOC_SYNC ioctl
 */
int sync_btrfs_fs(int fd)
{
	int ret;

	ret = ioctl(fd, BTRFS_IOC_SYNC);
	if (ret < 0) {
		ret = errno;
		return ret;
	}
	return 0;
}

/*
 * Program to test our btrfs functionality.
 * Right now it only does a re-implementation of btrfs find-new.
 * Eventually:
 * btrfs-util what-changed hashfile
 * btrfs-util log2ino logical
 */
static char *path = NULL;
static uint64_t gen;
static int parse_opts(int argc, char **argv)
{
	if (argc < 2)
		return -1;

	if (strcmp(argv[1], "find-new") == 0) {
		if (argc != 4)
			return -1;
		path = strdup(argv[2]);
		abort_on(!path);
		gen = atoll(argv[3]);
	} else {
		return -1;
	}

	return 0;
}

/* print exactly like btrfs-progs to make it easier to compare output */
int print_changes(uint64_t subvolid, int fd,
		  struct btrfs_ioctl_search_header *sh,
		  struct btrfs_file_extent_item *item,
		  u64 found_gen,
		  struct name_lookup_cache *cache)
{
	return print_one_extent(fd, sh, item, found_gen, &cache->dirid,
				&cache->dir_name, &cache->ino,
				&cache->full_name);
}

static int do_find_new(char *subvol_path, uint64_t subvol_gen)
{
	int ret, fd;
	uint64_t max_gen;

	fd = open(subvol_path, O_RDONLY);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Could not open %s: %d\n", subvol_path, ret);
		return ret;
	}

	if (!test_issubvolume(subvol_path)) {
		fprintf(stderr, "%s is not a subvolume.\n", subvol_path);
		return -1;
	}

	ret = sync_btrfs_fs(fd);
	if (ret) {
		ret = errno;
		fprintf(stderr, "Could not sync %s: %d\n", subvol_path, ret);
		return -1;
	}

	ret = subvol_find_updated_extents(fd, 0, subvol_gen, &max_gen,
					  print_changes);
	if (ret) {
		fprintf(stderr, "Error %d finding changes\n", ret);
		return ret;
	}

	printf("transid marker was %"PRIu64"\n", max_gen);
	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	if (parse_opts(argc, argv)) {
		printf("tests duperemove btrfs functions.\nUsage:\n"
		       "btrfs-util find-new subvolume last-gen\n");
		return 1;
	}

	ret = do_find_new(path, gen);

	return ret;
}
#endif	/* BTRFS_UTIL_TEST */
