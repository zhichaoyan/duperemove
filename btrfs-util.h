/*
 * btrfs-util.h
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
 */

#ifndef	__BTRFS_UTIL__
#define	__BTRFS_UTIL__

extern unsigned int num_subvols;
extern struct rb_root subvols_by_id;

int check_file_btrfs(int fd, int *btrfs);
int find_btrfs_subvol_from_file(int fd, char *filename, uint64_t *rootid);

int record_btrfs_subvol(int fd, uint64_t subvolid, uint64_t gen, char *path);

struct btrfs_subvol {
	uint64_t	subvol_id;
	uint64_t	subvol_gen; /* most recent generation we've
				     * scanned with */

	/*
	 * objectids can be reused, so record uuid to test if a
	 * subvolume has been deleted and recreated
	 */
	char		subvol_uuid[16];

	char		*subvol_path;		/* Absolute path to subvolume */

	struct rb_node	subvol_node; /* for subvols_by_id rbtree */
};

#endif	/* __BTRFS_UTIL__ */
