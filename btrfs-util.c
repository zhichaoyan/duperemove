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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <linux/magic.h>
#include <linux/btrfs.h>
#include <stddef.h>
#include <libgen.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "rbtree.h"
#include "kernel.h"
#include "list.h"

#include "filerec.h"
#ifdef BTRFS_UTIL_TEST
#include "csum.h"
#include "hash-tree.h"
#include "serialize.h"
#endif

#include "btrfs-internal.h"
#include "btrfs-util.h"
#include "debug.h"

static unsigned int on_btrfs = 0;

/*
 * Every btrfs subvolume has a unique id. Getting subvol id from an
 * inode is easy - see lookup_btrfs_subvolid().  The ids can be reused
 * though if a subvolume is deleted.
 *
 * To get a truly unique identifier we have to look up subvolume uuid,
 * but this takes more work than getting the id - we have to search
 * the tree of roots to find the correct root_item and get uuid off
 * that. We don't want to do this for every inode scanned.
 *
 * So as a compromise, we'll assume that the user isn't going to be
 * created and deleteing subvolumes underneath us. Given that
 * assumption, we're safe using subvolid as a unique identifier until
 * we have to store that data in a hash file. If we're going to store
 * this information on disk, we go back to the tree by ids and get the
 * uuid for each one.
 */
struct rb_root subvols_by_id = RB_ROOT;
struct rb_root subvols_by_uuid = RB_ROOT;
unsigned int num_subvols = 0;

static struct btrfs_subvol *find_btrfs_subvol_rb(uint64_t subvolid)
{
	struct rb_node *n = subvols_by_id.rb_node;
	struct btrfs_subvol *s;

	while (n) {
		s = rb_entry(n, struct btrfs_subvol, subvol_node);
		if (s->subvol_id > subvolid)
			n = n->rb_left;
		else if (s->subvol_id < subvolid)
			n = n->rb_right;
		else
			return s;
	}
	return NULL;
}

static void insert_btrfs_subvol_rb(struct btrfs_subvol *s2)
{
	struct rb_node **p = &subvols_by_id.rb_node;
	struct rb_node *parent = NULL;
	struct btrfs_subvol *s1;

	while (*p) {
		parent = *p;

		s1 = rb_entry(parent, struct btrfs_subvol, subvol_node);

		if (s1->subvol_id > s2->subvol_id)
			p = &(*p)->rb_left;
		else if (s1->subvol_id < s2->subvol_id)
			p = &(*p)->rb_right;
		else
			abort_lineno(); /* We should never find a duplicate */
	}

	rb_link_node(&s2->subvol_node, parent, p);
	rb_insert_color(&s2->subvol_node, &subvols_by_id);
	num_subvols++;
}

/*
 * work backwards from filename to a subvol path
 * XXX: Jokes on you, btrfs has an ioctl to resolve subvolid->path !!
 */
static int find_subvol_path(char *filename, char **subvol_path)
{
	int ret;
	char pathtmp[PATH_MAX+1];
	char *path;

	path = realpath(filename, pathtmp);
	if (!path)
		return errno;

test_subvol:
	ret = test_issubvolume(path);
	if (ret < 0)
		return ret;
	if (ret == 1)
		goto success;

	abort_on(path[0] != '/');
	if (strlen(path) == 1 && path[0] == '/')
		goto success;

	path = dirname(path);
	goto test_subvol;

success:
	*subvol_path = strdup(path);
	if (!(*subvol_path))
		return ENOMEM;
	return 0;
}

int record_btrfs_subvol(int fd, uint64_t subvolid, uint64_t gen, char *path)
{
	struct btrfs_subvol *s;

	s = find_btrfs_subvol_rb(subvolid);
	if (s)
		return 0;

	s = calloc(sizeof(*s), 1);
	if (!s)
		return ENOMEM;

	s->subvol_id = subvolid;
	s->subvol_gen = gen;
	rb_init_node(&s->subvol_node);

	s->subvol_path = strdup(path);
	if (!s->subvol_path) {
		free(s);
		return ENOMEM;
	}

	insert_btrfs_subvol_rb(s);

	return 0;
}

/*
 * For a given:
 * - file or directory return the containing tree root id
 * - subvolume return its own tree id
 * - BTRFS_EMPTY_SUBVOL_DIR_OBJECTID (directory with ino == 2) the result is
 *   undefined and function returns -1
 */
static int __lookup_btrfs_subvolid(int fd, uint64_t *subvolid)
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

static int lookup_btrfs_subvolid(char *filename, uint64_t *subvolid)
{
	int fd, ret;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		return errno;

	ret = __lookup_btrfs_subvolid(fd, subvolid);

	close(fd);
	return ret;
}

int find_btrfs_subvol_from_file(int fd, char *filename, uint64_t *rootid)
{
	int ret;
	uint64_t subvolid, max_gen;
	char *subvol_path;

	ret = __lookup_btrfs_subvolid(fd, &subvolid);
	if (ret)
		return ret;

	*rootid = subvolid;

	max_gen = find_root_gen(fd);
	if (!max_gen)
		return EIO;

	ret = find_subvol_path(filename, &subvol_path);
	if (ret)
		return ret;

	ret = record_btrfs_subvol(fd, subvolid, max_gen, subvol_path);

	free(subvol_path);
	return ret;
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
		*btrfs = on_btrfs = 1;

	return ret;
}

struct name_lookup_cache {
	u64	ino;
	u64	dirid;
	char	*dir_name;
	char	*full_name;
};
/* callback can return nonzero to stop search */
typedef int (subvol_changed_cb)(uint64_t subvolid, int fd,
				struct btrfs_ioctl_search_header *sh,
				struct btrfs_file_extent_item *item,
				u64 found_gen,
				struct name_lookup_cache *cache, void *priv);
static int subvol_find_updated_extents(int fd, u64 root_id,
				       u64 oldest_gen,
				       u64 *max_gen_found, u64 objectid,
				       subvol_changed_cb *callback, void *priv)
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
	if (objectid) {
		sk->min_objectid = objectid;
		sk->max_objectid = objectid;
	} else
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
				int stop;
				stop = callback(root_id, fd, &sh, item,
						found_gen, &cache, priv);
				if (stop)
					goto out;
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
out:
	if (cache.dir_name)
		free(cache.dir_name);
	if (cache.full_name)
		free(cache.full_name);
	if (*max_gen_found)
		*max_gen_found = max_found;
	return ret;
}

static uint64_t extent_len_from_item(struct btrfs_file_extent_item *item)
{
	uint64_t len = 0;
	unsigned int type;

	type = btrfs_stack_file_extent_type(item);

	if (type == BTRFS_FILE_EXTENT_REG ||
	    type == BTRFS_FILE_EXTENT_PREALLOC)
		len = btrfs_stack_file_extent_num_bytes(item);
	else if (type == BTRFS_FILE_EXTENT_INLINE)
		len = btrfs_stack_file_extent_ram_bytes(item);
	else
		fprintf(stderr, "WARNING: Unexpected extent type: %u\n", type);

	return len;
}

struct check_filerec_priv {
	uint64_t	subvol_gen;
	struct filerec	*file;
	int             changed;
};

static int check_filerec_cb(uint64_t subvolid, int fd,
			    struct btrfs_ioctl_search_header *sh,
			    struct btrfs_file_extent_item *item,
			    u64 found_gen,
			    struct name_lookup_cache *cache, void *priv)
{
	uint64_t ino = sh->objectid;
	uint64_t off = sh->offset;
	uint64_t len = extent_len_from_item(item);
	struct check_filerec_priv *fp = priv;
	struct filerec *file = fp->file;

	printf("file: %s subvol: %"PRIu64" ino: %"PRIu64" gen: %"PRIu64" changed from "
	       "%"PRIu64" to %"PRIu64"\n", file->filename, subvolid, ino, found_gen, off,
	       len);

	if (found_gen > fp->subvol_gen) {
		fp->changed = 1;
		return 1;
	}
	return 0;
}

int btrfs_check_file_changed(struct filerec *file, int *ret_changed)
{
	int ret;
	struct btrfs_subvol *sub;
	struct check_filerec_priv priv = {0, };

	abort_on(!filerec_meta_uptodate(file));

	sub = find_btrfs_subvol_rb(file->subvolid);
	if (!sub) {
		printf("file %s has unknown subvolid %"PRIu64"\n",
		       file->filename, file->subvolid);
		priv.changed = 1;
		ret = 0;
		goto out;
	}

	ret = filerec_open(file, 0);
	if (ret)
		goto out;

	priv.subvol_gen = sub->subvol_gen;
	priv.file = file;
	ret = subvol_find_updated_extents(file->fd, sub->subvol_id,
					  sub->subvol_gen, NULL, file->inum,
					  check_filerec_cb, &priv);
	if (ret) {
		fprintf(stderr,
			"Error %d while checking extent generations for file "
			"\"%s\": %s\n", ret, file->filename, strerror(ret));
		priv.changed = 1;
		ret = 0;
		goto out;
	}

out:
	if (!ret)
		*ret_changed = priv.changed;
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
 * btrfs-util show-changes hashfile
 * btrfs-util log2ino logical
 */
static char *path = NULL;
static uint64_t gen;

int verbose = 0, debug = 0;
unsigned int blocksize;

static enum {
	FIND_NEW,
	SHOW_CHANGES,
	TRANSID,
} action;

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
		action = FIND_NEW;
	} else if (strcmp(argv[1], "show-changes") == 0) {
		if (argc != 3)
			return -1;
		path = strdup(argv[2]);
		abort_on(!path);
		action = SHOW_CHANGES;
	} else if (strcmp(argv[1], "transid") == 0) {
		if (argc != 4)
			return -1;
		path = strdup(argv[2]);
		abort_on(!path);
		gen = atoll(argv[3]);
		action = TRANSID;
	} else {
		return -1;
	}

	return 0;
}

int show_live_changes(uint64_t subvolid, int fd,
		      struct btrfs_ioctl_search_header *sh,
		      struct btrfs_file_extent_item *item,
		      u64 found_gen,
		      struct name_lookup_cache *cache, void *priv)
{
	struct filerec *file;
	uint64_t ino = sh->objectid;
	uint64_t off = sh->offset;
	uint64_t len = extent_len_from_item(item);

	file = find_filerec(ino, subvolid);
	if (!file)
		return 0;

	printf("subvol: %"PRIu64" ino: %"PRIu64" (\"%s\") changed from "
	       "%"PRIu64" to %"PRIu64"\n", subvolid, ino, file->filename, off,
	       len);

	return 0;
}

static int show_one_subvol_changes(struct btrfs_subvol *subvol)
{
	int fd, ret;
	uint64_t max_gen;

	fd = open(subvol->subvol_path, O_RDONLY);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Could not open %s: %d\n", subvol->subvol_path,
			ret);
		return ret;
	}

	if (!test_issubvolume(subvol->subvol_path)) {
		fprintf(stderr, "%s is not a subvolume.\n",
			subvol->subvol_path);
		ret = -1;
		goto out;
	}

	ret = sync_btrfs_fs(fd);
	if (ret) {
		ret = errno;
		fprintf(stderr, "Could not sync %s: %d\n", subvol->subvol_path,
			ret);
		goto out;
	}

	ret = subvol_find_updated_extents(fd, subvol->subvol_id,
					  subvol->subvol_gen, &max_gen, 0,
					  show_live_changes, NULL);
	if (ret)
		fprintf(stderr, "Error %d finding changes\n", ret);

out:
	close(fd);
	return ret;
}

static int do_show_changes(char *hashfile)
{
	int ret;
	struct rb_node *n;
	struct btrfs_subvol *subvol;
	struct hash_tree tree;

	/*
	 * Load the hashfile
	 * Run subvol_find_updated_extents (rename to _extents)
	 *    - lookup filerec by inode / subvol
	 *    - if it exists, print it!
	 */
	printf("hashfile: %s\n", hashfile);

	init_filerec();
	init_hash_tree(&tree);

	ret = init_csum_module(DEFAULT_HASH_STR);
	if (ret) {
		fprintf(stderr, "Could not init csum module\n");
		return ret;
	}

	ret = read_hash_tree(hashfile, &tree, &blocksize, NULL, 0, NULL, 0);
	if (ret) {
		fprintf(stderr,
			"Error %d reading hashfile \"%s\".\n", ret, hashfile);
		return ret;
	}

	n = rb_first(&subvols_by_id);
	while (n) {
		subvol = rb_entry(n, struct btrfs_subvol, subvol_node);

		ret = show_one_subvol_changes(subvol);

		n = rb_next(n);
	}

	return 0;
}

/* print exactly like btrfs-progs to make it easier to compare output */
int print_changes(uint64_t subvolid, int fd,
		  struct btrfs_ioctl_search_header *sh,
		  struct btrfs_file_extent_item *item,
		  u64 found_gen,
		  struct name_lookup_cache *cache, void *priv)
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

	ret = subvol_find_updated_extents(fd, 0, subvol_gen, &max_gen, 0,
					  print_changes, NULL);
	if (ret) {
		fprintf(stderr, "Error %d finding changes\n", ret);
		return ret;
	}

	printf("transid marker was %"PRIu64"\n", max_gen);
	return 0;
}

static int changed = 0;
static int show_file_transid_cb(uint64_t subvolid, int fd,
				struct btrfs_ioctl_search_header *sh,
				struct btrfs_file_extent_item *item,
				u64 found_gen,
				struct name_lookup_cache *cache, void *priv)
{
	uint64_t ino = sh->objectid;
	uint64_t off = sh->offset;
	uint64_t len = extent_len_from_item(item);

	printf("subvol: %"PRIu64" ino: %"PRIu64" gen: %"PRIu64" changed from "
	       "%"PRIu64" to %"PRIu64"\n", subvolid, ino, found_gen, off,
	       len);

	changed++;

	return 0;
}

static int do_show_file_transid(char *path, uint64_t subvol_gen)
{
	int ret, fd;
	uint64_t ino, subvolid;
	struct stat st;
	u64 max_gen; /* ignored */

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		ret = errno;
		fprintf(stderr, "Could not open \"%s\"\n", path);
		return ret;
	}

	ret = fstat(fd, &st);
	if (ret) {
		ret = errno;
		fprintf(stderr, "Error %d while statting \"%s\": %s\n", ret,
			path, strerror(ret));
		goto out;
	}

	ino = st.st_ino;

	ret = __lookup_btrfs_subvolid(fd, &subvolid);
	if (ret) {
		fprintf(stderr, "Could not find subvol for \"%s\"\n", path);
		goto out;
	}

	ret = subvol_find_updated_extents(fd, subvolid, subvol_gen, &max_gen,
					  ino, show_file_transid_cb, NULL);
	if (ret)
		fprintf(stderr, "Error %d: %s\n", ret, strerror(ret));
out:
	close(fd);

	return ret;
}

int main(int argc, char **argv)
{
	int ret;

	if (parse_opts(argc, argv)) {
		printf("tests duperemove btrfs functions.\nUsage:\n"
		       "btrfs-util find-new subvolume last-gen\n"
		       "btrfs-util show-changes hashfile\n"
		       "btrfs-util transid filename last-gen\n");
		return 1;
	}

	switch (action) {
	case FIND_NEW:
		ret = do_find_new(path, gen);
		break;
	case SHOW_CHANGES:
		ret = do_show_changes(path);
		break;
	case TRANSID:
		ret = do_show_file_transid(path, gen);
		break;
	default:
		abort_lineno();
	}

	return ret;
}
#endif	/* BTRFS_UTIL_TEST */
