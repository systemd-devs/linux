/*
 *
 * Copyright (C) 2011 Novell Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "overlayfs.h"

static int ovl_copy_up_truncate(struct dentry *dentry)
{
	int err;
	struct dentry *parent;
	struct kstat stat;
	struct path lowerpath;
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct inode *inode = d_backing_inode(dentry);

	parent = dget_parent(dentry);
	err = ovl_copy_up(parent);
	if (err)
		goto out_dput_parent;

	ovl_path_lower(dentry, &lowerpath);
	err = vfs_getattr(&lowerpath, &stat);
	if (err)
		goto out_dput_parent;

	stat.size = 0;

	/* Shift UID and GID if ncessary */
	stat.uid = ovl_vfs_shift_kuid(ofs, inode->i_uid);
	stat.gid = ovl_vfs_shift_kgid(ofs, inode->i_gid);

	err = ovl_copy_up_one(parent, dentry, &lowerpath, &stat);

out_dput_parent:
	dput(parent);
	return err;
}

int ovl_setattr(struct dentry *dentry, struct iattr *attr)
{
	int err;
	struct dentry *upperdentry;

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	err = ovl_copy_up(dentry);
	if (!err) {
		upperdentry = ovl_dentry_upper(dentry);

		mutex_lock(&upperdentry->d_inode->i_mutex);
		err = notify_change(upperdentry, attr, NULL);
		mutex_unlock(&upperdentry->d_inode->i_mutex);
	}
	ovl_drop_write(dentry);
out:
	return err;
}

static int ovl_getattr(struct vfsmount *mnt, struct dentry *dentry,
			 struct kstat *stat)
{
	int ret;
	struct path realpath;
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct inode *inode = d_backing_inode(dentry);

	ovl_path_real(dentry, &realpath);
	ret = vfs_getattr(&realpath, stat);
	if (ret)
		return ret;

	/* shift UID and GID if necessary */
	stat->uid = ovl_vfs_shift_kuid(ofs, inode->i_uid);
	stat->gid = ovl_vfs_shift_kgid(ofs, inode->i_gid);

	return 0;
}

/*
 * Remap fsuid for overlayfs permission check in case if the
 * constructed kuid from inode uid value is valid and
 * 1) has a mapping in the current user namespace and
 * 2) equals the current_fsuid() or
 */
static bool ovl_permission_remap_fsuid(struct ovl_fs *ofs,
				       struct inode *inode)
{
	kuid_t uid;
	struct user_namespace *user_ns = current_user_ns();

	if (!ovl_config_shift_uids(ofs))
		return false;

	/* No mapping is needed in this case */
	if (uid_eq(current_fsuid(), inode->i_uid))
		return false;

	uid = ovl_vfs_shift_kuid(ofs, inode->i_uid);
	/* fail if uid not valid or namespace crossed */
	if (!uid_valid(uid) || !kuid_has_mapping(user_ns, uid))
		return false;

	if (uid_eq(current_fsuid(), uid))
		return true;

	return false;
}

/*
 * Remap fsgid if the constructed kgid from inode gid value is
 * valid and it equals the current_fsgid()
 */
static bool ovl_permission_remap_fsgid(struct ovl_fs *ofs,
				       struct inode *inode)
{
	kgid_t gid;
	struct user_namespace *user_ns = current_user_ns();

	if (!ovl_config_shift_gids(ofs))
		return false;

	/* No mapping is needed in this case */
	if (gid_eq(current_fsgid(), inode->i_gid))
		return false;

	gid = ovl_vfs_shift_kgid(ofs, inode->i_gid);
	/* fail if gid not valid or namespace crossed */
	if (!gid_valid(gid) || !kgid_has_mapping(user_ns, gid))
		return false;

	if (gid_eq(current_fsgid(), gid))
		return true;

	return false;
}

int ovl_permission(struct inode *inode, int mask)
{
	struct ovl_entry *oe;
	struct dentry *alias = NULL;
	struct inode *realinode;
	struct dentry *realdentry;
	const struct cred *old_cred = NULL;
	struct cred *override_cred;
	struct ovl_fs *ofs = inode->i_sb->s_fs_info;
	bool remap_fsuid = false, remap_fsgid = false;
	bool is_upper;
	int err;

	if (S_ISDIR(inode->i_mode)) {
		oe = inode->i_private;
	} else if (mask & MAY_NOT_BLOCK) {
		return -ECHILD;
	} else {
		/*
		 * For non-directories find an alias and get the info
		 * from there.
		 */
		alias = d_find_any_alias(inode);
		if (WARN_ON(!alias))
			return -ENOENT;

		oe = alias->d_fsdata;
	}

	realdentry = ovl_entry_real(oe, &is_upper);

	/* Careful in RCU walk mode */
	realinode = ACCESS_ONCE(realdentry->d_inode);
	if (!realinode) {
		WARN_ON(!(mask & MAY_NOT_BLOCK));
		err = -ENOENT;
		goto out_dput;
	}

	if (mask & MAY_WRITE) {
		umode_t mode = realinode->i_mode;

		/*
		 * Writes will always be redirected to upper layer, so
		 * ignore lower layer being read-only.
		 *
		 * If the overlay itself is read-only then proceed
		 * with the permission check, don't return EROFS.
		 * This will only happen if this is the lower layer of
		 * another overlayfs.
		 *
		 * If upper fs becomes read-only after the overlay was
		 * constructed return EROFS to prevent modification of
		 * upper layer.
		 */
		err = -EROFS;
		if (is_upper && !IS_RDONLY(inode) && IS_RDONLY(realinode) &&
		    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)))
			goto out_dput;
	}

	/*
	 * Check if we should map current's fsuid and fsgid to the
	 * corresponding inode->i_uid and inode->i_gid in order to
	 * perform a basic permission check. We want to success at
	 * acl_permission_check()
	 *
	 * Before updating fsuid and fsgid we do the UID and GID
	 * shifting according to the VFS user namespace shift rules.
	 */
	remap_fsuid = ovl_permission_remap_fsuid(ofs, realinode);
	remap_fsgid = ovl_permission_remap_fsgid(ofs, realinode);

	if (remap_fsuid || remap_fsgid) {
		if (mask & MAY_NOT_BLOCK)
			return -ECHILD;

		override_cred = prepare_creds();
		if (!override_cred)
			goto out_dput;

		if (remap_fsuid)
			override_cred->fsuid = realinode->i_uid;

		if (remap_fsgid)
			override_cred->fsgid = realinode->i_gid;

		old_cred = override_creds(override_cred);
	}

	err = __inode_permission(realinode, mask);
	if (old_cred) {
		revert_creds(old_cred);
		put_cred(override_cred);
	}
out_dput:
	dput(alias);
	return err;
}

static const char *ovl_get_link(struct dentry *dentry,
				struct inode *inode,
				struct delayed_call *done)
{
	struct dentry *realdentry;
	struct inode *realinode;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	realdentry = ovl_dentry_real(dentry);
	realinode = realdentry->d_inode;

	if (WARN_ON(!realinode->i_op->get_link))
		return ERR_PTR(-EPERM);

	return realinode->i_op->get_link(realdentry, realinode, done);
}

static int ovl_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	struct path realpath;
	struct inode *realinode;

	ovl_path_real(dentry, &realpath);
	realinode = realpath.dentry->d_inode;

	if (!realinode->i_op->readlink)
		return -EINVAL;

	touch_atime(&realpath);

	return realinode->i_op->readlink(realpath.dentry, buf, bufsiz);
}


static bool ovl_is_private_xattr(const char *name)
{
	return strncmp(name, OVL_XATTR_PRE_NAME, OVL_XATTR_PRE_LEN) == 0;
}

int ovl_setxattr(struct dentry *dentry, const char *name,
		 const void *value, size_t size, int flags)
{
	int err;
	struct dentry *upperdentry;

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	err = -EPERM;
	if (ovl_is_private_xattr(name))
		goto out_drop_write;

	err = ovl_copy_up(dentry);
	if (err)
		goto out_drop_write;

	upperdentry = ovl_dentry_upper(dentry);
	err = vfs_setxattr(upperdentry, name, value, size, flags);

out_drop_write:
	ovl_drop_write(dentry);
out:
	return err;
}

static bool ovl_need_xattr_filter(struct dentry *dentry,
				  enum ovl_path_type type)
{
	if ((type & (__OVL_PATH_PURE | __OVL_PATH_UPPER)) == __OVL_PATH_UPPER)
		return S_ISDIR(dentry->d_inode->i_mode);
	else
		return false;
}

ssize_t ovl_getxattr(struct dentry *dentry, const char *name,
		     void *value, size_t size)
{
	struct path realpath;
	enum ovl_path_type type = ovl_path_real(dentry, &realpath);

	if (ovl_need_xattr_filter(dentry, type) && ovl_is_private_xattr(name))
		return -ENODATA;

	return vfs_getxattr(realpath.dentry, name, value, size);
}

ssize_t ovl_listxattr(struct dentry *dentry, char *list, size_t size)
{
	struct path realpath;
	enum ovl_path_type type = ovl_path_real(dentry, &realpath);
	ssize_t res;
	int off;

	res = vfs_listxattr(realpath.dentry, list, size);
	if (res <= 0 || size == 0)
		return res;

	if (!ovl_need_xattr_filter(dentry, type))
		return res;

	/* filter out private xattrs */
	for (off = 0; off < res;) {
		char *s = list + off;
		size_t slen = strlen(s) + 1;

		BUG_ON(off + slen > res);

		if (ovl_is_private_xattr(s)) {
			res -= slen;
			memmove(s, s + slen, res - off);
		} else {
			off += slen;
		}
	}

	return res;
}

int ovl_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct path realpath;
	enum ovl_path_type type = ovl_path_real(dentry, &realpath);

	err = ovl_want_write(dentry);
	if (err)
		goto out;

	err = -ENODATA;
	if (ovl_need_xattr_filter(dentry, type) && ovl_is_private_xattr(name))
		goto out_drop_write;

	if (!OVL_TYPE_UPPER(type)) {
		err = vfs_getxattr(realpath.dentry, name, NULL, 0);
		if (err < 0)
			goto out_drop_write;

		err = ovl_copy_up(dentry);
		if (err)
			goto out_drop_write;

		ovl_path_upper(dentry, &realpath);
	}

	err = vfs_removexattr(realpath.dentry, name);
out_drop_write:
	ovl_drop_write(dentry);
out:
	return err;
}

static bool ovl_open_need_copy_up(int flags, enum ovl_path_type type,
				  struct dentry *realdentry)
{
	if (OVL_TYPE_UPPER(type))
		return false;

	if (special_file(realdentry->d_inode->i_mode))
		return false;

	if (!(OPEN_FMODE(flags) & FMODE_WRITE) && !(flags & O_TRUNC))
		return false;

	return true;
}

struct inode *ovl_d_select_inode(struct dentry *dentry, unsigned file_flags)
{
	int err;
	struct path realpath;
	enum ovl_path_type type;

	if (d_is_dir(dentry))
		return d_backing_inode(dentry);

	type = ovl_path_real(dentry, &realpath);
	if (ovl_open_need_copy_up(file_flags, type, realpath.dentry)) {
		err = ovl_want_write(dentry);
		if (err)
			return ERR_PTR(err);

		if (file_flags & O_TRUNC)
			err = ovl_copy_up_truncate(dentry);
		else
			err = ovl_copy_up(dentry);
		ovl_drop_write(dentry);
		if (err)
			return ERR_PTR(err);

		ovl_path_upper(dentry, &realpath);
	}

	if (realpath.dentry->d_flags & DCACHE_OP_SELECT_INODE)
		return realpath.dentry->d_op->d_select_inode(realpath.dentry, file_flags);

	return d_backing_inode(realpath.dentry);
}

static const struct inode_operations ovl_file_inode_operations = {
	.setattr	= ovl_setattr,
	.permission	= ovl_permission,
	.getattr	= ovl_getattr,
	.setxattr	= ovl_setxattr,
	.getxattr	= ovl_getxattr,
	.listxattr	= ovl_listxattr,
	.removexattr	= ovl_removexattr,
};

static const struct inode_operations ovl_symlink_inode_operations = {
	.setattr	= ovl_setattr,
	.get_link	= ovl_get_link,
	.readlink	= ovl_readlink,
	.getattr	= ovl_getattr,
	.setxattr	= ovl_setxattr,
	.getxattr	= ovl_getxattr,
	.listxattr	= ovl_listxattr,
	.removexattr	= ovl_removexattr,
};

struct inode *ovl_new_inode(struct super_block *sb, umode_t mode,
			    struct ovl_entry *oe)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;

	mode &= S_IFMT;

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_flags |= S_NOATIME | S_NOCMTIME;

	switch (mode) {
	case S_IFDIR:
		inode->i_private = oe;
		inode->i_op = &ovl_dir_inode_operations;
		inode->i_fop = &ovl_dir_operations;
		break;

	case S_IFLNK:
		inode->i_op = &ovl_symlink_inode_operations;
		break;

	case S_IFREG:
	case S_IFSOCK:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		inode->i_op = &ovl_file_inode_operations;
		break;

	default:
		WARN(1, "illegal file type: %i\n", mode);
		iput(inode);
		inode = NULL;
	}

	return inode;
}
