#!/usr/sbin/dtrace -Cs
#pragma D option quiet
#pragma D option defaultargs
#pragma D option dynvarsize=64m
/*
 * Report on ZFS activity.
 *
 * usage: zfs-mon.d [verbosity [pool-metadata]]
 *
 * verbosity 1 reports basic information about ZFS VFS metadata operations.
 * verbosity 2 adds reports on active ZIOs and pool TXGs.
 * pool-metadata 1 adds details on per-pool metadata operations; it implies
 * verbosity 1 (but you can use 'zfs-mon.d 0 1' if you want to).
 *
 * Information about what gets reported:
 *
 * Total ZFS: zfs_read() and zfs_write() volume, plus how many other ZFS
 *              VFS (metadata) operations there were that probably read
 *		from or write to the filesystem. Lookups are looking up
 *		things from names (in a directory); there are usually a
 *		lot and most of them are cached.
 *		(The script makes some attempt to count zfs_getpage() and
 *		zfs_putpage() activity, but <cks> is not convinced it's
 *		accurate. Our NFS v3 server makes little use of either.)
 *		Note that ZFS reads can hit readahead results and the ARC
 *		cache and not result in actual ZIO activity.
 *
 * Total ZIO: read, write, and how many times pool ZILs were committed.
 *		Note that you can have ZIL commits that don't write any
 *		data because the ZIL doesn't have anything uncommitted.
 *
 * Pool ZIO: count, pool, how many read & write ops and volume, and how
 *		IOs divide up among foreground, synchronous high-priority,
 *		readaheads, asynchronous writebacks, and other background IOs.
 *
 * IO multiplication: ZFS writes and reads versus ZIO writes and *foreground*
 *		ZIO reads. ZFS writes often multiply if you have redundant
 *		vdevs; mirrors will multiply them by (at least) the mirroring
 *		count. ZFS reads multiply on cache misses by the ZFS block
 *		size; you may read 4 KB at the user level, but ZIO always
 *		fetches full blocks (usually 128 KB).
 *
 * ZIL writes: total count, KB used / KB allocated in pool, ZIL commit count.
 *	The ZIL is allocated in blocks but not all of a block may be used
 *	for data before the block is committed.
 *
 * Active ZIO in pool and Pool TXG count should be obvious. Note that
 * active ZIO is an instantaneous snapshot of the current state, not a
 * cumulative count.
 * Metadata operations is the same data as the ZFS (VFS) metadata
 * operations, broken down by type.
 *
 * Note that all sizes and IO counts are per-ten-seconds cumulative totals,
 * *not* per-second numbers. Divide by ten to get a per-second number if you
 * want it, but it may be misleading.
 */

BEGIN
{
        ziotype[0] = "null";
        ziotype[1] = "read";
        ziotype[2] = "write";
        ziotype[3] = "free";
        ziotype[4] = "claim";
        ziotype[5] = "ioctl";

	/* It would be nice to get a per-pool metadata breakdown,
	   but this requires far too much grunt-work.
	   Well, unless we resort to CPP macros ... */
	zfsmops["zfs_setattr"]	= "setattr";
	zfsmops["zfs_create"]	= "create";
	zfsmops["zfs_remove"]	= "rm";
	zfsmops["zfs_link"]	= "ln";
	zfsmops["zfs_rename"]	= "mv";
	zfsmops["zfs_mkdir"]	= "mkdir";
	zfsmops["zfs_rmdir"]	= "rmdir";
	zfsmops["zfs_symlink"]	= "symlink";
	zfsmops["zfs_lookup"]	= "lookup";
	zfsmops["zfs_readdir"]	= "readdir";
	zfsmops["zfs_readlink"]	= "readlink";

	verbose = $1;
	metadata = $2;
}

/*
 * Count ZIL activity
 */
fbt::zil_lwb_write_start:entry
{
	this->syncpool = (string) args[0]->zl_dmu_pool->dp_spa->spa_name;
	@zilsync[this->syncpool] = count();
	@zilused[this->syncpool] = sum(args[1]->lwb_nused);
	@zilalloc[this->syncpool] = sum(args[1]->lwb_sz);
}

/* There is often a mismatch between ZIL commits and ZIL write activity.
 * <cks> assumes that this is because zil_commit() can be called when
 * there actually is nothing to commit. This may make tracking it less
 * useful; we'll see.
 */
fbt::zil_commit:entry
{
	@zilcommit = count();
	this->syncpool = (string) args[0]->zl_dmu_pool->dp_spa->spa_name;
	@zilcommits[this->syncpool] = count();
}

/*
 * Count how many TXG commits we have over the time span.
 */
fbt::txg_quiesce:entry
{
	self->txgpool = (string) args[0]->dp_spa->spa_name;
	self->txact = 1
}
fbt::txg_quiesce:return
/ self->txact /
{
	@txg[self->txgpool] = count();
	self->txact = 0;
}

/*
 * Count zfs_read and zfs_write activity so we can estimate the
 * multiplication factor. For reads this will be affected by ARC
 * hits.
 */
fbt::zfs_read:entry, fbt::zfs_write:entry
{
	self->zp = (znode_t *) args[0]->v_data;
	self->zpool = (string) self->zp->z_zfsvfs->z_os->os->os_spa->spa_name;
	self->zsize = args[1]->uio_resid;
}
fbt::zfs_getpage:entry, fbt::zfs_putpage:entry
{
	self->zp = (znode_t *) args[0]->v_data;
	self->zpool = (string) self->zp->z_zfsvfs->z_os->os->os_spa->spa_name;
	self->zsize = args[2];
}
fbt::zfs_putpage:entry
{
	self->inputpages = 1;
	self->putflags = args[3];
}

fbt::zfs_read:return, fbt::zfs_getpage:return
/ args[1] == 0 && self->zsize /
{
	@zfsread[self->zpool] = sum(self->zsize);
	@zfsrc[self->zpool] = count();
	@zfsrtot = sum(self->zsize);
}
fbt::zfs_write:return, fbt::zfs_putpage:return
/ args[1] == 0 && self->zsize /
{
	@zfswrite[self->zpool] = sum(self->zsize);
	@zfswc[self->zpool] = count();
	@zfswtot = sum(self->zsize);
}

/* NNGH */
fbt::zfs_putapage:entry
{ printf("zfs_putapage\n"); }
fbt::zfs_putapage:entry
/ self->inputpages && self->zsize == 0 /
{
	this->zpp = (znode_t *) args[0]->v_data;
	self->zpoolp = (string) this->zpp->z_zfsvfs->z_os->os->os_spa->spa_name;
	self->lenp = args[3];
}
fbt::zfs_putapage:return
/ args[1] == 0 && self->lenp /
{
	this->zsize = *(self->lenp);
	@zfswrite[self->zpoolp] = sum(this->zsize);
	@zfswtot = sum(this->zsize);
	@zfswput = sum(this->zsize);
}
fbt::zfs_putapage:return
{
	self->zpoolp = 0;
	self->lenp = 0;
}

fbt::zfs_read:return, fbt::zfs_write:return, fbt::zfs_getpage:return, fbt::zfs_putpage:return
/ self->zsize /
{
	self->zsize = 0;
	self->zpool = 0;
	self->zp = 0;
	self->inputpages = 0;
}

/*
 * Try to track metadata operations that can read and write.
 * We only care about operations that can be used through NFS v3, because
 * <cks> likes simplifcations.
 */
fbt::zfs_setattr:return, fbt::zfs_create:return, fbt::zfs_remove:return, fbt::zfs_link:return, fbt::zfs_rename:return, fbt::zfs_mkdir:return, fbt::zfs_rmdir:return, fbt::zfs_symlink:return
/ args[1] == 0 /
{
	@zfswrops = count();
	@zwrmops[zfsmops[probefunc] != 0 ? zfsmops[probefunc] : probefunc] = count();
}

fbt::zfs_lookup:return
/ args[1] == 0 /
{
	@zfslkops = count();
}
fbt::zfs_readdir:return, fbt::zfs_readlink:return
/ args[1] == 0 /
{
	@zfsrdops = count();
	@zrmops[zfsmops[probefunc] != 0 ? zfsmops[probefunc] : probefunc] = count();
}


fbt::zfs_setattr:entry, fbt::zfs_create:entry, fbt::zfs_remove:entry, fbt::zfs_link:entry, fbt::zfs_rename:entry, fbt::zfs_mkdir:entry, fbt::zfs_rmdir:entry, fbt::zfs_symlink:entry,fbt::zfs_lookup:entry,fbt::zfs_readdir:entry, fbt::zfs_readlink:entry
{
	self->zp = (znode_t *) args[0]->v_data;
	self->zpool = (string) self->zp->z_zfsvfs->z_os->os->os_spa->spa_name;
}

/*
 * It's possible to do better than this macro, but it requires CPP magic
 * and is <cks>'s opinion less clear as a result. See
 *	http://gcc.gnu.org/onlinedocs/cpp/Traditional-macros.html
 * for details on how.
 */
#define	ZVTR(FUNC, AGGR)	fbt::FUNC:return \
	/ args[1] == 0 && self->zp / \
	{AGGR[self->zpool] = count(); @zpoolops[self->zpool] = count(); }

ZVTR(zfs_setattr,  @z_setattr)
ZVTR(zfs_create,   @z_create)
ZVTR(zfs_remove,   @z_remove)
ZVTR(zfs_link,     @z_link)
ZVTR(zfs_rename,   @z_rename)
ZVTR(zfs_mkdir,    @z_mkdir)
ZVTR(zfs_rmdir,    @z_rmdir)
ZVTR(zfs_symlink,  @z_symlink)
ZVTR(zfs_lookup,   @z_lookup)
ZVTR(zfs_readdir,  @z_readdir)
ZVTR(zfs_readlink, @z_readlink)

fbt::zfs_setattr:return, fbt::zfs_create:return, fbt::zfs_remove:return, fbt::zfs_link:return, fbt::zfs_rename:return, fbt::zfs_mkdir:return, fbt::zfs_rmdir:return, fbt::zfs_symlink:return,fbt::zfs_lookup:return,fbt::zfs_readdir:return, fbt::zfs_readlink:return
{
	self->zp = 0;
	self->zpool = 0;
}

/*
 * We are only really interested in IO counts et al for IO to leaf devices.
 */
fbt::zio_create:return
/ args[1]->io_type && args[1]->io_type != 5 &&
	args[1]->io_vd && args[1]->io_vd->vdev_ops->vdev_op_leaf /
{
	this->pool = (string) args[1]->io_spa->spa_name;
	this->cactive = 1;
	@zactive[this->pool] = sum(1);
	@z1active = sum(1);

	/* Even if we do not use this timestamp, we need some marker for
	   'zio_create has incremented the active counter'. Otherwise the
	   active count will go negative during early startup, as ZIOs
	   complete that were created before this script started. */
	ziots[args[1]] = timestamp;
}
fbt::zio_create:return
/ this->cactive && args[1]->io_type == 1 /
{
	@zractive[this->pool] = sum(1);
	@z1ractive = sum(1);
}
fbt::zio_create:return
/ this->cactive && args[1]->io_type == 2 /
{
	@zwactive[this->pool] = sum(1);
	@z1wactive = sum(1);
}
fbt::zio_create:return
/ this->cactive /
{
	this->cactive = 0;
}

/*
 * Main tracking
 */
fbt::zio_done:entry
/ args[0]->io_type && args[0]->io_type != 5 &&
	args[0]->io_vd && args[0]->io_vd->vdev_ops->vdev_op_leaf &&
	ziots[args[0]] /
{
	this->active = 1;
	this->op = ziotype[args[0]->io_type];
	this->pool = (string) args[0]->io_spa->spa_name;
	@zio[this->pool] = count();
	@zactive[this->pool] = sum(-1);
	@z1active = sum(-1);

	ziots[args[0]] = 0;
}

fbt::zio_done:entry
/ this->active && args[0]->io_priority == 0 /
{
	@ziofg[this->pool] = count();
}
fbt::zio_done:entry
/ this->active && args[0]->io_priority == 6 /
{
	@ziora[this->pool] = count();
}
fbt::zio_done:entry
/ this->active && args[0]->io_priority == 4 /
{
	@ziowb[this->pool] = count();
}
fbt::zio_done:entry
/ this->active && args[0]->io_priority != 0 && args[0]->io_priority != 6 && args[0]->io_priority != 4/
{
	@ziobg[this->pool] = count();
}

/* Track high-priority, someone-is-waiting reads explicitly. */
fbt::zio_done:entry
/ this->active && this->op == "read" && args[0]->io_priority == 0 /
{
	@zfgread[this->pool] = count();
	@zfgrsize[this->pool] = sum(args[0]->io_size);
}

fbt::zio_done:entry
/ this->active && this->op == "read" /
{
	@zread[this->pool] = count();
	@zrsize[this->pool] = sum(args[0]->io_size);
	@zractive[this->pool] = sum(-1);
	@z1ractive = sum(-1);
	@ztread = sum(args[0]->io_size);
}

fbt::zio_done:entry
/ this->active && this->op == "write" /
{
	@zwrite[this->pool] = count();
	@zwsize[this->pool] = sum(args[0]->io_size);
	@zwactive[this->pool] = sum(-1);
	@z1wactive = sum(-1);
	@ztwrite = sum(args[0]->io_size);
}

fbt::zio_done:entry
/ this->active /
{
	this->active = 0;
	this->pool = 0;
	this->op = 0;
}

tick-10sec
/ verbose == 0 /
{
	trunc(@txg);
	trunc(@zactive); trunc(@zractive); trunc(@zwactive);
}

tick-10sec
{	
	printf("\n---- %Y ---- (10 second totals):\n", walltimestamp);
	normalize(@zfsrtot, 1024*1024); normalize(@zfswtot, 1024*1024);
	normalize(@ztread, 1024*1024); normalize(@ztwrite, 1024*1024);
	printa("Total ZFS: %@5d MB read %@5d MB write   +FS metaops: %@3d readers %@3d writers %@4d lookups\n", @zfsrtot, @zfswtot, @zfsrdops, @zfswrops, @zfslkops);
	printa("Total ZIO: %@5d MB read %@5d MB write   %@d ZIL commits\n", @ztread, @ztwrite, @zilcommit);
		printf("\n");

	printf("Pool ZIO:\n");
	normalize(@zrsize, 1024*1024);	normalize(@zwsize, 1024*1024);
	printa("%@6d in %16s  reads: %@4d / %@4d MB  writes: %@5d / %@4d MB | %@5d fg %@4d ra %@5d wb %@3d bg\n",
		@zio, @zread, @zrsize, @zwrite, @zwsize, @ziofg, @ziora, @ziowb, @ziobg);
	printf("\n");

	normalize(@zfsread, 1024*1024); normalize(@zfswrite, 1024*1024);
	normalize(@zfgrsize, 1024*1024);
	printf("IO multiplication, zfs_(read|write) vs ZIO (ZIO reads are fg only):\n");
	printa("  %-16s  writes: %@5d / %@4d MB vs %@5d / %@4d MB  reads: %@4d / %@4d MB vs %@4d / %@4d MB\n",
		@zfswc, @zfswrite, @zwrite, @zwsize,
		@zfsrc, @zfsread, @zfgread, @zfgrsize);
	printf("\n");

	/* The X/Y sizes are the amount of data actually used and the amount
	   of ZIL space allocated. <cks> believes that the ZIL allocates in
	   whole 4k? blocks but may not use all of the space in a block. */
	printf("ZIL writes:\n");
	normalize(@zilused, 1024);
	normalize(@zilalloc, 1024);
	printa("%@6d for %@5d / %@6d KB in %-16s  %@4d commits\n", @zilsync,
		@zilused, @zilalloc, @zilcommits);
}

tick-10sec
/verbose || metadata/
{
	printf("\nMetadata operations:\n");
	printf(" read: "); printa(" %@d %s", @zrmops); printf("\n");
	printf(" write:"); printa(" %@d %s", @zwrmops); printf("\n");
}
tick-10sec
/metadata/
{
	printa(" %@5d %-16s  %@3d creat %@3d ln %@3d mv %@3d rm %@3d mkdir %@3d rmdir %@3d slink %@3d sattr | %@3d rdlink %@3d rddir | %@4d lookup\n",
		@zpoolops,
		@z_create, @z_link, @z_rename, @z_remove, @z_mkdir, @z_rmdir,
		@z_symlink, @z_setattr,
		@z_readlink, @z_readdir, @z_lookup);
}

tick-10sec
/verbose >= 2/
{
	printf("\n");
	printf("Active ZIO:\n");
	printa("%@6d  == TOTAL ==       %@5d read / %@3d write\n",
		@z1active, @z1ractive, @z1wactive);
	printa("%@6d in %-16s  %@3d read / %@3d write\n", @zactive, @zractive, @zwactive);
	printf("\n");

	printf("Pool TXG count:\n");
	printa("%@6d  %s\n", @txg);

	/* <cks> doesn't expect this to fire on our workload.
	   It should probably be removed. */
	printa("\nzfs_putapage() bytes: %@d\n", @zfswput);
	trunc(@zfswput);
}

/*
 * Force a blank line at the end of the report.
 */
tick-10sec
{
	printf("\n");
}

/*
 * We truncate everything at END so that it isn't printed out one last
 * time (badly).
 */
tick-10sec, END
{
	trunc(@zilsync); trunc(@zilused); trunc(@zilalloc);
	trunc(@txg);
	trunc(@zilcommit); trunc(@zilcommits);

	trunc(@zio); trunc(@zread); trunc(@zrsize); trunc(@zwrite);
	trunc(@zwsize);
	trunc(@ziofg); trunc(@ziora); trunc(@ziowb); trunc(@ziobg);
	trunc(@ztread); trunc(@ztwrite);

	trunc(@zfsread); trunc(@zfswrite); trunc(@zfsrc); trunc(@zfswc);
	trunc(@zfgread); trunc(@zfgrsize);
	trunc(@zfsrtot); trunc(@zfswtot);

	trunc(@zfslkops); trunc(@zfsrdops); trunc(@zfswrops);
	trunc(@zrmops); trunc(@zwrmops);

	trunc(@zpoolops);
	trunc(@z_create); trunc(@z_link); trunc(@z_rename); trunc(@z_remove);
	trunc(@z_mkdir); trunc(@z_rmdir); trunc(@z_setattr); trunc(@z_symlink);
	trunc(@z_readdir); trunc(@z_readlink); trunc(@z_lookup);
}

END
{
	trunc(@zactive); trunc(@zractive); trunc(@zwactive);
	trunc(@z1active); trunc(@z1ractive); trunc(@z1wactive);
}
