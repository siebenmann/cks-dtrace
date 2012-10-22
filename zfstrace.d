#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option defaultargs
#pragma D option dynvarsize=64m

/*
 * Dump ZFS activity traces.
 * We trace zfs_read/zfs_write/zfs_getpage, ZIO activity, and iSCSI
 * activity.
 * (this is what we care about right now.)
 * Trace output is deliberately condensed because <cks> is worried about
 * DTrace keeping up under heavy load.
 *
 * Timestamps and delta times are microseconds.
 *
 * Output lines:
 *	ZR ...			-- ZFS reads/getpages
 *	ZW ...			-- ZFS writes
 *	ZIO ...			-- ZIO ops
 *	IS ...			-- iSCSI ops
 * See further comments for descriptions of the fields for each.
 *
 * All traces are produced when the operation completes. For iSCSI ops,
 * this is when the reply has been fully received (state E3).
 * Multi-CPU issues and other things may not produce traces in strictly
 * sequential order; use the timestamps if you need to reconstruct this
 * better.
 */

/* For CSLab, the first 18 characters of the iSCSI target name are
 * constant so we omit them. Change this as appropriate for your
 * environment.
 */
inline int TGTNAME_OFFSET = 18;

BEGIN
{
        ziotype[0] = "null";
        ziotype[1] = "read";
        ziotype[2] = "write";
        ziotype[3] = "free";
        ziotype[4] = "claim";
        ziotype[5] = "ioctl";
}

/*
 * Count zfs_read and zfs_write activity so we can estimate the
 * multiplication factor. For reads this will be affected by ARC
 * hits.
 */
fbt::zfs_read:entry, fbt::zfs_write:entry
{
	self->fs = (string)args[0]->v_vfsp->vfs_mntpt->rs_string;
	self->zp = (znode_t *) args[0]->v_data;
	self->inum = self->zp->z_id + 0ULL;
	self->zpool = (string) self->zp->z_zfsvfs->z_os->os->os_spa->spa_name;
	self->zsize = args[1]->uio_resid;
	self->zoffset = args[1]->_uio_offset._f;
	self->ts = timestamp;
}
fbt::zfs_getpage:entry
{
	self->fs = (string)args[0]->v_vfsp->vfs_mntpt->rs_string;
	self->zp = (znode_t *) args[0]->v_data;
	self->inum = self->zp->z_id + 0ULL;
	self->zpool = (string) self->zp->z_zfsvfs->z_os->os->os_spa->spa_name;
	self->zsize = args[2];
	self->zoffset = args[1];
	self->ts = timestamp;
}

/*
 * [ZR|ZW] <delta> <offset in file> <size> <filesystem> <inode #> <pool> <timestamp> <cpu>
 *    1       2           3            4       5           6        7         8  9
 *
 * offset and size are in bytes.
 */
fbt::zfs_read:return, fbt::zfs_getpage:return
/ args[1] == 0 && self->zsize /
{
	printf("ZR %d %d %d %s %d %s %d %d\n", (timestamp-self->ts)/1000,
		self->zoffset, self->zsize, 
		self->fs, self->inum, self->zpool,
		timestamp/1000, cpu);
}

fbt::zfs_write:return
/ args[1] == 0 && self->zsize /
{
	printf("ZW %d %d %d %s %d %s %d %d\n", (timestamp-self->ts)/1000,
		self->zoffset, self->zsize, 
		self->fs, self->inum, self->zpool,
		timestamp/1000, cpu);
}

fbt::zfs_read:return, fbt::zfs_write:return, fbt::zfs_getpage:return, fbt::zfs_putpage:return
/ self->zsize /
{
	self->zsize = 0;
	self->zpool = 0;
	self->zp = 0;
	self->inputpages = 0;
	self->zoffset = 0;
}

/*
 * We are only really interested in IO counts et al for IO to leaf devices.
 */
fbt::zio_create:return
/ args[1]->io_type && args[1]->io_type != 5 &&
	args[1]->io_vd && args[1]->io_vd->vdev_ops->vdev_op_leaf /
{
	this->pool = (string) args[1]->io_spa->spa_name;
	ziots[args[1]] = timestamp;
}

/*
 * ZIO <op> <priority> <delta> <offset> <size> <pool> <vdev GUID> <timestamp> <cpu>
 *  1   2       3         4       5        6     7        8           9         10
 *
 * offset and size are still both in bytes. offset is the (byte) offset into
 * the vdev device.
 * op is zio_type_name: see the beginning.
 *
 * priorities:
 *	0	foreground sync read/write, log write, do it now
 *	1	cache fill / 'AGG'?
 *	2	DDT prefetch
 *	4	free, async write
 *	6	async read
 *	10	resilver
 *	20	scrub
 *
 * see zio_priority_table in uts/common/fs/zfs/zio.c
 *
 */
fbt::zio_done:entry
/ args[0]->io_type && args[0]->io_type != 5 &&
	args[0]->io_vd && args[0]->io_vd->vdev_ops->vdev_op_leaf &&
	ziots[args[0]] /
{
	this->op = ziotype[args[0]->io_type];
	this->pool = (string) args[0]->io_spa->spa_name;
	this->delta = (timestamp-ziots[args[0]]) / 1000;

	printf("ZIO %s %d %d %d %d %s %lu %d %d\n",
		this->op, args[0]->io_priority,
		this->delta, args[0]->io_offset, args[0]->io_size,
		this->pool, args[0]->io_vd->vdev_guid,
		timestamp/1000, cpu);

	ziots[args[0]] = 0;
}

/*
 * iSCSI
 */
sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E1"/
{
	started[arg0] = timestamp;
}

/*
 * IS c.<cmd> <delta> <lba> <count> <tgt name>/<lun> <ip> <timestamp> <cpu>
 *  1    2      3       4     5              6         7       8        9
 *
 * lba and count are in (512-byte) sectors.
 * <cmd> is in decimal. 40 is READ_G1/READ_10; 42 is WRITE_G1/WRITE_10.
 */
sdt::iscsi_cmd_state_machine:event
/(string) arg2 == "E3" && started[arg0]/
{
	this->delta = (timestamp - started[arg0])/1000;
	this->icmdp = (iscsi_cmd_t *) arg0;
	this->lun = this->icmdp->cmd_lun;

	/* This is a sleazy hack, but for us the first 18 characters
	   of the target name are always constant. */
	this->tgtname = (string) (this->lun->lun_sess->sess_name+TGTNAME_OFFSET);

	this->cmdb = this->icmdp->cmd_un.scsi.pkt->pkt_cdbp[0];
	this->cdb = this->icmdp->cmd_un.scsi.pkt->pkt_cdbp;
	this->lba = (uint)this->cdb[2] << 24 | (uint)this->cdb[3] << 16 | (uint)this->cdb[4] << 8 | (uint)this->cdb[5];
	this->count = (uint)this->cdb[7] << 8 | (uint)this->cdb[8];

	this->a = (uint8_t *)&this->icmdp->cmd_conn->conn_curr_addr.sin4.sin_addr.S_un.S_addr;
	this->addr1 = strjoin(lltostr(this->a[0] + 0ULL), strjoin(".",
			strjoin(lltostr(this->a[1] + 0ULL), ".")));
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".",
			lltostr(this->a[3] + 0ULL)));
	this->address = strjoin(this->addr1, this->addr2);

	printf("IS c.%d %d %d %d %s/%d %s %d %d\n", this->cmdb,
		this->delta, this->lba, this->count,
		this->tgtname, this->lun->lun_num, this->address,
		timestamp/1000, cpu);
	started[arg0] = 0;
}
