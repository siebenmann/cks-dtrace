#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option defaultargs
#pragma D option dynvarsize=64m
/*
 * Report on NFS v3 and ZFS IO latencies and timings.
 *
 * usage: nfs3-stats.d [verbosity]
 *
 * Verbosity 2 prints stack traces that you probably don't care about.
 *
 * High-level NFS and ZFS IO is separated into 'fast' IO (takes less than
 * 1/4 msec) and 'slow' IO. The assumption is that fast IO is being
 * satisfied from cache instead of from actual disk IO.
 */

dtrace:::BEGIN
{
	ziotype[0] = "zio_null";
	ziotype[1] = "zio_read";
	ziotype[2] = "zio_write";
	ziotype[3] = "zio_free";
	ziotype[4] = "zio_claim";
	ziotype[5] = "zio_ioctl";

	chain[0] = "(error)";
	chain[1] = "zfs_read";
	chain[2] = "zfs_write";
	chain[3] = "zfs_write from commit";

	verbose = $1;
	starttime = timestamp;
}

/* 
 * NFS v3 tracing
*/
fbt::rfs3_read:entry
{self->rts = timestamp;}
fbt::rfs3_read:return 
/self->rts > 0 && (timestamp-self->rts) > 250000/
{
	this->delta = (timestamp - self->rts)/1000000;
	@nfs3["rfs3_read for > 1/4 ms times", "ms"] = quantize(this->delta);
	@avg["NFS v3 read avg", "ms"] = avg(this->delta);
	@max["NFS v3 read max", "ms"] = max(this->delta);
}
fbt::rfs3_read:return 
/self->rts > 0/
{
	this->str = (timestamp - self->rts) > 250000 ? "slow reads" : "fast reads";
	@count[this->str] = count();
	self->rts = 0;
}

fbt::rfs3_write:entry
{self->wts = timestamp;}
fbt::rfs3_write:return 
/self->wts > 0 && (timestamp-self->wts) > 250000/
{
	this->delta = (timestamp - self->wts)/1000000;
	@nfs3["rfs3_write for > 1/4 ms times", "ms"] = quantize(this->delta);
	@avg["NFS v3 write avg", "ms"] = avg(this->delta);
	@max["NFS v3 write max", "ms"] = max(this->delta);
}
fbt::rfs3_write:return 
/ self->wts > 0 /
{
	this->str = (timestamp - self->wts) > 250000 ? "slow writes" : "fast writes";
	@count[this->str] = count();
	self->wts = 0;
}

fbt::rfs3_commit:entry
{self->cts = timestamp;}
fbt::rfs3_commit:return 
/self->cts > 0 && (timestamp-self->cts) > 250000/
{
	this->delta = (timestamp - self->cts)/1000000;
	@nfs3["rfs3_commit for > 1/4 ms times", "ms"] = quantize(this->delta);
	@avg["NFS v3 commit avg", "ms"] = avg(this->delta);
	@max["NFS v3 commit max", "ms"] = max(this->delta);
}
fbt::rfs3_commit:return 
/ self->cts > 0 /
{
	this->str = (timestamp - self->cts) > 250000 ? "slow commits" : "fast commits";
	@count[this->str] = count();
	self->cts = 0;
}

fbt::rfs3_*:entry
/ probefunc != "rfs3_readdirplus_free" && probefunc != "rfs3_read_free" && probefunc != "rfs3_readlink_free" && probefunc != "rfs3_readdir_free" /
{ 
	self->basets = timestamp;
}
fbt::rfs3_*:return
/ self->basets > 0 /
{
	this->delta = (timestamp - self->basets) / 1000000;
	@opcount[probefunc] = count();
	@opavg[probefunc, "avg ms"] = avg(this->delta);
	@opdist[probefunc, "ms"] = quantize(this->delta);
	self->basets = 0;
}

/*
 * ZFS level tracing
 *
 * zfs_(read|write) is the high level ZFS interface, zio_* is the low
 * level IO to ZFS devices that is not satisfied from cache. <cks>'s
 * understanding is that ZIO stuff cascades down vdevs; you issue a
 * ZIO against the top level vdev and then it's reflected or replicated
 * to the low-level vdevs that represent actual disks.
 */

fbt::zfs_read:entry, fbt::zfs_write:entry
{
	self->zts = timestamp;
	self->chain = 0;
	@zcount[probefunc] = count();
}
fbt::zfs_read:return, fbt::zfs_write:return
/ self->zts > 0 /
{
	this->delta = (timestamp - self->zts) / 1000000;
	@zavg[probefunc, "avg ms"] = avg(this->delta);
	@zmax[probefunc, "max ms"] = max(this->delta);
	@zstats[probefunc, "ms"] = quantize(this->delta);
	self->ztz = 0;
	self->chain = 0;
}

/* We ignore zio_ioctl (io_type 5) operations because they're only
   used for DKIOCFLUSHWRITECACHE operations and our disks don't
   support those so they complete immediately (in Solaris, they
   don't result in iSCSI commands). We don't need the noise that
   results from tracking them; we only care about real operations
   that might hit the disk.
*/
fbt::zio_create:return
/ args[1]->io_type && args[1]->io_type != 5/
{
	this->op = ziotype[args[1]->io_type];
	ziots[args[1]] = timestamp;
	@ziocount[this->op] = count();
	ziostart[args[1]] = 0;
	ziointr[args[1]] = 0;
}
/* Okay, we'll count zio_ioctl operations as indicators of
   theoretically sync operations but otherwise exclude them.
   I'm neurotic. */
fbt::zio_create:return
/ args[1]->io_type && args[1]->io_type == 5 /
{
	this->op = ziotype[args[1]->io_type];
	@ziocount[this->op] = count();
}

fbt::zio_done:entry
/ ziots[args[0]] > 0 /
{
	this->delta = (timestamp - ziots[args[0]]) / 1000000;
	this->op = ziotype[args[0]->io_type];
	@zioavg[this->op, "ZIO op avg ms"] = avg(this->delta);
	@ziomax[this->op, "ZIO op max ms"] = max(this->delta);
	@ziostats[this->op, "ms"] = quantize(this->delta);
	ziots[args[0]] = 0;
	ziostart[args[0]] = 0;
}

/* We only do the delay on these if it's larger than 1/4 msec.
   NOTE: it's possible for this to come out with zio_vdev_io_start
   having a higher time than zio_interrupt. To highlight this we
   count events too.

   Otherwise too noisy. This is after zio_done to make things
   print out in the right order (sigh). */
fbt::zio_vdev_io_start:entry, fbt::zio_interrupt:entry
/ ziots[args[0]] > 0 && (timestamp - ziots[args[0]]) > 250000 /
{
	this->delta = (timestamp - ziots[args[0]]) / 1000000;
	this->op = ziotype[args[0]->io_type];
	@ziointercount[probefunc, this->op, "for >1/4ms ops"] = count();
	@ziointeravg[probefunc, this->op, "avg ms (for >1/4 ms ops)"] = avg(this->delta);
	@ziointerstats[probefunc, this->op, "ms (for >1/4 ms ops)"] = quantize(this->delta);
}

/*
 * Deltas from one operation to another.
 */
fbt::zfs_read:entry
/ self->rts > 0 /
{ 
	this->delta = (timestamp - self->rts)/1000000;
	@delta["rfs3_read to zfs_read", "ms"] = quantize(this->delta);
	self->chain = 1;
}
fbt::zfs_write:entry
/ self->wts > 0 /
{ 
	this->delta = (timestamp - self->wts)/1000000;
	@delta["rfs3_write to zfs_write", "ms"] = quantize(this->delta);
	self->chain = 2;
}
fbt::zfs_write:entry
/ self->cts > 0 /
{ 
	this->delta = (timestamp - self->cts)/1000000;
	@delta["rfs3_commit to zfs_write", "ms"] = quantize(this->delta);
	self->chain = 3;
}

/* We attempt to only track actual synchronous operations,
   not async IO kicked off (later) from one of these operations. We
   do this based on priority (args[0]), a zio_priority_table[] entry;
   we want priority 0. 
   We exclude zio_ioctl operations for the same reason as before: no
   real disk IO is produced.
*/
/* args0 is zio_t *pio, args8 is zio_type_t type. */
fbt::zio_create:entry
/ args[8] && args[8] != 5 && args[9] == 0 && self->zts > 0 && self->chain/
{
	this->delta = (timestamp - self->zts)/1000000;
	@zdelta["zio_create (sync) from", chain[self->chain], "ms"] = quantize(this->delta);
}

/*
 * Attempt to track 'slow' ZIO initiation. This is the creation of a ZIO
 * operation that starts more than 20 milliseconds after whatever higher-level
 * operation started the show.
 * The stack traces here are not very useful in practice.
*/
fbt::zio_create:entry
/ verbose >= 2 && args[8] && args[8] != 5 && args[9] == 0 && self->zts > 0 && self->chain && ((timestamp - self->zts)/1000000) > 20/
{
	@stack[ziotype[args[8]], ">20 msec sync zio_create from", chain[self->chain], stack()] = count();
}

fbt::zio_vdev_io_start:entry
/ ziots[args[0]] > 0 /
{
	ziostart[args[0]] = timestamp;
}	

/*
 * This is the ZFS-level view of the underlying IO latency; it goes from
 * when the vdev IO is started until ZIO is signalled that it's done.
 */
fbt::zio_interrupt:entry
/ ziostart[args[0]] > 0 /
{
	this->delta = (timestamp - ziostart[args[0]]) / 1000000;
	this->op = ziotype[args[0]->io_type];
	/* This is actually a crucial measure of the actual low-level device
	 * latency as observed by ZFS.
	 */
	@zdelta1["zio_vdev_io_start() to zio_interrupt() for", this->op, "ms"] = quantize(this->delta);
	ziostart[args[0]] = 0;
	ziointr[args[0]] = timestamp;
}
fbt::zio_done:entry
/ ziointr[args[0]] > 0 /
{
	this->delta = (timestamp - ziointr[args[0]]) / 250000;
	this->op = ziotype[args[0]->io_type];
	@zdelta2["interrupt to done", this->op, "1/4 ms"] = quantize(this->delta);
	ziointr[args[0]] = 0;
}

/*
 * Print things usefully.
 */
END
{
	printf("\nRUN TIME: %d seconds\n\n", (timestamp - starttime) / 1000000000);
	printf("\n== Event counts ==");
	printf("\nAll NFS v3 ops:\n");
	printa("  %-16s   %@10d\n", @opcount);
	printf("\n\nNFS v3 read/write/commit; fast is <1/4 msec, assumed to hit cache:\n");
	printa("  %-16s   %@10d\n",@count);
	printf("\n\nZFS/ZIO counts:\n");
	printa("  %-16s   %@10d\n", @zcount); printf("\n");
	printa("  %-16s   %@10d\n", @ziocount);

	printf("\n\n== Averages and other stats ==\n\n");
	printa("  %-30s   %@10d %s\n", @avg); printf("\n");
	printa("  %-30s   %@10d %s\n", @max); printf("\n");
	printa("  %-20s %9s   %@10d\n", @opavg); printf("\n");
	printa("  %-20s %9s   %@10d\n", @zavg); printf("\n");
	printa("  %-20s %9s   %@10d\n", @zmax); printf("\n");
	printa("  %-10s %19s   %@10d\n", @zioavg); printf("\n");
	printa("  %-10s %19s   %@10d\n", @ziomax);

	printf("\n\nNFS v3 read/write/commit that took >1/4 msec:");
	printa(@nfs3);

	printf("\nNFS durations for all NFS operations, all times:");
	printa(@opdist);

	printf("\nZFS high-level operations:");
	printa(@zstats);
	printf("\nZIO durations for various sorts of ZIO ops:");
	printa(@ziostats);
	printf("\nCore 'disk' delay as seen by ZIO:\n");
	printa("%s %s in %s: %@d\n", @zdelta1);

	printf("\n\n == ");
	printf("\nTime delay distributions for various things to other things:");
	printa(@delta); printf("\n");
	printa("%s %s in %s: %@d\n", @zdelta); printf("\n");

	printf("\n'Slow' intermediate ZIO counts/averages/distributions:\n");
	printf("These are for time deltas (from zio_create()) that are > 1/4 msec.\n\n");
	printa("  %-18s for %-9s           %@8d\n", @ziointercount); printf("\n");
	printa("  %-18s for %-9s   avg ms: %@8d\n", @ziointeravg); printf("\n");
	printa("%s for ZIO type %s in %s: %@d\n", @ziointerstats);
	printf("\n  This reports zio_vdev_io_start() or zio_interrupt() calls that took more\n  than 1/4 msec to go from zio_create() to the routine. Note that it's\n  routine for slow zio_vdev_io_start() to average higher than zio_interrupt().\n");

	printf("\nZIO zio_interrupt() to zio_done() time delay:\n");
	printa("%s for %s in %s: %@d\n", @zdelta2);
	printf("\n\n ---- \n");
}

END
/ verbose >= 2 /
{
	printa(@stack);
}
