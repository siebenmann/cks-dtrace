#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option dynvarsize=64m
/* 
 * Report on read/write activity by a process on all FDs, by fd.
 * Reports are produced every ten seconds, with per-one-second figures.
 * Right now it reports only on read()/readv()/write()/writev().
 * A synthetic 'FD 999' is used to report aggregate read and write
 * activity.
 *
 * usage: ./fdrwmon.d -p PID
 * using multiple -p PID arguments will produce odd results.
 *
 * output:
 *	<T> fd  NN<D>: NNN MB/s  waiting ms: NNN / 1000   ( NN KB avg * NNN)
 *          fd 999<D>: .....
 *      ....
 *      IO waits: write: NNN ms   read: NNN ms  total: NNN ms
 *
 * <D> is 'r' or 'w' for read or write. A FD with both activities will
 * have two lines, one for each.
 * The MB/s is the achieved bandwidth. 'waiting ms' is how many milliseconds
 * the process spent waiting for read/write IO on that FD (on a per-second
 * average basis). The 'NN KB avg' is the average IO size over the ten
 * second tick; the '* NNN' bit is how many (average) calls/sec there were.
 * The <T> is a single character that describes the type of the fd/file,
 * as follows:
 *
 *	f: file, d: directory, p: pipe (FIFO), s: socket,
 *	B: block device, C: char device,
 *	L: symlink, D: OmniOS door, P: 'VPROC' /proc file?,
 *	O: OmniOS event port, B: bad, ?: bad magic
 *
 * un-capitalized types are the usual cases (so they aren't yelling at
 * you).
 *
 * FD 999 is synthetic; it is the totals for read and write over all FDs.
 * 'IO waits' summarizes the total IO waits (split into reads, writes, and
 * the sum). The order of write and read on the line varies but total will
 * normally always be last.
 *
 * Only FDs with activity are reported on. The numbers are rounded, so a
 * low activity FD can show 0's after rounding and conversion to
 * per-second figures.
 *
 * Written by Chris Siebenmann
 * https://github.com/siebenmann/cks-dtrace/
*/

/* 
 * On Solaris 10 update 8, there is no getf(). We/you need to use:
 *	curthread->t_procp->p_user.u_finfo.fi_list[self->fd].uf_file 
 *
 * This is taken from
 *   https://blogs.oracle.com/mws/entry/dtrace_inlines_translators_and_file
*/

BEGIN
{
	/* this is kind of a sleazy trick to get things to sort right. */
	dirmap["read"] = 998; 
	dirmap["readv"] = 998;
	dirmap["write"] = 999;
	dirmap["writev"] = 999;

	/* see sys/vnode.h */
	vtype[0] = "?";
	vtype[1] = "f";
	vtype[2] = "d";
	vtype[3] = "B";
	vtype[4] = "C";
	vtype[5] = "L";		/* VLNK */
	vtype[6] = "p";		/* VFIFO aka pipe */
	vtype[7] = "D";		/* VDOOR */
	vtype[8] = "P";		/* VPROC */
	vtype[9] = "s";		/* socket */
	vtype[10] = "O";	/* VPORT ?? */
	vtype[11] = "X";	/* bad */
}

syscall::read:entry, syscall::write:entry, syscall::writev:entry, syscall::readv:entry
/ pid == $target /
{
	self->ts = timestamp;
	self->fd = arg0;
}

syscall::read:return, syscall::write:return, syscall::writev:return, syscall::readv:return
/ self->ts > 0 && arg0 > 0 /
{
	this->dir = (probefunc == "read" || probefunc == "readv") ? "r" : "w";
	this->dirfd = dirmap[probefunc];

	this->fi = getf(self->fd);
	this->vn = vtype[this->fi->f_vnode->v_type];

	@fds[this->vn,this->dir,self->fd] = avg(self->fd * 10000 + this->dirfd);
	@fdact[this->vn,this->dir,self->fd] = count();
	@fdvol[this->vn,this->dir,self->fd] = sum(arg0);
	/* this->deltams = (timestamp - self->ts) / 1000000; */
	/* @fdbw[self->fd] = avg(this->deltams > 0 ? arg0 / this->deltams : arg0); */
	/* active IO time in nanoseconds */
	@fdtime[this->vn,this->dir,self->fd] = sum(timestamp - self->ts);
	@fdsize[this->vn,this->dir,self->fd] = avg(arg0);

	this->deltaus = (timestamp - self->ts) / 1000;
	this->deltaus = this->deltaus > 0 ? this->deltaus : 1;
	/* @fdbw[self->fd] = avg((arg0*1000000) / this->deltaus); */

	/* this->dirfd is used for sort order only; our synthetic fd is 999.
	 * this is, frankly, an ugly trick.
	 */
	@fds[" ",this->dir,this->dirfd] = avg(999 * 10000 + this->dirfd);
	@fdact[" ",this->dir,this->dirfd] = count();
	@fdvol[" ",this->dir,this->dirfd] = sum(arg0);
	@fdtime[" ",this->dir,this->dirfd] = sum(timestamp - self->ts);
	@fdsize[" ",this->dir,this->dirfd] = avg(arg0);
	/* @fdbw[this->dirfd] = avg((arg0*1000000) / this->deltaus); */

	@wait[this->dir == "r" ? "read" : "write"] = sum(timestamp - self->ts);
	@wait["total"] = sum(timestamp - self->ts);

	self->ts = 0;
	self->fd = 0;
}

tick-10sec
{
	/* sleazy trick to de-sugar @fds */
	normalize(@fds, 10000);

	/* normalize from bytes-per-10-seconds to megabytes per second */
	normalize(@fdvol, (1024*1024) * 10);
	normalize(@fdact, 10);
	/* bytes-per-ms summed over 10 seconds -> mb-per-1s */
	/* normalize(@fdbw, (1024*1024) / 1000); */
	/* convert fdtime from active ns over 10 seconds to active ms per 1s */
	normalize(@fdtime, 1000000 * 10);
	normalize(@wait, 1000000 * 10);
	normalize(@fdsize, 1024);
	/* normalize(@fdbw, (1024*1024)); */
	
	printa("%s fd %@3d%s: %@4d MB/s  waiting ms: %@3d / 1000   (%@3d KB avg * %@5d)\n",
		@fds, @fdvol, @fdtime, @fdsize, @fdact);

	printf("IO waits:");
	printa(" %5s: %@3d ms ", @wait);
	printf("\n\n");

	trunc(@fdvol); trunc(@fdact);
	trunc(@fdtime); trunc(@fds); trunc(@fdsize);
	trunc(@wait);
	/* trunc(@fdbw); */
}

END
{
	trunc(@fdvol); trunc(@fdact); trunc(@fdtime); trunc(@fds);
	trunc(@fdsize);
	trunc(@wait);
	/* trunc(@fdbw); */
}
