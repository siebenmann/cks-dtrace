#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option defaultargs
#pragma D option dynvarsize=64m

/*
 * Give a traffic overview for an NFS fileserver every ten seconds.
 * Specialized to CSLab's environment.
 *
 * usage: nfs3-mon.d [verbosity]
 *
 * verbosity 1 adds some extra activity breakdowns.
 *
 * Information on what gets reported:
 * - writes are broken down into different categories depending on the
 *   NFS v3 'stable' setting. These are plain writes (no stability
 *   required), 'write (data sync)' aka DATA_SYNC, and 'write (file
 *   sync)' aka FILE_SYNC.
 *
 * The 'currently outstanding' information is an instantaneous snapshot.
 * All other information is aggregated over ten seconds. Note that size
 * are *not* MB/second, they are total MBs; divide by ten to get a per-second
 * figure.
 *
 * Written by Chris Siebenmann
 * https://github.com/siebenmann/cks-dtrace/
 */

BEGIN
{
	/* BRUTE FORCE TRIUMPHS */
	names["128.100.3.90"] = "aviary";
	names["128.100.3.96"] = "dcsimap";
	names["128.100.3.40"] = "apps0";
	names["128.100.3.41"] = "apps1";
	names["128.100.3.42"] = "apps2";
	names["128.100.3.43"] = "apps3";
	names["128.100.3.37"] = "oldapps";
	names["128.100.3.83"] = "dcssmb-3";
	names["128.100.3.84"] = "smb-3";
	names["128.100.3.30"] = "colony";
	names["128.100.1.10"] = "settlement";
	names["128.100.3.218"] = "arsenal";
	names["128.100.3.124"] = "mailswitch";

	names["128.100.3.150"] = "comps0";
	names["128.100.3.151"] = "comps1";
	names["128.100.3.152"] = "comps2";
	names["128.100.3.153"] = "comps3";
	names["128.100.3.154"] = "comps4";

	/* this is the stable_how enum */
	wtypes[0] = "writes";			/* UNSTABLE */
	wtypes[1] = "writes (data sync)";	/* DATA_SYNC */
	wtypes[2] = "writes (file sync)";	/* FILE_SYNC */

	verbose = $1;
	topn = verbose > 0 ? 5: 3;
	vnl = verbose ? "\n" : "";
	ztype = `zfsfstype;
}

fbt::rfs3_read:entry
{
	self->dir = "reads";
}

fbt::rfs3_write:entry
{
	self->dir = wtypes[args[0]->stable];
}

fbt::rfs3_commit:entry
{
	self->dir = "commits";
}

fbt::rfs3_read:entry, fbt::rfs3_write:entry, fbt::rfs3_commit:entry
{
	self->in_rfs3 = 1;
	self->count = args[0]->count;
	self->req = args[3];
	self->uid = args[4]->cr_uid;
	self->fs = (string)args[2]->exi_export.ex_path;
	self->ts = timestamp;

	this->socket =
	    (struct sockaddr_in *)self->req->rq_xprt->xp_xpc.xpc_rtaddr.buf;
	/* DTrace 1.0: no inet functions, no this->strings */
	this->a = (uint8_t *)&this->socket->sin_addr.S_un.S_addr;
	this->addr1 = strjoin(lltostr(this->a[0] + 0ULL), strjoin(".",
	    strjoin(lltostr(this->a[1] + 0ULL), ".")));
	this->addr2 = strjoin(lltostr(this->a[2] + 0ULL), strjoin(".",
	    lltostr(this->a[3] + 0ULL)));
	self->address = strjoin(this->addr1, this->addr2);
	self->address = names[self->address] != 0 ? names[self->address] : self->address;

	@curops = sum(1);
	@opsc[self->dir] = sum(1);
}

/*
 * nfs3_fhtovp can fail, eg on a stale filehandle, and in
 * that case we can't go digging for the pool et al.
 */
fbt::nfs3_fhtovp:return
/self->in_rfs3 && args[1]/
{
	self->vp = args[1];

	/* Ugly simplification */
	this->fst = self->vp->v_vfsp->vfs_fstype;
	this->znode = (znode_t *)self->vp->v_data;
	self->pool = this->fst == ztype ? 
		stringof(this->znode->z_zfsvfs->z_os->os->os_spa->spa_name) :
		strjoin("non-ZFS fstype ", stringof(`vfssw[this->fst].vsw_name));

	/* guard against repeated calls to nfs3_fhtovp() just in case. */
	self->in_rfs3 = 0;
}

/*
 * We can only trace requests where nfs3_fhtovp() succeeded.
 * Such requests have a timestamp but had in_rfs3 turned off
 * above.
 */
fbt::rfs3_read:return, fbt::rfs3_write:return, fbt::rfs3_commit:return
/ self->ts > 0 && !self->in_rfs3 / 
{
	@fsuser[self->fs, self->uid] = sum(self->count);
	@fsclient[self->fs, self->address] = sum(self->count);
	@fs[self->fs] = sum(self->count);
	@user[self->uid] = sum(self->count);
	@client[self->address] = sum(self->count);
	@matrix[self->fs, self->uid, self->address] = sum(self->count);
	@dir[self->dir] = sum(self->count);
	@counts[self->dir] = count();
	@pools[self->pool] = sum(self->count);
}

/*
 * We must count and clear out *all* ops, even the ones where invalid
 * filehandles happened.
 */
fbt::rfs3_read:return, fbt::rfs3_write:return, fbt::rfs3_commit:return
/ self->ts > 0 / 
{
	@curops = sum(-1);
	@opsc[self->dir] = sum(-1);

	self->in_rfs3 = 0;
	self->count = 0;
	self->req = 0;
	self->uid = 0;
	self->dir = 0;
	self->ts = 0;
	self->pool = 0;
	self->address = 0;
}

/* quick hack. this really belongs in a ZFS stats DTrace script */
fbt::zil_lwb_write_start:entry
{
	this->syncpool = (string) args[0]->zl_dmu_pool->dp_spa->spa_name;
	/* @zilsync[this->syncpool] = count(); */
}

tick-10sec
/ verbose == 0 /
{
	trunc(@fsuser, 0);
	trunc(@fsclient, 0);
	trunc(@user, 0);
	trunc(@fs, 0);
}

tick-10sec
{	
	printf("\n%Y (10 second totals):\n", walltimestamp);
	trunc(@fsuser, topn); 	normalize(@fsuser, (1024*1024));
	trunc(@fsclient, topn);	normalize(@fsclient, (1024*1024));
	trunc(@fs, topn);	normalize(@fs, (1024*1024));
	trunc(@user, topn);	normalize(@user, (1024*1024));
	trunc(@client, topn);	normalize(@client, (1024*1024));
	trunc(@matrix, 5);	normalize(@matrix, (1024*1024));
	trunc(@pools, topn);	normalize(@pools, (1024*1024));
				normalize(@dir, (1024*1024));

	printa("currently outstanding: %@d NFS request(s)\n   ", @curops);
	printa(" %@d %s", @opsc); printf("\n\n");

	printa(" %@5d MB in %@4d %s\n", @dir, @counts); printf("\n");

	printa("%@6d MB   %-8s uid %5d on %-s\n", @matrix); printf("\n");
	printa("%@6d MB   %s\n", @pools); printf("\n");
	printa("%@6d MB   %-8s uid %5d\n", @fsuser); printf("%s", vnl);
	printa("%@6d MB   %-8s from %-15s\n", @fsclient); printf("%s", vnl);
	printa("%@6d MB   %s\n", @fs); printf("%s", vnl);
	printa("%@6d MB   %s\n", @client); printf("\n");
	printa("%@6d MB   uid %5d\n", @user); printf("%s", vnl);

	/* trunc(@zilsync, topn);
	printa("%@6d ZIL writes in %s\n", @zilsync); printf("\n"); */
}

/*
 * We truncate everything at END so that it isn't printed out one last
 * time (badly).
 */
tick-10sec, END
{
	/* trunc(@zilsync); */

	trunc(@fsuser);
	trunc(@fsclient);
	trunc(@fs);
	trunc(@user);
	trunc(@client);
	trunc(@matrix);
	trunc(@dir);
	trunc(@counts);
	trunc(@pools);
}
