#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option defaultargs
#pragma D option dynvarsize=64m

/*
 * Report long NFS read/write/commit operations.
 *
 * usage: nfs3-long.d [verbosity [delay]]
 *
 * verbosity 1 shows filenames when available.
 * verbosity 2 also shows currently active request counts on a per-pool
 *	basis.
 * delay is in milliseconds and defaults to 500 msec.
 *
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
	wtypes[0] = "write";			/* UNSTABLE */
						/* (the default/normal) */
	wtypes[1] = "write.data_sync";		/* DATA_SYNC */
	wtypes[2] = "write.file_sync";		/* FILE_SYNC */

	delaytime = $2 > 0 ? $2 * 1000000 : 500 * 1000000;
	verbose = $1;
}

fbt::rfs3_read:entry
{
	self->dir = "read";
}

fbt::rfs3_write:entry
{
	self->dir = wtypes[args[0]->stable];
}

fbt::rfs3_commit:entry
{
	self->dir = "commit";
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
}

fbt::nfs3_fhtovp:return
/self->in_rfs3 && args[1]/
{
	self->vp = args[1];
	self->path = self->vp->v_path ? (string) self->vp->v_path : "";

	/* Ugly simplification that assumes all FSes are ZFS fses */
	self->znode = (znode_t *)self->vp->v_data;
	self->inum = self->znode->z_id + 0ULL;
	self->pool = (string) self->znode->z_zfsvfs->z_os->os->os_spa->spa_name;
	self->itxg = self->znode->z_zfsvfs->z_os->os->os_spa->spa_dsl_pool->dp_tx.tx_open_txg;
	/* make sure this is always set */
	pooltxg[self->pool] = self->itxg;

	@poolc[self->pool] = sum(1);

	/* guard against repeated calls to nfs3_fhtovp() just in case. */
	/* also signals that this was a valid filehandle */
	self->in_rfs3 = 0;
}

fbt::txg_quiesce:entry
{
	/* This is the (open) pool txg that will exist after we return. */
	/* This matches how we get the pooltxg above */
	pooltxg[args[0]->dp_spa->spa_name] = args[0]->dp_tx.tx_open_txg + 1;
}

fbt::rfs3_read:return, fbt::rfs3_write:return, fbt::rfs3_commit:return
/ self->ts > 0 && (timestamp - self->ts) > delaytime/ 
{
	this->delta = (timestamp - self->ts) / 1000000;
	this->kb = self->count / 1024;
	this->path = strjoin(" file ", self->path);
	this->istr = self->inum ? strjoin(" inum ", lltostr(self->inum)) : "";

	/* We would like to directly dereference the znode, but it may not
	   exist any more by the time we reach this routine. So we must get
	   the current pool txg through a hack. */
	this->ctxg = pooltxg[self->pool];
	this->tstr = this->ctxg != self->itxg ?
		strjoin(" txg +", lltostr(this->ctxg-self->itxg)) : "";

	printf("%Y LONG NFS %5d msec %d %s %s on %s %s for uid %d from %s%s%s%s\n",
		walltimestamp, this->delta,
		this->kb ? this->kb : self->count, this->kb ? "Kb" : "bytes",
		self->dir, self->fs, self->pool, self->uid, self->address, 
		this->istr, this->tstr, 
		verbose && self->path != "" ? this->path : "");
}

/* This is unfortunately very verbose. I wish we could somehow get DTrace
   to exclude keys with zeros, or let us retrieve only a specific keyed
   aggregate. */
fbt::rfs3_read:return, fbt::rfs3_write:return, fbt::rfs3_commit:return
/ verbose >= 2 && self->ts > 0 && (timestamp - self->ts) > delaytime/ 
{
	/* Turns out I don't want a timestamp on this after all */
	printf("   ACTIVE NFS reqs: ");
	printa(" %@d %s", @poolc); printf("\n");
}

fbt::rfs3_read:return, fbt::rfs3_write:return, fbt::rfs3_commit:return
/ self->ts > 0 && !self->in_rfs3 / 
{
	@poolc[self->pool] = sum(-1);
}

fbt::rfs3_read:return, fbt::rfs3_write:return, fbt::rfs3_commit:return
/ self->ts > 0 / 
{
	self->in_rfs3 = 0;
	self->count = 0;
	self->req = 0;
	self->uid = 0;
	self->dir = 0;
	self->ts = 0;
	self->vp = 0;
	self->path = 0;
	self->znode = 0;
	self->inum = 0;
	self->pool = 0;
	self->itxg = 0;
}

/* Keep us from dumping the pool active counts. */
END
{
	trunc(@poolc);
}
