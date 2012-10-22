#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option defaultargs
/*
 * Report details on long iSCSI operations.
 *
 * usage: iscsi-long.d [slow-msecs]
 *
*/

/*
 * CDDB command byte values I have seen:
 *	 0	0x00	TEST_UNIT_READY
 *	 8	0x08	READ
 *	26	0x1a	MODE_SENSE
 *	37	0x25	READ_CAPACITY
 *	40	0x28	READ_G1
 *	42	0x2a	WRITE_G1
 *     160	0xa0	REPORT_LUNS
 */

/* For CSLab, the first 18 characters of the iSCSI target name are
 * constant so we omit them. Change this as appropriate for your
 * environment.
 */
inline int TGTNAME_OFFSET = 18;

BEGIN
{
	starttime = timestamp;
	/* The default delay time is 500 msec */
	delaytime = $1 > 0 ? $1 * 1000000 : 500 * 1000000;
}

/*
 * State E1 is the initial creation of the iSCSI request.
 * State E2 is request transmitted.
 * State E3 is completion from the network.
 * State E8 is full completion of SCSI commands.
 * States E4 and E6 are various sorts of errors. We don't see them in normal
 * operation; I'm including them just in case.
 */

sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E1"/
{
	started[arg0] = timestamp;
}

sdt::iscsi_cmd_state_machine:event
/(string) arg2 == "E3" && started[arg0] && (timestamp - started[arg0]) > delaytime /
{
	this->icmdp = (iscsi_cmd_t *) arg0;
	this->lun = this->icmdp->cmd_lun;

	/* This is a sleazy hack, but for us the first 18 characters
	   of the target name are always constant. */
	this->tgtname = (string) (this->lun->lun_sess->sess_name+TGTNAME_OFFSET);

	this->delta = (timestamp - started[arg0])/1000000;
	/* See uts/common/sys/scsi/impl/commands.h; we want group 1, 2 format.
	   also io/scsi/targets/sd.c */
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

	printf("%Y LONG ISCSI %4d ms %s/%d @ %s CDDB cmd %2d clen %d slen %d data trans %6d lba %d count %d\n",
		walltimestamp, this->delta,
		this->tgtname, this->lun->lun_num, this->address,
		this->cmdb, this->icmdp->cmd_un.scsi.cmdlen,
		this->icmdp->cmd_un.scsi.statuslen,
		this->icmdp->cmd_un.scsi.data_transferred,
		this->lba, this->count);
}
