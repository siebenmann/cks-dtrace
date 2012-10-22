#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option defaultargs
/*
 * Report on iSCSI initiator IO timings and so on.
 *
 * usage: iscsi-stats.d [verbosity]
 *
 * verbosity 1 produces per-LUN+target IP statistics as well as some
 * other attempts to track queue depth.
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

BEGIN
{
	verbose = $1;
	closedcnt = 0;
	starttime = timestamp;
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
/(string) arg2 == "E1"/
{
	/* started[arg0] = timestamp; */
	e3[arg0] = 0;
	@counts["submit (all cmd types)"] = count();
	@submit["submit cmd type", ((iscsi_cmd_t *) arg0)->cmd_type] = count();
}
sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E1"/
{
	started[arg0] = timestamp;
}

/*
sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && ((string) arg2 == "E1" || started[arg0]) /
{
	this->icmdp = (iscsi_cmd_t *) arg0;
	printf("%u delta %8u %p %d %s %s\n", timestamp, timestamp - started[arg0], arg0, this->icmdp->cmd_type, (string) arg1, (string) arg2);
}
*/

sdt::iscsi_cmd_state_machine:event
/verbose && ((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E2" && started[arg0]/
{
	this->delta = (timestamp - started[arg0])/250000;
	@trans["transmit scsi", "1/4 ms"] = quantize(this->delta); 

	this->icmdp = (iscsi_cmd_t *) arg0;
	this->sess = this->icmdp->cmd_lun->lun_sess;
	@simulcnt["outstanding connection commands"] = lquantize(this->icmdp->cmd_conn->conn_queue_active.count, -1, 33);
	@simulcnt["pending session commands"] = lquantize(this->sess->sess_queue_pending.count, -1, 33);
	@simulcnt["session window"] = lquantize(this->sess->sess_maxcmdsn - this->sess->sess_cmdsn, -1, 33);
	@simulcnt["session table count"] = lquantize(this->sess->sess_cmd_table_count, -1, 33);
	closedcnt += (this->sess->sess_maxcmdsn - this->sess->sess_cmdsn) > 0 ? 0 : 1;
}

sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E2" && started[arg0]/
{
	@counts["transmit scsi"] = count();
	trans[arg0] = timestamp;
}

sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && ((string) arg2 == "E4" || (string) arg2 == "E6") && started[arg0]/
{
	@counts2["error handling", (string) arg2] = count();
	this->delta = (timestamp - started[arg0])/1000000;
	@errors["state transition to", (string) arg2, "ms"] = quantize(this->delta);
	started[arg0] = 0;
	trans[arg0] = 0;
}

sdt::iscsi_cmd_state_machine:event
/verbose && ((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E3" && started[arg0] && trans[arg0] /
{
	this->icmdp = (iscsi_cmd_t *) arg0;
	this->delta2 = (timestamp - started[arg0])/250000;
	this->delta = (timestamp - started[arg0])/1000000;

	/* cid + oid is more useful for identifying things, I think.
	   it shows up in kstat output et al. */
	/* @lrg["completion", this->icmdp->cmd_conn->conn_cid, this->icmdp->cmd_conn->conn_oid, "1/4 ms"] = quantize(this->delta); */
	/* @lrg["completion", (string) this->icmdp->cmd_lun->lun_guid, "1/4 ms"] = quantize(this->delta); */

	this->tgtname = (string) this->icmdp->cmd_lun->lun_sess->sess_name;
	this->addr =  (u_char *) &this->icmdp->cmd_conn->conn_curr_addr.sin4.sin_addr;
	@lrg["completion for target:", this->tgtname, this->icmdp->cmd_lun->lun_num, (uint) this->addr[0], (uint) this->addr[1], (uint) this->addr[2], (uint) this->addr[3], "1/4 ms"] = quantize(this->delta2);
	@tgtavg["completion for target:", this->tgtname, this->icmdp->cmd_lun->lun_num, (uint) this->addr[0], (uint) this->addr[1], (uint) this->addr[2], (uint) this->addr[3], "avg ms"] = avg(this->delta);

	/* this->cmdb = this->icmdp->cmd_un.scsi.pkt->pkt_cdbp[0];
	// this->cdb = this->icmdp->cmd_un.scsi.pkt->pkt_cdbp;
	// this->lba = this->cdb[2] << 24 | this->cdb[3] << 16 | this->cdb[4] << 8 | this->cdb[5];
	// this->lba = this->lba / (2097152*2);
	// @lba["lba addresses quantized in 2 GB chunks", this->cmdb] = lquantize(this->lba, 0, 100);
	*/
}

sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E3" && started[arg0]/
{
	this->icmdp = (iscsi_cmd_t *) arg0;
	this->delta2 = (timestamp - started[arg0])/250000;
	this->delta = (timestamp - started[arg0])/1000000;
	@complete["completion", "ms"] = lquantize(this->delta, 0, 100, 1);
	@spread["low-res completion", "ms"] = lquantize(this->delta, 50, 1000, 50);
	@spread2["intermediate completion", "ms"] = lquantize(this->delta, 0, 200, 5);

	@counts["scsi complete"] = count();
	e3[arg0] = timestamp;
	@xavg["avg completion", "1/4 ms"] = avg(this->delta2);
	@xmin["min completion", "1/4 ms"] = min(this->delta2);
	@xmax["max completion", "ms"] = max(this->delta);

	/* 40 is SCMD_READ_G1, 42 is SCMD_WRITE_G1 */
	/* See uts/common/sys/scsi/generic/commands.h */
	this->cmdb = this->icmdp->cmd_un.scsi.pkt->pkt_cdbp[0];
	@ccount["SCSI CDDB command byte", this->cmdb] = count();
	@cmax["SCSI CDDB command byte", this->cmdb, "max ms"] = max(this->delta);
	@cavg["SCSI CDDB command byte", this->cmdb, "avg ms"] = avg(this->delta);
	@cdist["completion for CDDB command byte:", this->cmdb, "(ms)"] = quantize(this->delta);

	/* This is what really matters */
	@recvdelta["transmit to receive time", "ms"] = quantize((timestamp - trans[arg0])/1000000);
	trans[arg0] = 0;
}

sdt::iscsi_cmd_state_machine:event
/verbose && ((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E8" && started[arg0]/
{
	this->delta2 = e3[arg0] ? (timestamp - e3[arg0])/1000 : -1;
	@delta["E3 to E8 time delta", "us"] = quantize(this->delta2);
	e3[arg0] = 0;
}

sdt::iscsi_cmd_state_machine:event
/((iscsi_cmd_t *) arg0)->cmd_type == 1 && (string) arg2 == "E8" && started[arg0]/
{
	this->delta = (timestamp - started[arg0])/500000;
	/* surplus given what is generally a very close tie between E3 and E8. */
	/* @["done", "1/2 ms"] = lquantize(this->delta, 0, 200, 1); */
	@counts["scsi done"] = count();
	started[arg0] = 0;
}

END
{
	printf("\nRUN TIME: %d seconds\n\n", (timestamp - starttime) / 1000000000);
	printf("\nItem counts:\n");
	printa("%-25s   %@10d\n", @counts); printf("\n");
	printa("%s %1d:   %@10d\n", @submit); printf("\n");
	printa("%s %3d:   %@10d\n", @ccount); printf("\n");
	printf("(CDDB command byte 40 is READ_G1, 42 is WRITE_G1. 0, 8, 26, and 37 are\nunimportant)\n");

	printf("\nStats:\n");
	printa("%-20s %6s:  %@8d\n", @xavg);
	printa("%-20s %6s:  %@8d\n", @xmin);
	printa("%-20s %6s:  %@8d\n", @xmax);
	printf("\n");
	printa("%-20s %3d %s: %@4d\n", @cavg); printf("\n");
	printa("%-20s %3d %s: %@4d\n", @cmax);

	printf("\nDetail timing distribution:");
	printa(@complete);
	printa(@spread);
	printa(@spread2);
	printf("(CDDB command byte 40 is READ_G1, 42 is WRITE_G1)\n");
	printa("%s %d %s %@d\n", @cdist); printf("\n");
	printa(@recvdelta);
}

END
/verbose/
{
	printf("\nPer-target completion (split by IP)\n");
	printa("%22s %34s/%d %d.%d.%d.%d -- %s: %@4d\n", @tgtavg); printf("\n");
	printa("%s %s/%d %d.%d.%d.%d in %s: %@d\n", @lrg);

	printf("\nObscure:");
	printa(@trans);
	printa(@delta);

	printf("\nCounts of outstanding & pending commands & stuff\n");
	printf("Session window was closed: %d times\n", closedcnt);
	printa(@simulcnt);

	/* printa(@lba); */
}
