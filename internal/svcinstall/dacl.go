package svcinstall

// ServiceSDDL is the protected service DACL (design: self-protection item 2).
// SYSTEM has every service right; administrators (BA), interactive, service and
// batch logons (IU, SU, BU) have an explicit deny of change-config (DC), stop
// (WP), pause (DT) and delete (SD) ahead of an allow to query (CC, LC) and
// start (RP); administrators also keep WRITE_DAC, which is the break-glass path
// (`sc sdset`) that must stay open or a hardened service could not be removed. The SACL audits failed and successful access by everyone,
// which the winevt module turns into the `sc sdset` alert. SYSTEM owns the
// object and so needs no explicit WRITE_DAC.
//
// The deny omits LC (query status) and RP (start) on purpose: the design says
// the groups may query and start and may not stop, reconfigure, pause or
// delete.
const ServiceSDDL = "D:(A;;CCDCLCSWRPWPDTLOCRRC;;;SY)" +
	"(D;;DCWPDTSD;;;BA)(D;;DCWPDTSD;;;IU)(D;;DCWPDTSD;;;SU)(D;;DCWPDTSD;;;BU)" +
	"(A;;CCLCSWRPLOCRRCWD;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)" +
	"(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;BU)" +
	"S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

// defaultServiceSDDL is what the SCM creates for a service: SYSTEM and
// administrators full control. Uninstall restores it first (the same
// break-glass an elevated console uses with `sc sdset`).
const defaultServiceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
	"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
	"(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
