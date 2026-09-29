# Manual audit checklist

Timed from `show running-config` until every box is ticked.

- [ ] CS-01 SSH version 2 only. Compliant looks like: `ip ssh version 2`
- [ ] CS-02 VTY lines accept SSH only. Compliant looks like: `line vty 0 15 / transport input ssh`
- [ ] CS-03 VTY idle timeout of 10 minutes or less. Compliant looks like: `line vty 0 15 / exec-timeout 10 0`
- [ ] CS-04 Console idle timeout of 10 minutes or less. Compliant looks like: `line con 0 / exec-timeout 10 0`
- [ ] CS-05 VTY access limited by an ACL. Compliant looks like: `line vty 0 15 / access-class MGMT-SSH in`
- [ ] CS-06 Enable secret set, no enable password. Compliant looks like: `enable secret <strong-password> / no enable password`
- [ ] CS-07 Password encryption service on. Compliant looks like: `service password-encryption`
- [ ] CS-08 Local users stored as secrets. Compliant looks like: `username <name> secret <strong-password>`
- [ ] CS-09 No default SNMP community names. Compliant looks like: `no snmp-server community public / no snmp-server community private`
- [ ] CS-10 No read-write SNMP communities. Compliant looks like: `no snmp-server community <name> RW`
- [ ] CS-11 AAA new-model enabled. Compliant looks like: `aaa new-model`
- [ ] CS-12 SSH login timeout of 60 seconds or less. Compliant looks like: `ip ssh time-out 60`
- [ ] CS-13 Logs sent to a remote syslog server. Compliant looks like: `logging host <syslog-server-ip>`
- [ ] CS-14 Debug messages carry timestamps. Compliant looks like: `service timestamps debug datetime msec show-timezone`
- [ ] CS-15 Login warning banner set. Compliant looks like: `banner login ^CAuthorized access only. Activity is logged.^C`
