=============================
masakari-monitors-icmp-plugin
=============================

masakari hostmonitor plugin using icmp to detective host.

As we knonw masakri-monitor monitor host is used Pacemaker as it backend by default.
Pacemaker are very nice production for cluster resource management, but for
monitor openstack cluster is not. openstack cluster usually have multiple network,
and two more network have to monitor.

masakari-monitors-icmp-plugin could provides an ablity that monitor multiple network,
even "TWO LEVEL CHECK" - SSH to another host check target host is realy failed or not.
(Why need "TWO LEVEL CHECK": may be just network unstable from masakari-monitor to that host).


* Free software: Apache license
