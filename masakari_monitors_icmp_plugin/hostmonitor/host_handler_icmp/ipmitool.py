# Copyright(c) 2019 Unitedstack Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import eventlet
import os
import time
import yaml

from masakarimonitors import utils
from oslo_concurrency.processutils import ProcessExecutionError
from oslo_log import log as oslo_logging

import masakari_monitors_icmp_plugin.conf
from masakari_monitors_icmp_plugin.exceptions import HostUnavailableException
from masakari_monitors_icmp_plugin.utils import retry

LOG = oslo_logging.getLogger(__name__)
CONF = masakari_monitors_icmp_plugin.conf.CONF

ADDR = 'ipmi_addr'
USER = 'ipmi_username'
PASSWD = 'ipmi_password'


class IpmiTool(object):
    """Store IPMI addr, username, password for segment hosts."""

    def __init__(self, hosts):
        self._load_ipmi_info()
        self._valid_format()
        self._check_ipmi_connection(hosts)

    def _load_ipmi_info(self):
        LOG.info("load ipmi info")
        if CONF.host_icmp.ipmi_info_file == "":
            LOG.error("You have to define ipmi_info_file")
            raise ValueError("You have to define ipmi_info_file")

        self.ipmi_file = CONF.host_icmp.ipmi_info_file
        if not os.path.exists(self.ipmi_file):
            LOG.error("IPMI info file %s not exists", self.ipmi_file)
            raise IOError(
                "IPMI info file %s not exists", self.ipmi_file)

        with open(self.ipmi_file) as f:
            data = yaml.safe_load(f)
            if not data:
                LOG.error("Could not load info from %s" % self.ipmi_file)
                raise ValueError("Could not load info from %s" %
                                 self.ipmi_file)

            self.ipmi_info = data.get('hosts')
            if not self.ipmi_info:
                LOG.error("Could not find any host info in IPMI File")
                raise ValueError("Could not find any host info in IPMI File")

    def _valid_format(self):
        for host in self.ipmi_info.values():
            if (host.get(ADDR) is None or host.get(USER) is None
                    or host.get(PASSWD) is None):
                raise ValueError("""
IPMI file Format is incorrect.
Correct format is:
---
hosts:
  <hostname>:
    ipmi_addr: <ip address>
    ipmi_username: <username>
    ipmi_password: <password>
""")

    def get_host_ipmi(self, host):
        info = self.ipmi_info.get(host.name)
        if info:
            return (info.get(ADDR),
                    info.get(USER),
                    info.get(PASSWD))

    def _check_ipmi_connection(self, hosts):
        for host in hosts:
            addr, user, passwd = self.get_host_ipmi(host)
            command = ('ipmitool -I lanplus -H %s -U %s -P %s '
                       'power status' % (addr, user, passwd)).split(' ')
            try:
                LOG.info("connecting to Host %s ipmi addr %s" % (host, addr))
                utils.execute(*command)
            except OSError:
                LOG.error("ipmitool must installed on system")
                raise
            except ProcessExecutionError:
                LOG.error("ipmitool connecting error. Host %s" % addr)
                raise

    @retry(max_retry=CONF.host.ipmi_retry_max,
           retry_interval=CONF.host.ipmi_retry_interval)
    def power_off(self, host):
        addr, user, passwd = self.get_host_ipmi(host)
        power_status = ('ipmitool -I lanplus -H %s -U %s -P %s '
                        'power status' % (addr, user, passwd)).split(' ')
        power_off = ('ipmitool -I lanplus -H %s -U %s -P %s power off' % (
            addr, user, passwd)).split(' ')

        utils.execute(*power_off)
        wait = CONF.host_icmp.ipmi_poweroff_wait
        start = time.time()
        while True:
            out, err = utils.execute(*power_status)
            if 'power is off' in out:
                return
            if (time.time() - start) > wait:
                raise HostUnavailableException("Host %s Poweroff timeout."
                                               % host.name)
            else:
                eventlet.greenthread.sleep(1)
