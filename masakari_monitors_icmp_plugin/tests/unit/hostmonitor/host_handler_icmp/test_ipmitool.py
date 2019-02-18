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

import sys
"""
Unit Test for IpmiTool
"""

import mock
import testtools
import yaml

from oslo_concurrency.processutils import ProcessExecutionError

from masakari_monitors_icmp_plugin.exceptions import HostUnavailableException
from masakari_monitors_icmp_plugin.hostmonitor.host_handler_icmp \
    import ipmitool
from masakari_monitors_icmp_plugin.tests.unit import fakes

hosts = [fakes.FakeHost(name="fake_host1"),
         fakes.FakeHost(name="fake_host2"),
         fakes.FakeHost(name="fake_host3")]

ipmi_file_valid = """---
hosts:
  fake_host1:
    ipmi_addr: 192.168.1.1
    ipmi_username: fake
    ipmi_password: fake
  fake_host2:
    ipmi_addr: 192.168.1.2
    ipmi_username: fake
    ipmi_password: fake
  fake_host3:
    ipmi_addr: 192.168.1.3
    ipmi_username: fake
    ipmi_password: fake
"""

ipmi_file_invalid = """---
hosts:
  fake_host1:
    ipmi_addr: 192.168.1.1
    ipmi_username: fake
    ipmi_password:
  fake_host2:
    ipmi_addr: 192.168.1.2
    ipmi_username:
    ipmi_password: fake
  fake_host3:
    ipmi_addr:
    ipmi_username: fake
    ipmi_password: fake
"""

if sys.version_info.major == 2:
    builtin = '__builtin__'
else:
    builtin = 'builtins'


@mock.patch.object(ipmitool.IpmiTool, '__init__', lambda x, host: None)
class TestIpmiTool(testtools.TestCase):
    @mock.patch.object(ipmitool, 'os')
    @mock.patch.object(ipmitool, 'CONF')
    def test_load_ipmi_info(self,
                            mock_conf,
                            mock_os):
        ipmi = ipmitool.IpmiTool(hosts)
        mock_conf.host_icmp.ipmi_info_file = "ipmi.yml"
        mock_os.path.exists.return_value = True

        with mock.patch('%s.open' % builtin, new_callable=mock.mock_open,
                        read_data=ipmi_file_valid) as mock_file:
            ipmi._load_ipmi_info()

        mock_file.assert_called_with('ipmi.yml')

    @mock.patch.object(ipmitool, 'os')
    @mock.patch.object(ipmitool, 'CONF')
    def test_load_ipmi_info_ipmi_file_not_configured(self,
                                                     mock_conf,
                                                     mock_os):

        ipmi = ipmitool.IpmiTool(hosts)
        mock_conf.host_icmp.ipmi_info_file = ""

        self.assertRaises(ValueError, ipmi._load_ipmi_info)

    @mock.patch.object(ipmitool, 'os')
    @mock.patch.object(ipmitool, 'CONF')
    def test_load_ipmi_info_ipmi_file_not_exist(self,
                                                mock_conf,
                                                mock_os):

        ipmi = ipmitool.IpmiTool(hosts)
        mock_conf.host_icmp.ipmi_info_file = "ipmi.yml"
        mock_os.path.exists.return_value = False

        self.assertRaises(IOError, ipmi._load_ipmi_info)

    @mock.patch.object(ipmitool, 'os')
    @mock.patch.object(ipmitool, 'CONF')
    def test_load_ipmi_info_invalid_yaml(self,
                                         mock_conf,
                                         mock_os):
        ipmi = ipmitool.IpmiTool(hosts)
        mock_conf.host_icmp.ipmi_info_file = "ipmi.yml"
        mock_os.path.exists.return_value = True

        with mock.patch('%s.open' % builtin, new_callable=mock.mock_open,
                        read_data="---") as mock_file:
            with self.assertRaisesRegexp(ValueError,
                                         "Could not load info from %s"
                                         % "ipmi.yml"):
                ipmi._load_ipmi_info()
        mock_file.assert_called_with('ipmi.yml')

    @mock.patch.object(ipmitool, 'os')
    @mock.patch.object(ipmitool, 'CONF')
    def test_load_ipmi_info_hosts_not_defined(self,
                                              mock_conf,
                                              mock_os):
        ipmi = ipmitool.IpmiTool(hosts)
        mock_conf.host_icmp.ipmi_info_file = "ipmi.yml"
        mock_os.path.exists.return_value = True

        with mock.patch('%s.open' % builtin, new_callable=mock.mock_open,
                        read_data='{host: {}}') as mock_file:
            with self.assertRaisesRegexp(ValueError,
                                         "Could not find any "
                                         "host info in IPMI File"):
                ipmi._load_ipmi_info()
        mock_file.assert_called_with('ipmi.yml')

    def test_valid_format(self):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')

        ipmi._valid_format()

    def test_valid_format_incorrect_format(self):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_invalid).get('hosts')

        self.assertRaises(ValueError, ipmi._valid_format)

    def test_get_host_ipmi(self):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')
        host = hosts[0]

        addr, user, passwd = ipmi.get_host_ipmi(host)
        assert addr == '192.168.1.1'
        assert user == 'fake'
        assert passwd == 'fake'

    @mock.patch.object(ipmitool, 'utils')
    def test_check_ipmi_connection(self, mock_utils):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')
        host_1command = ('ipmitool -I lanplus -H %s -U %s -P %s '
                         'power status' % ('192.168.1.1', 'fake', 'fake')
                         ).split(' ')
        host_2command = ('ipmitool -I lanplus -H %s -U %s -P %s '
                         'power status' % ('192.168.1.2', 'fake', 'fake')
                         ).split(' ')
        host_3command = ('ipmitool -I lanplus -H %s -U %s -P %s '
                         'power status' % ('192.168.1.3', 'fake', 'fake')
                         ).split(' ')
        calls = [mock.call(*host_1command), mock.call(
            * host_2command), mock.call(*host_3command)]

        ipmi._check_ipmi_connection(hosts)

        mock_utils.execute.assert_has_calls(calls)

    @mock.patch.object(ipmitool, 'utils')
    def test_check_ipmi_connection_ipmitool_not_install(self, mock_utils):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')
        mock_utils.execute.side_effect = OSError

        self.assertRaises(OSError, ipmi._check_ipmi_connection, hosts)

    @mock.patch.object(ipmitool, 'utils')
    def test_check_ipmi_connection_ipmi_network_unreachable(self, mock_utils):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')
        mock_utils.execute.side_effect = ProcessExecutionError

        self.assertRaises(ProcessExecutionError,
                          ipmi._check_ipmi_connection, hosts)

    @mock.patch.object(ipmitool, 'time')
    @mock.patch.object(ipmitool, 'utils')
    @mock.patch.object(ipmitool, 'eventlet')
    @mock.patch.object(ipmitool, 'CONF')
    def test_power_off(self, mock_conf, mock_eventlet, mock_utils, mock_time):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')
        mock_utils.execute.return_value = ('power is off', '')
        host = hosts[0]
        power_status = ('ipmitool -I lanplus -H %s -U %s -P %s '
                        'power status' % ('192.168.1.1', 'fake', 'fake')
                        ).split(' ')
        power_off = ('ipmitool -I lanplus -H %s -U %s -P %s power off' % (
            '192.168.1.1', 'fake', 'fake')).split(' ')
        calls = [mock.call(*power_off), mock.call(*power_status)]

        ipmi.power_off(host)
        mock_utils.execute.assert_has_calls(calls)

    @mock.patch.object(ipmitool, 'time')
    @mock.patch.object(ipmitool, 'utils')
    @mock.patch.object(ipmitool, 'eventlet')
    @mock.patch.object(ipmitool, 'CONF')
    def test_power_off_timeout(self,
                               mock_conf, mock_eventlet,
                               mock_utils, mock_time):
        ipmi = ipmitool.IpmiTool(hosts)
        ipmi.ipmi_info = yaml.safe_load(ipmi_file_valid).get('hosts')
        mock_conf.host_icmp.ipmi_poweroff_wait = 30
        mock_conf.host.ipmi_retry_interval = 0
        mock_utils.execute.return_value = ('power is on', '')
        time = mock.MagicMock()
        time.__sub__.return_value = 100
        mock_time.time.return_value = time
        host = hosts[0]
        power_status = ('ipmitool -I lanplus -H %s -U %s -P %s '
                        'power status' % ('192.168.1.1', 'fake', 'fake')
                        ).split(' ')
        power_off = ('ipmitool -I lanplus -H %s -U %s -P %s power off' % (
            '192.168.1.1', 'fake', 'fake')).split(' ')
        calls = [mock.call(*power_off), mock.call(*power_status)]

        self.assertRaises(HostUnavailableException, ipmi.power_off, host)
        mock_utils.execute.assert_has_calls(calls)
