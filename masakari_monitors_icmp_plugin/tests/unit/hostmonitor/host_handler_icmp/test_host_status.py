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

"""
Unit Test for HostStatus
"""

import testtools

from masakari_monitors_icmp_plugin.hostmonitor.host_handler_icmp.host_status \
    import HostsStatus
from masakari_monitors_icmp_plugin.tests.unit.fakes import FakeHost


class TestHostStatus(testtools.TestCase):
    def test_set_host_status(self):
        host_status = HostsStatus()
        host = FakeHost(name="fake_host")
        host_status.set_host_status(host, "ONLINE")

        assert host_status.hosts_status[host.name] == "ONLINE"

    def test_get_host_status(self):
        host_status = HostsStatus()
        host = FakeHost(name="fake_host")
        host_status.set_host_status(host, "ONLINE")

        assert host_status.get_host_status(host) == "ONLINE"
