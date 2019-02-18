# Copyright(c) 2019 UnitedStack Corporation
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


class HostsStatus(object):
    """Hold all hosts status"""

    def __init__(self):
        self.hosts_status = {}

    def set_host_status(self, host, status):
        self.hosts_status[host.name] = status

    def get_host_status(self, host):
        return self.hosts_status.get(host.name)
