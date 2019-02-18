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

from keystoneauth1.identity.generic import password as ks_password
from keystoneauth1 import session as ks_session
import masakari_monitors_icmp_plugin.conf
from openstack import connection
from oslo_log import log as oslo_logging

from masakari_monitors_icmp_plugin.utils import retry

LOG = oslo_logging.getLogger(__name__)
CONF = masakari_monitors_icmp_plugin.conf.CONF


class Api(object):

    def _make_client(self):
        auth = ks_password.Password(
            auth_url=CONF.api.auth_url,
            username=CONF.api.username,
            password=CONF.api.password,
            user_domain_id=CONF.api.user_domain_id,
            project_name=CONF.api.project_name,
            project_domain_id=CONF.api.project_domain_id)
        session = ks_session.Session(auth=auth)
        conn = connection.Connection(session=session,
                                     interface=CONF.api.api_interface,
                                     region_name=CONF.api.region)

        return conn.instance_ha

    @retry(max_retry=CONF.host.api_retry_max,
           retry_interval=CONF.host.api_retry_interval)
    def get_segments(self):
        """Get all segments from masakari-api."""

        LOG.info("Get all segments")
        client = self._make_client()
        return [segment for segment in client.segments()]

    @retry(max_retry=CONF.host.api_retry_max,
           retry_interval=CONF.host.api_retry_interval)
    def get_hosts(self, segment):
        """Get all hosts from single segment."""

        LOG.info("Get all hosts from segment: %s", segment.name)
        client = self._make_client()
        # Maintenance host have no need of monitor
        return [host for host in client.hosts(segment.uuid)
                if not host.on_maintenance]
