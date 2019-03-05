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

import mock
import testtools

from keystoneauth1.identity.generic import password as ks_password
from keystoneauth1 import session as ks_session
from openstack import connection

import masakari_monitors_icmp_plugin.conf
from masakari_monitors_icmp_plugin.ha.api import Api
from masakari_monitors_icmp_plugin.tests.unit.fakes \
    import FakeHost, FakeSegment

CONF = masakari_monitors_icmp_plugin.conf.CONF
fake_hosts = [FakeHost(name='fake_host1',
                       failover_segment_id='1'),
              FakeHost(name='fake_host2',
                       failover_segment_id='1'),
              FakeHost(name='fake_host3',
                       failover_segment_id='1'),
              ]


class TestApi(testtools.TestCase):

    @mock.patch.object(connection, 'Connection')
    @mock.patch.object(ks_session, 'Session')
    @mock.patch.object(ks_password, 'Password')
    def test_make_client(self,
                         mock_password,
                         mock_session,
                         mock_connection):
        api = Api()
        auth = mock.Mock()
        session = mock.Mock()
        mock_password.return_value = auth
        mock_session.return_value = session

        api._make_client()
        mock_password.assert_called_once()
        mock_session.assert_called_once_with(auth=auth)
        mock_connection.assert_called_once_with(
            session=session,
            interface=CONF.api.api_interface,
            region_name=CONF.api.region)

    @mock.patch.object(Api, '_make_client')
    def test_get_segments(self, mock_client):
        api = Api()
        segments = [FakeSegment(name='fake')]
        client = mock.Mock()
        client.segments.return_value = segments
        mock_client.return_value = client

        ret = api.get_segments()
        self.assertEqual(segments, ret)
        client.segments.assert_called_once()

    @mock.patch.object(Api, '_make_client')
    def test_get_hosts(self, mock_client):
        api = Api()
        client = mock.Mock()
        mock_client.return_value = client
        hosts = fake_hosts[:]
        client.hosts.return_value = hosts
        expected_hosts = hosts

        ret = api.get_hosts(mock.Mock())
        self.assertEqual(expected_hosts, ret)
        client.hosts.assert_called_once()

    @mock.patch.object(Api, '_make_client')
    def test_get_hosts_without_maintenance_node(self, mock_client):
        api = Api()
        client = mock.Mock()
        mock_client.return_value = client
        hosts = fake_hosts[:]
        client.hosts.return_value = hosts
        hosts[0].on_maintenance = True
        expected_hosts = hosts[1:]

        ret = api.get_hosts(mock.Mock())
        self.assertEqual(expected_hosts, ret)
        client.hosts.assert_called_once()

    @mock.patch.object(Api, '_make_client')
    def test_get_hosts_only_maintenance_node(self, mock_client):
        api = Api()
        client = mock.Mock()
        mock_client.return_value = client
        hosts = fake_hosts[:]
        client.hosts.return_value = hosts
        hosts[0].on_maintenance = True
        expected_hosts = hosts[:1]

        ret = api.get_hosts(mock.Mock(), maintenance=True)
        self.assertEqual(expected_hosts, ret)
        client.hosts.assert_called_once()
