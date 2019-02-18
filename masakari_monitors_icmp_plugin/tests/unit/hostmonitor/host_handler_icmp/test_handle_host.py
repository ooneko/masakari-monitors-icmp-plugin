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
Unit Tests for HandleHost
"""

import eventlet
import mock
from pssh import exceptions as ssh_exception
import testtools

from masakarimonitors.objects import event_constants as ec
from openstack.exceptions import HttpException
from oslo_concurrency.processutils import ProcessExecutionError

import masakari_monitors_icmp_plugin.conf
from masakari_monitors_icmp_plugin.exceptions import HostUnavailableException
from masakari_monitors_icmp_plugin.hostmonitor.host_handler_icmp.handle_host \
    import HandleHost
from masakari_monitors_icmp_plugin.hostmonitor.host_handler_icmp.host_status import \
    HostsStatus
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
fake_segments = [FakeSegment(name='fake_segment1', uuid='1'),
                 FakeSegment(name='fake_segment2', uuid='2')]


@mock.patch.object(HandleHost, '__init__', lambda x: None)
class TestHandleHost(testtools.TestCase):
    def setUp(self):
        super(TestHandleHost, self).setUp()

    @mock.patch.object(HandleHost, '_get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_check_ssh_host(self, mock_conf, mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = fake_hosts
        mock_conf.host_icmp.check_ssh_host = True
        mock_client = mock.Mock()
        mock_ssh_client.return_value = mock_client

        host_handler._check_ssh_host()

        mock_ssh_client.assert_called_once_with(fake_hosts)
        mock_client.run_command.assert_called_once_with('uname')
        mock_client.join.assert_called()

    @mock.patch.object(HandleHost, '_get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_check_ssh_host_disable_check(self, mock_conf, mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = fake_hosts
        mock_conf.host_icmp.check_ssh_host = False

        host_handler._check_ssh_host()
        mock_ssh_client.assert_not_called()

    @mock.patch.object(HandleHost, '_get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_check_ssh_host_with_connection_error(self,
                                                  mock_conf,
                                                  mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = fake_hosts
        mock_conf.host_icmp.check_ssh_host = True
        mock_client = mock.Mock()
        mock_client.run_command.side_effect = \
            ssh_exception.ConnectionErrorException
        mock_ssh_client.return_value = mock_client

        self.assertRaises(ssh_exception.ConnectionErrorException,
                          host_handler._check_ssh_host)
        mock_ssh_client.assert_called_once_with(fake_hosts)
        mock_client.run_command.assert_called_once_with('uname')

    @mock.patch.object(HandleHost, '_get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_check_ssh_host_with_unknownhost(self,
                                             mock_conf,
                                             mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = fake_hosts
        mock_conf.host_icmp.check_ssh_host = True
        mock_client = mock.Mock()
        mock_client.run_command.side_effect = \
            ssh_exception.UnknownHostException
        mock_ssh_client.return_value = mock_client

        self.assertRaises(ssh_exception.UnknownHostException,
                          host_handler._check_ssh_host)
        mock_ssh_client.assert_called_once_with(fake_hosts)
        mock_client.run_command.assert_called_once_with('uname')

    def test_stop(self):
        host_handler = HandleHost()
        host_handler.hosts = [x for x in range(3)]

        host_handler.stop()
        assert host_handler.running is False

    @mock.patch.object(HandleHost, '_load_hosts')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_watch_masakari_api_segment_added(self,
                                              mock_eventlet,
                                              mock_loadhosts):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.hosts = None
        mock_loadhosts.return_value = None
        tp = mock.Mock()
        mock_api = mock.Mock()
        mock_api.get_segments.side_effect = [fake_segments[:], Exception]
        host_handler.api = mock_api
        host_handler.segments = fake_segments[:1]

        self.assertRaises(Exception, host_handler._watch_masakari_api, tp)
        mock_loadhosts.assert_called_once_with(fake_segments[:])
        mock_api.get_segments.assert_called()

    @mock.patch.object(HandleHost, '_load_hosts')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_watch_masakari_api_segment_removed(self,
                                                mock_eventlet,
                                                mock_loadhosts):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.hosts = None
        mock_loadhosts.return_value = None
        tp = mock.Mock()
        mock_api = mock.Mock()
        mock_api.get_segments.side_effect = [fake_segments[:1], Exception]
        host_handler.api = mock_api
        host_handler.segments = fake_segments[:]

        self.assertRaises(Exception, host_handler._watch_masakari_api, tp)
        mock_loadhosts.assert_called_once_with(fake_segments[:1])
        mock_api.get_segments.assert_called()

    @mock.patch.object(HandleHost, '_load_hosts')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_watch_masakari_api_hosts_added(self,
                                            mock_eventlet,
                                            mock_loadhosts):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.hosts = []
        mock_loadhosts.return_value = fake_hosts[:]
        tp = mock.Mock()
        mock_api = mock.Mock()
        mock_api.get_segments.side_effect = [fake_segments[:], Exception]
        host_handler.api = mock_api
        host_handler.segments = fake_segments[:]
        calls = [mock.call(host_handler._check_host, fake_hosts[0]),
                 mock.call(host_handler._check_host, fake_hosts[1]),
                 mock.call(host_handler._check_host, fake_hosts[2])]

        self.assertRaises(Exception, host_handler._watch_masakari_api, tp)
        mock_loadhosts.assert_called_once_with(fake_segments[:])
        self.assertEqual(host_handler.hosts, fake_hosts)
        tp.spawn.assert_has_calls(calls)
        mock_api.get_segments.assert_called()

    @mock.patch.object(HandleHost, '_load_hosts')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_watch_masakari_api_hosts_removed(self,
                                              mock_eventlet,
                                              mock_loadhosts):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.hosts = fake_hosts[:]
        mock_loadhosts.return_value = fake_hosts[1:]
        tp = mock.Mock()
        mock_api = mock.Mock()
        mock_api.get_segments.side_effect = [fake_segments[:], Exception]
        host_handler.api = mock_api
        host_handler.segments = fake_segments[:]

        self.assertRaises(Exception, host_handler._watch_masakari_api, tp)
        mock_loadhosts.assert_called_once_with(fake_segments[:])
        self.assertEqual(host_handler.hosts, fake_hosts[1:])
        mock_api.get_segments.assert_called()

    @mock.patch.object(HandleHost, '_load_hosts')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_watch_masakari_api_no_change(self,
                                          mock_eventlet,
                                          mock_loadhosts):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.hosts = fake_hosts[:]
        mock_loadhosts.return_value = fake_hosts[:]
        tp = mock.Mock()
        mock_api = mock.Mock()
        mock_api.get_segments.side_effect = [fake_segments[:], Exception]
        host_handler.api = mock_api
        host_handler.segments = fake_segments[:]

        self.assertRaises(Exception, host_handler._watch_masakari_api, tp)
        mock_loadhosts.assert_called_once_with(fake_segments[:])
        self.assertEqual(host_handler.hosts, fake_hosts[:])
        mock_api.get_segments.assert_called()
        tp.spawn.assert_not_called()

    @mock.patch.object(HandleHost, '_load_hosts')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_watch_masakari_api_with_http_exception(self,
                                                    mock_eventlet,
                                                    mock_loadhosts):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.hosts = fake_hosts[:]
        mock_loadhosts.side_effect = [HttpException, ]
        tp = mock.Mock()
        mock_api = mock.Mock()
        mock_api.get_segments.side_effect = [HttpException, Exception]
        host_handler.api = mock_api
        host_handler.segments = fake_segments[:]

        self.assertRaises(Exception, host_handler._watch_masakari_api, tp)
        mock_api.get_segments.assert_called()
        mock_loadhosts.assert_called_once_with(fake_segments[:])
        self.assertEqual(host_handler.hosts, fake_hosts[:])
        self.assertEqual(host_handler.segments, fake_segments[:])

    @mock.patch.object(eventlet, 'GreenPool')
    def test_monitor_hosts(self, mock_greenpool):
        host_handler = HandleHost()
        host_handler.hosts = fake_hosts
        tp = mock.Mock()
        mock_greenpool.return_value = tp
        calls = [mock.call(host_handler._check_host, fake_hosts[0]),
                 mock.call(host_handler._check_host, fake_hosts[1]),
                 mock.call(host_handler._check_host, fake_hosts[2]),
                 mock.call(host_handler._watch_masakari_api, tp)]

        host_handler.monitor_hosts()
        tp.spawn.assert_has_calls(calls)
        tp.waitall.assert_called_once()

    def test_load_host(self):
        host_handler = HandleHost()
        host_handler.api = mock.Mock()
        host_handler.api.get_hosts.return_value = fake_hosts
        segments = [FakeSegment(name='fake_segment')]

        hosts = host_handler._load_hosts(segments)
        host_handler.api.get_hosts.assert_called_once()
        self.assertEqual(hosts, fake_hosts)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_load_host_have_no_host(self, mock_log):
        host_handler = HandleHost()
        host_handler.api = mock.Mock()
        host_handler.api.get_hosts.return_value = []
        segments = [FakeSegment(name='fake_segment')]

        hosts = host_handler._load_hosts(segments)
        host_handler.api.get_hosts.assert_called_once()
        mock_log.warn.assert_called_once_with("No hosts to monitor")
        self.assertEqual(hosts, [])

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_load_networks(self, mock_conf):
        host_handler = HandleHost()
        mock_conf.host_icmp.monitoring_networks = ['local']

        host_handler._load_networks()
        assert 'local' in host_handler.networks

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_load_networks_start_with_dot(self, mock_conf):
        host_handler = HandleHost()
        mock_conf.host_icmp.monitoring_networks = ['.local']

        host_handler._load_networks()
        assert 'local' in host_handler.networks

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_load_networks_have_no_networks(self, mock_conf):
        host_handler = HandleHost()
        mock_conf.host_icmp.monitoring_networks = []

        host_handler._load_networks()
        assert host_handler.networks is None

    @mock.patch.object(HandleHost, '_check_if_host_down')
    @mock.patch.object(HandleHost, '_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_check_host_nornal(self, mock_eventlet, mock_ping, mock_check):
        host_handler = HandleHost()
        mock_ping.side_effect = [None, Exception("Test Exception")]
        host_handler.running = True
        host_handler.networks = ['local']
        host_handler.hosts = fake_hosts
        host = fake_hosts[0]

        host_handler._check_host(host)
        self.assertEqual(2, mock_ping.call_count)
        mock_ping.assert_called_with(host, 'local')
        mock_eventlet.greenthread.sleep.assert_called_with(
            CONF.host.monitoring_interval)

    @mock.patch.object(HandleHost, '_check_if_host_down')
    @mock.patch.object(HandleHost, '_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_check_host_without_networks(self, mock_eventlet,
                                         mock_ping, mock_check):
        host_handler = HandleHost()
        mock_ping.side_effect = [None, Exception("Test Exception")]
        host_handler.running = True
        host_handler.networks = []
        host_handler.hosts = fake_hosts
        host = fake_hosts[0]

        host_handler._check_host(host)

        self.assertEqual(2, mock_ping.call_count)
        mock_ping.assert_called_with(host)
        mock_eventlet.greenthread.sleep.assert_called_with(
            CONF.host.monitoring_interval)

    @mock.patch.object(HandleHost, '_check_if_host_down')
    @mock.patch.object(HandleHost, '_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.eventlet')
    def test_check_host_if_host_down(self, mock_eventlet,
                                     mock_ping, mock_check):
        host_handler = HandleHost()
        host_handler.running = True
        host_handler.networks = ['local']
        host_handler.hosts = fake_hosts
        host = fake_hosts[0]
        mock_ping.side_effect = [HostUnavailableException(
            host=host, network='local'), Exception]

        host_handler._check_host(host)

        self.assertEqual(2, mock_ping.call_count)
        mock_ping.assert_called_with(host, 'local')
        mock_check.assert_called_once_with(host, 'local')
        mock_eventlet.greenthread.sleep.assert_called_with(
            CONF.host.monitoring_interval)

    @mock.patch.object(HandleHost, '_fence_host')
    @mock.patch.object(HandleHost, '_make_event')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_send_notification_when_host_alived(self, mock_conf,
                                                mock_make_event,
                                                mock_fence_host):
        host_handler = HandleHost()
        host_handler.notifier = mock.Mock()
        host = FakeHost(name="fake_host")
        alived = True

        host_handler._send_notification(host, alived)

        mock_make_event.assert_called_once_with(host, alived)
        host_handler.notifier.send_notification.assert_called_once()

    @mock.patch.object(HandleHost, '_fence_host')
    @mock.patch.object(HandleHost, '_make_event')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_send_notification_when_host_down(self,
                                              mock_conf,
                                              mock_make_event,
                                              mock_fence_host):

        host_handler = HandleHost()
        host_handler.notifier = mock.Mock()
        host = FakeHost(name="fake_host")
        alived = False
        is_power_off = True
        mock_fence_host.return_value = is_power_off

        host_handler._send_notification(host, alived)

        mock_fence_host.assert_called_once_with(host)
        mock_make_event.assert_called_once_with(host, alived, is_power_off)
        host_handler.notifier.send_notification.assert_called_once()

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.timeutils')
    def test_make_event_current_status_is_online(self, mock_time):
        host_handler = HandleHost()
        host = FakeHost(name='fake_host')
        alived = True
        current_time = "fake_time"
        mock_time.utcnow.return_value = current_time
        event_type = ec.EventConstants.EVENT_STARTED
        cluster_status = "ONLINE"
        host_status = ec.EventConstants.HOST_STATUS_NORMAL
        expected_event = {
            'notification': {
                'type': ec.EventConstants.TYPE_COMPUTE_HOST,
                'hostname': host.name,
                'generated_time': current_time,
                'payload': {
                    'event': event_type,
                    'cluster_status': cluster_status,
                    'host_status': host_status
                }
            }
        }

        event = host_handler._make_event(host, alived)

        self.assertEqual(expected_event, event)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.timeutils')
    def test_make_event_current_status_is_offline(self, mock_time):
        host_handler = HandleHost()
        host = FakeHost(name='fake_host')
        alived = False
        current_time = "fake_time"
        mock_time.utcnow.return_value = current_time
        event_type = ec.EventConstants.EVENT_STOPPED
        cluster_status = "OFFLINE"
        host_status = ec.EventConstants.HOST_STATUS_UNKNOWN
        expected_event = {
            'notification': {
                'type': ec.EventConstants.TYPE_COMPUTE_HOST,
                'hostname': host.name,
                'generated_time': current_time,
                'payload': {
                    'event': event_type,
                    'cluster_status': cluster_status,
                    'host_status': host_status
                }
            }
        }

        event = host_handler._make_event(host, alived)

        self.assertEqual(expected_event, event)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.timeutils')
    def test_make_event_current_status_is_offline_and_poweroff(self,
                                                               mock_time):
        host_handler = HandleHost()
        host = FakeHost(name='fake_host')
        is_power_off = True
        alived = False
        current_time = "fake_time"
        mock_time.utcnow.return_value = current_time
        event_type = ec.EventConstants.EVENT_STOPPED
        cluster_status = "OFFLINE"
        host_status = ec.EventConstants.HOST_STATUS_NORMAL
        expected_event = {
            'notification': {
                'type': ec.EventConstants.TYPE_COMPUTE_HOST,
                'hostname': host.name,
                'generated_time': current_time,
                'payload': {
                    'event': event_type,
                    'cluster_status': cluster_status,
                    'host_status': host_status
                }
            }
        }

        event = host_handler._make_event(host, alived, is_power_off)

        self.assertEqual(expected_event, event)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_fence_host(self, mock_conf):
        host_handler = HandleHost()
        host_handler.ipmitool = mock.Mock()
        host = FakeHost(name='fake_host')
        mock_conf.host_icmp.fence_failure_host = True

        ret = host_handler._fence_host(host)

        host_handler.ipmitool.power_off.assert_called_once_with(host)
        self.assertEqual(True, ret)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_fence_host_do_nothing(self, mock_conf):
        host_handler = HandleHost()
        host_handler.ipmitool = mock.Mock()
        host = FakeHost(name='fake_host')
        mock_conf.host_icmp.fence_failure_host = False

        ret = host_handler._fence_host(host)

        host_handler.ipmitool.power_off.assert_not_called()
        self.assertEqual(True, ret)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_fence_host_failed(self, mock_conf):
        host_handler = HandleHost()
        host_handler.ipmitool = mock.Mock()
        host_handler.ipmitool.power_off.side_effect = Exception(
            "poweroff time out")
        host = FakeHost(name='fake_host')
        mock_conf.host_icmp.fence_failure_host = True

        ret = host_handler._fence_host(host)

        host_handler.ipmitool.power_off.assert_called_once_with(host)
        self.assertEqual(False, ret)

    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(HandleHost, '_ssh_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_check_if_host_down_host_not_down(self, mock_log,
                                              mock_ssh_ping,
                                              mock_send_notification):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        segment = FakeSegment(name='fake_segment', uuid='1')
        [host_handler.hosts_status.set_host_status(h, "ONLINE")
            for h in host_handler.hosts]
        host_handler.segments = [segment]
        mock_ssh_ping.return_value = True

        host_handler._check_if_host_down(host, network=None)

        mock_ssh_ping.assert_called_once_with(host, neighbors, None)
        mock_log.warn.assert_called_once()

    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(HandleHost, '_ssh_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_check_if_host_down_host_down(self, mock_log,
                                          mock_ssh_ping,
                                          mock_send_notification):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        segment = FakeSegment(name='fake_segment', uuid='1')
        [host_handler.hosts_status.set_host_status(h, "ONLINE")
            for h in host_handler.hosts]
        host_handler.segments = [segment]
        mock_ssh_ping.return_value = False

        host_handler._check_if_host_down(host, network=None)

        mock_ssh_ping.assert_called_once_with(host, neighbors, None)
        mock_send_notification.assert_called_once_with(host, False)

    @mock.patch.object(HandleHost, '_get_neighbors')
    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(HandleHost, '_ssh_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_check_if_host_down_host_already_down(self, mock_log,
                                                  mock_ssh_ping,
                                                  mock_send_notification,
                                                  mock_get_neighbors):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host = FakeHost(name='fake_host1')
        host_handler.hosts_status.set_host_status(host, "OFFLINE")

        host_handler._check_if_host_down(host, network=None)

        mock_get_neighbors.assert_not_called()
        mock_ssh_ping.assert_not_called()
        mock_log.error.assert_not_called()
        mock_log.warn.assert_not_called()
        mock_send_notification.assert_not_called()

    @mock.patch.object(HandleHost, '_get_neighbors')
    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(HandleHost, '_ssh_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_check_if_host_down_without_neighbors(self,
                                                  mock_log,
                                                  mock_ssh_ping,
                                                  mock_send_notification,
                                                  mock_get_neighbors):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host = FakeHost(name='fake_host1', failover_segment_id='1')
        host_handler.hosts_status.set_host_status(host, "ONLINE")
        segment = FakeSegment(name='fake_segment', uuid='1')
        host_handler.segments = [segment]
        mock_get_neighbors.return_value = None

        host_handler._check_if_host_down(host, network=None)

        mock_get_neighbors.assert_called_once_with(segment, host)
        mock_ssh_ping.assert_not_called()
        mock_send_notification.assert_called_once_with(host, False)

    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(HandleHost, '_ssh_ping_host')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_check_if_host_down_host_neighbor_ssh_error(self,
                                                        mock_log,
                                                        mock_ssh_ping,
                                                        mock_notification):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        segment = FakeSegment(name='fake_segment', uuid='1')
        [host_handler.hosts_status.set_host_status(h, "ONLINE")
            for h in host_handler.hosts]
        host_handler.segments = [segment]
        mock_ssh_ping.side_effect = ssh_exception.ConnectionErrorException()

        host_handler._check_if_host_down(host, network=None)

        mock_ssh_ping.assert_called_once_with(host, neighbors, None)
        mock_log.error.assert_called_once()
        mock_notification.assert_not_called()

    def test_get_neighbors(self):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        segment = FakeSegment(name='fake_segment', uuid='1')
        expected = host_handler.hosts[:]
        expected.remove(host)
        [host_handler.hosts_status.set_host_status(h, "ONLINE")
            for h in host_handler.hosts]

        ret = host_handler._get_neighbors(segment, host)

        self.assertEqual(expected, ret)

    def test_get_neighbors_remove_offline_node(self):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        segment = FakeSegment(name='fake_segment', uuid='1')
        host_handler.hosts_status.set_host_status(
            host_handler.hosts[1], "ONLINE")
        host_handler.hosts_status.set_host_status(
            host_handler.hosts[2], "OFFLINE")

        ret = host_handler._get_neighbors(segment, host)

        assert host_handler.hosts[1] in ret
        assert host_handler.hosts[2] not in ret

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.utils')
    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(eventlet.greenthread, 'sleep')
    def test_ping_host_with_network(self,
                                    mock_eventlet,
                                    mock_send_notification,
                                    mock_utils):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host = FakeHost(name='fake_host1')
        command = ('ping -W 1 -c 1 %s' % host.name).split(' ')
        host_handler.hosts_status.set_host_status(
            host, "ONLINE")

        host_handler._ping_host(host, None)

        mock_utils.execute.assert_called_once_with(*command)
        mock_send_notification.assert_not_called()

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.utils')
    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(eventlet.greenthread, 'sleep')
    def test_ping_host_without_network(self,
                                       mock_eventlet,
                                       mock_send_notification,
                                       mock_utils):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host = FakeHost(name='fake_host1')
        network = 'local'
        command = ('ping -W 1 -c 1 %s.%s' % (host.name, network)).split(' ')
        host_handler.hosts_status.set_host_status(
            host, "ONLINE")

        host_handler._ping_host(host, network)

        mock_utils.execute.assert_called_once_with(*command)
        mock_send_notification.assert_not_called()

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.utils')
    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(eventlet.greenthread, 'sleep')
    def test_ping_host_host_unreachable_to_alive(self,
                                                 mock_eventlet,
                                                 mock_send_notification,
                                                 mock_utils):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host = FakeHost(name='fake_host1')
        network = 'local'
        command = ('ping -W 1 -c 1 %s.%s' % (host.name, network)).split(' ')
        host_handler.hosts_status.set_host_status(
            host, "OFFLINE")

        host_handler._ping_host(host, network)

        mock_utils.execute.assert_called_once_with(*command)
        mock_send_notification.assert_called_once_with(host, alived=True)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.utils')
    @mock.patch.object(HandleHost, '_send_notification')
    @mock.patch.object(eventlet.greenthread, 'sleep')
    def test_ping_host_host_alive_to_unreachable(self,
                                                 mock_eventlet,
                                                 mock_send_notification,
                                                 mock_utils):
        host_handler = HandleHost()
        host_handler.hosts_status = HostsStatus()
        host = FakeHost(name='fake_host1')
        network = 'local'
        command = ('ping -W 1 -c 1 %s.%s' % (host.name, network)).split(' ')
        host_handler.hosts_status.set_host_status(
            host, "ONLINE")
        mock_utils.execute.side_effect = ProcessExecutionError

        self.assertRaises(HostUnavailableException,
                          host_handler._ping_host, host, network)
        mock_utils.execute.assert_called_with(*command)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.HandleHost._get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_ssh_ping_host_normal(self,
                                  mock_log,
                                  mock_conf,
                                  mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        mock_client = mock.Mock()
        mock_ssh_client.return_value = mock_client
        output = mock.Mock()
        output.exit_code = 1
        mock_client.run_command.return_value = {
            'fake_host2': output, 'fake_host3': output}
        mock_conf.host_icmp.all_failed = True
        command = 'ping -W 1 -c 3 %s' % host.name

        status = host_handler._ssh_ping_host(host, neighbors)
        mock_ssh_client.assert_called_once_with(neighbors)
        mock_client.run_command.assert_called_once_with(command)
        mock_client.join.assert_called()
        self.assertEqual(status, False)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.HandleHost._get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_ssh_ping_with_network(self,
                                   mock_log,
                                   mock_conf,
                                   mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        network = 'local'
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        mock_client = mock.Mock()
        mock_ssh_client.return_value = mock_client
        output = mock.Mock()
        output.exit_code = 1
        mock_client.run_command.return_value = {
            'fake_host2': output, 'fake_host3': output}
        mock_conf.host_icmp.all_failed = True
        command = 'ping -W 1 -c 3 %s.%s' % (host.name, network)

        status = host_handler._ssh_ping_host(host, neighbors, network)
        mock_ssh_client.assert_called_once_with(neighbors)
        mock_client.run_command.assert_called_once_with(command)
        mock_client.join.assert_called()
        self.assertEqual(status, False)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.HandleHost._get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_ssh_ping_host_with_all_failed_policy(self,
                                                  mock_log,
                                                  mock_conf,
                                                  mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        network = 'local'
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        mock_client = mock.Mock()
        mock_ssh_client.return_value = mock_client
        host2_output = mock.Mock()
        host3_output = mock.Mock()
        host2_output.exit_code = 1
        host3_output.exit_code = 0
        mock_client.run_command.return_value = {
            'fake_host2': host2_output, 'fake_host3': host3_output}
        mock_conf.host_icmp.all_failed = True
        command = 'ping -W 1 -c 3 %s.%s' % (host.name, network)

        status = host_handler._ssh_ping_host(host, neighbors, network)
        mock_ssh_client.assert_called_once_with(neighbors)
        mock_client.run_command.assert_called_once_with(command)
        mock_client.join.assert_called()
        self.assertEqual(status, True)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.HandleHost._get_ssh_client')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.LOG')
    def test_ssh_ping_host_with_any_failed_policy(self,
                                                  mock_log,
                                                  mock_conf,
                                                  mock_ssh_client):
        host_handler = HandleHost()
        host_handler.hosts = [FakeHost(name='fake_host1',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host2',
                                       failover_segment_id='1'),
                              FakeHost(name='fake_host3',
                                       failover_segment_id='1'),
                              ]
        host = host_handler.hosts[0]
        network = 'local'
        neighbors = host_handler.hosts[:]
        neighbors.remove(host)
        mock_client = mock.Mock()
        mock_ssh_client.return_value = mock_client
        host2_output = mock.Mock()
        host3_output = mock.Mock()
        host2_output.exit_code = 1
        host3_output.exit_code = 0
        mock_client.run_command.return_value = {
            'fake_host2': host2_output, 'fake_host3': host3_output}
        mock_conf.host_icmp.all_failed = False
        command = 'ping -W 1 -c 3 %s.%s' % (host.name, network)

        status = host_handler._ssh_ping_host(host, neighbors, network)
        mock_ssh_client.assert_called_once_with(neighbors)
        mock_client.run_command.assert_called_once_with(command)
        mock_client.join.assert_called()
        self.assertEqual(status, False)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.ParallelSSHClient')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_get_ssh_client_with_password(self, mock_conf, mock_ssh_client):
        host_handler = HandleHost()
        mock_conf.host_icmp.ssh_user = 'fake'
        mock_conf.host_icmp.ssh_password = 'fake'
        mock_conf.host_icmp.sshkey_location = ''
        mock_conf.host_icmp.ssh_timeout = 10

        host_handler._get_ssh_client(fake_hosts)
        mock_ssh_client.assert_called_once_with(
            [h.name for h in fake_hosts],
            user='fake', password='fake', timeout=10)

    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.ParallelSSHClient')
    @mock.patch('masakari_monitors_icmp_plugin.hostmonitor'
                '.host_handler_icmp.handle_host.CONF')
    def test_get_ssh_client_with_sshkey(self, mock_conf, mock_ssh_client):
        host_handler = HandleHost()
        mock_conf.host_icmp.ssh_user = 'fake'
        mock_conf.host_icmp.ssh_password = 'fake'
        mock_conf.host_icmp.sshkey_location = 'sshkey'
        mock_conf.host_icmp.ssh_timeout = 10

        host_handler._get_ssh_client(fake_hosts)
        mock_ssh_client.assert_called_once_with(
            [h.name for h in fake_hosts], pkey='sshkey', timeout=10)
