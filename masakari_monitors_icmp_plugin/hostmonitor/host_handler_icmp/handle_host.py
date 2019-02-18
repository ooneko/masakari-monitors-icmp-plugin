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

import random

import eventlet
from openstack.exceptions import HttpException
from oslo_concurrency.processutils import ProcessExecutionError
from oslo_log import log as oslo_logging
from oslo_utils import timeutils
from pssh.clients import ParallelSSHClient
from pssh import exceptions as ssh_exception

from .host_status import HostsStatus
from .ipmitool import IpmiTool
import masakari_monitors_icmp_plugin.conf
from masakari_monitors_icmp_plugin.exceptions import HostUnavailableException
from masakari_monitors_icmp_plugin.ha import api
from masakari_monitors_icmp_plugin.utils import retry

from masakarimonitors.ha import masakari
import masakarimonitors.hostmonitor.host_handler.driver as driver
from masakarimonitors.objects import event_constants as ec
from masakarimonitors import utils

LOG = oslo_logging.getLogger(__name__)
CONF = masakari_monitors_icmp_plugin.conf.CONF

HOST_STATUS_ONLINE = "ONLINE"
HOST_STATUS_OFFLINE = "OFFLINE"
MAX_MONITORS = 1000


class HandleHost(driver.DriverBase):
    """This class monitor the hosts."""

    def __init__(self):
        self.api = api.Api()
        self.segments = self.api.get_segments()
        self.hosts = self._load_hosts(self.segments)
        self._load_networks()
        self.ipmitool = IpmiTool(self.hosts)
        self.notifier = masakari.SendNotification()
        self.hosts_status = HostsStatus()
        self._check_ssh_host()

    def _check_ssh_host(self):
        check = CONF.host_icmp.check_ssh_host
        if not check:
            return

        client = self._get_ssh_client(self.hosts)
        try:
            output = client.run_command('uname')
            client.join(output)
        except ssh_exception.ConnectionErrorException:
            raise
        except ssh_exception.UnknownHostException:
            raise

    def stop(self):
        self.running = False

    def _watch_masakari_api(self, tp):
        """Watch hosts and segments in masakari-api

        When host removed from segment, remove host from self.hosts
        When host added to segment by masakri-api, start monitor the host.
        """
        while self.running:
            # Avoid to communication with api broken
            try:
                segments = self.api.get_segments()
            except HttpException as e:
                LOG.warn('Getting segment occur error', e)
            else:
                if segments != self.segments:
                    # Add new segment to self.segments if new segment added
                    # by masakari-api
                    [self.segments.append(segment)
                     for segment in segments if segment not in self.segments]
                # remove segment which already removed by masakari-api
                    [self.segments.remove(segment)
                     for segment in self.segments if segment not in segments]

            try:
                hosts = self._load_hosts(self.segments)
            except HttpException as e:
                LOG.warn('Getting hosts occur error', e)
            else:
                if hosts != self.hosts:
                    # Add host to be monitor
                    new_hosts = [host for host in hosts
                                 if host not in self.hosts]
                    self.hosts.extend(new_hosts)
                    [tp.spawn(self._check_host, host) for host in new_hosts]

                    # Remove host which already removed by masakari-api from
                    # segment
                    [self.hosts.remove(host)
                     for host in self.hosts if host not in hosts]

            eventlet.greenthread.sleep(CONF.host_icmp.refresh_info_interval)

    def monitor_hosts(self):
        """Spawn number of hosts greenthead to monitor each host."""

        self.running = True
        tp = eventlet.GreenPool(MAX_MONITORS)
        for host in self.hosts:
            tp.spawn(self._check_host, host)

        # Watch masakari-api hosts changed
        tp.spawn(self._watch_masakari_api, tp)
        tp.waitall()

    def _load_hosts(self, segments):
        """Load hosts from segments."""

        hosts = []
        for segment in segments:
            hosts.extend(self.api.get_hosts(segment))
        if not hosts:
            LOG.warn("No hosts to monitor")

        return hosts

    def _load_networks(self):
        """Load networks from CONF."""

        self.networks = []
        if not CONF.host_icmp.monitoring_networks:
            self.networks = None
            return
        for network in CONF.host_icmp.monitoring_networks:
            if network.startswith('.'):
                network = network[1:]
            self.networks.append(network)

    def _check_host(self, host):
        """Check host whether alive or not."""

        while self.running and host in self.hosts:
            try:
                if not self.networks:
                    self._ping_host(host)
                else:
                    for net in self.networks:
                        self._ping_host(host, net)
                LOG.info('Host %s is alive' % host.name)
            except HostUnavailableException as e:
                self._check_if_host_down(e.host, e.network)

                LOG.error('Host %s is failure' % e.host.name)
                if e.network:
                    LOG.error('Host %s network %s is down' %
                              (e.host.name, e.network))
            except Exception as e:
                LOG.exception("Exception caught: %s", e)
                break

            eventlet.greenthread.sleep(CONF.host.monitoring_interval)

    def _send_notification(self, host, alived):
        """Send notification to masakari api

        Tell api "host down" or "host up"
        """
        if alived:
            event = self._make_event(host, alived)
        else:
            is_power_off = self._fence_host(host)
            event = self._make_event(host, alived, is_power_off)

        self.notifier.send_notification(
            CONF.host.api_retry_max,
            CONF.host.api_retry_interval,
            event
        )

    def _make_event(self, host, alived, is_poweroff=None):
        """Make a event used by notification"""

        if alived:
            event_type = ec.EventConstants.EVENT_STARTED
            # Only for compatible with masakari-monitor
            cluster_status = "ONLINE"
            host_status = ec.EventConstants.HOST_STATUS_NORMAL
        else:
            event_type = ec.EventConstants.EVENT_STOPPED
            # Only for compatible with masakari-monitor
            cluster_status = "OFFLINE"
            if is_poweroff:
                host_status = ec.EventConstants.HOST_STATUS_NORMAL
            else:
                host_status = ec.EventConstants.HOST_STATUS_UNKNOWN

        current_time = timeutils.utcnow()
        event = {
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
        return event

    def _fence_host(self, host):
        """Fence specific host and return result.

        :returns:
        True: host has been shutdown.
        False: host unable to shutdown.
        """
        fence_host = CONF.host_icmp.fence_failure_host
        if not fence_host:
            is_poweroff = True
        else:
            try:
                self.ipmitool.power_off(host)
            except Exception as e:
                LOG.error("Host %s Poweroff failed" % host.name)
                LOG.error(e)
                is_poweroff = False
            else:
                is_poweroff = True

        return is_poweroff

    def _check_if_host_down(self, host, network=None):
        """Check target host whether alived or failured.

        Random pick 3 node in same neighbor to ping target.
        If neighbor < 3: pick all neighbor to ping target.
        If neighbor = 0: means no neighbor to ping target and
        vm have no host to evaucate.
        """
        def get_host_segment(h, s):
            return s if s.uuid == h.failover_segment_id else None

        if self.hosts_status.get_host_status(host) == HOST_STATUS_OFFLINE:
            # host already offline
            return
        # Set host status "offline" whether neighbor report host alive
        # or host down. because monitor unable to ping host
        self.hosts_status.set_host_status(host, HOST_STATUS_OFFLINE)

        for s in self.segments:
            segment = get_host_segment(host, s)
            if segment:
                break

        neighbors = self._get_neighbors(segment, host)
        try:
            if neighbors:
                alived = self._ssh_ping_host(host, neighbors, network)
            else:
                # If have no neighbor which means segment only have one host.
                alived = False
        except ssh_exception.ConnectionErrorException:
            # When unable connecting to neighbor, just log it.
            LOG.error(
                "ssh connection error, could not communicate with neighbors")
        else:
            if alived:
                LOG.warn(
                    "unable to ping host, but neighbor reported that"
                    "host is still alive")
            else:
                self._send_notification(host, alived)

    def _get_neighbors(self, segment, host):
        """Get neighbors of host's segment.

        :returns:
        List of host: when host have neighbor
        None: when host have no neighbor
        """
        neighbors = [
            h for h in self.hosts if h.failover_segment_id == segment.uuid]
        # neighbors should't contain host self
        neighbors.remove(host)

        # Remove offline node from neighbors
        for n in neighbors:
            if self.hosts_status.get_host_status(n) == HOST_STATUS_OFFLINE:
                neighbors.remove(n)

        witness = CONF.host_icmp.witness

        if len(neighbors) > witness:
            random.shuffle(neighbors)
            return neighbors[0:witness]
        else:
            return neighbors

    @retry(max_retry=CONF.host_icmp.icmp_max_retry,
           retry_interval=CONF.host_icmp.icmp_retry_interval)
    def _ping_host(self, host, network=None):
        """Execute ping command on monitor.

        This function will return None if host is alive
        else raise ProcessExecutionError
        """
        if network:
            target = "%s.%s" % (host.name, network)
        else:
            target = host.name

        command = ['ping', '-W', '1', '-c', '1', target]
        try:
            utils.execute(*command)
        except ProcessExecutionError:
            raise HostUnavailableException(
                host=host, network=network, target=target)
        else:
            # if host_status is empty means it's new node of monitor
            # if node have host_status and it't not ONLINE status
            # means node from OFFLINE to ONLINE
            if (self.hosts_status.get_host_status(host) and
                    self.hosts_status.get_host_status(host) !=
                    HOST_STATUS_ONLINE):
                self._send_notification(host, alived=True)
            self.hosts_status.set_host_status(host, HOST_STATUS_ONLINE)

    def _ssh_ping_host(self, failed_host, neighbors, network=None):
        """SSH to neighbors to check host whether or not failed.

        :returns:
        True: Host is alive.
        False: Host is down.
        """

        all_failed = CONF.host_icmp.all_failed
        client = self._get_ssh_client(neighbors)

        if not network:
            target = failed_host.name
        else:
            target = '%s.%s' % (failed_host.name, network)

        try:
            # Arg -c means ping 3 times to prevent network unstable
            output = client.run_command('ping -W 1 -c 3 %s' % target)
            # Wait for exit code
            client.join(output)
        except ssh_exception.ConnectionErrorException as e:
            # When unable connecting to neighbor, just log it.
            LOG.error("Error connecting to host %s" % e.host)
            raise
        else:
            for host, host_output in output.items():
                if host_output.exit_code == 0:
                    LOG.info("Host %s still alive" %
                             (target))
                    status = True
                else:
                    status = False

                # False when all host report failed
                if all_failed and status:
                    break
                # False when anyone report failed
                if not all_failed and not status:
                    break

        return status

    def _get_ssh_client(self, hosts):

        ssh_hosts = [host.name for host in hosts]
        user = CONF.host_icmp.ssh_user
        password = CONF.host_icmp.ssh_password
        ssh_key = CONF.host_icmp.sshkey_location
        timeout = CONF.host_icmp.ssh_timeout

        if ssh_key:
            # If sshkey is defined use sshkey instead username and password
            client = ParallelSSHClient(
                ssh_hosts, pkey=ssh_key, timeout=timeout)
        else:
            client = ParallelSSHClient(
                ssh_hosts, user=user, password=password, timeout=timeout)

        return client
