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
from oslo_config import cfg

HOST_ICMP_GROUP = 'host_icmp'

host_icmp_group = cfg.OptGroup(
    HOST_ICMP_GROUP,
    title="HOST ICMP Plugin Options",
    help="""
Configuration options for HOST ICMP Plugin.
"""
)

monitor_host_opts = [
    cfg.StrOpt('ssh_user',
               default='root',
               help='Login to host\'s username of ssh.'),
    cfg.StrOpt('ssh_password',
               help='Monitoring interval(in seconds) of node status.'),
    cfg.StrOpt('sshkey_location',
               help='If sshkey_location configured, login to remote host'
               'user ssh key instead username and password.'),
    cfg.IntOpt('ssh_timeout',
               default=10,
               help='SSH timeout when use of ssh ping'),
    cfg.BoolOpt('check_ssh_host',
                default=True,
                help='Check ssh host connection when monitor startup'),
    cfg.IntOpt('refresh_info_interval',
               default=30,
               help='Refresh hosts and segments from masakari-api'),
    cfg.StrOpt('ipmi_info_file',
               default="",
               help='IPMI infomation for all hosts with YAML format'),
    cfg.IntOpt('ipmi_poweroff_wait',
               default=30,
               help='Wait N seconds to power host off with ipmitool'),
    cfg.IntOpt('witness',
               default=3,
               help="How many host needed when use ssh to ping failed host"),
    cfg.ListOpt('monitoring_networks',
                default=[],
                help="""Monitor networks
e.g:
  * storge.local
  * storge_mgmt.local
"""),
    cfg.IntOpt('icmp_max_retry',
               default=3,
               help='If ping host failed, retry number'),
    cfg.IntOpt('icmp_retry_interval',
               default=10,
               help='retry interval of retry ping'),
    cfg.BoolOpt('all_failed',
                default=True,
                help='Determine host failed through ssh'
                'when all_failed is True, set host to failed by'
                'all ssh hosts reported target host failed'
                'when all_failed is False set host to failed by'
                'one ssh host report target host failed '
                ),
    cfg.BoolOpt('fence_failure_host',
                default=True,
                help='Fence host when host failure.'
                'If this option set to True, when host down shutdown host '
                'with ipmitool. If this option set to False, when host '
                'down detected, will not shutdown the failure host, send '
                'notification directly. (Warning: Turn off this option '
                'may be cause VM brain split)'
                ),

]


def register_opts(conf):
    conf.register_opts(monitor_host_opts, group='host_icmp')


def list_opts():
    return [(HOST_ICMP_GROUP, monitor_host_opts)]
