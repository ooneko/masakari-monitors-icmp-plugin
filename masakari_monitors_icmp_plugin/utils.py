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

"""Utilities and helper functions."""

import eventlet
from functools import partial
from functools import wraps
from oslo_log import log as oslo_logging

LOG = oslo_logging.getLogger(__name__)


def retry(func=None, max_retry=0, retry_interval=0):
    if func is None:
        return partial(max_retry=max_retry,
                       retry_interval=retry_interval)

    @wraps(func)
    def wrap(*args, **kwargs):
        remain = max_retry
        while True:
            try:
                return func(*args, **kwargs)
            except Exception:
                if remain <= 0:
                    raise
                LOG.debug("retry %s left %d" % (func.__name__, remain - 1))
                remain -= 1
                eventlet.greenthread.sleep(retry_interval)
    return wrap
