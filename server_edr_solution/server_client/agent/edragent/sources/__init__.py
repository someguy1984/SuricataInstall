"""The log readers (client PLAN section 4.5, Inputs). Each one turns a log into make_event() events."""
from .base import AccessRing, AccessStats, Context, Source, parse_ip
from .tetragon import TetragonSource, describe, detail
from .nginx import AccessLogSource, ErrorLogSource, attribute_error_line, load_tripwires, match_tripwire, parse_access_line
from .journal import JournalSource, SeenStore, parse_sshd, parse_sudo
from .suricata import EveBulkSource, EveSource
from .kernel import KernelSource, parse_kernel_line
from .helpers import HelperWatcher
