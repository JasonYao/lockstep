from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from enum import Enum
from enum import auto


class TrafficType(Enum):
    UDP = auto()
    HTTP = auto()


@dataclass(frozen=True)
class DynamicFirewallTarget:
    """
    A user-defined object containing everything they need to define:
    - what firewall rules they'd like
    - with what update time they'd like
    - with a mechanism for retrieving an updated list (e.g. through an HTTP API call)
    """
    namespace: str
    supplier: Callable[[], list[str]]
    receiving_port: int = 31_000  # Just a port that's not in use
    traffic_type: TrafficType = TrafficType.UDP
    scrape_interval: timedelta = timedelta(minutes=5)


@dataclass(frozen=True)
class FirewallTarget:
    """
    An internal value object representing:
      - A common grouped name (namespace) for this
        - e.g. "GitHub Actions IP Ranges"
      - A receiving port on this server to take in the traffic
        - e.g. if you'd like to allow GitHub Actions to have access to port 5432 (postgres),
          feel free to set this value here to allow it
      - A traffic type, indicating whether we're allowing UDP or HTTP traffic on this port
    """
    namespace: str
    affected_targets: list[str]
    receiving_port: int = 31_000  # Just a port that's not in use
    traffic_type: TrafficType = TrafficType.UDP


class ChangeType(Enum):
    ADD_FIREWALL_RULE = auto()
    REMOVE_FIREWALL_RULE = auto()
    REMOVE_FIREWALL_NAMESPACE = auto()


@dataclass(frozen=True)
class FirewallChange:
    change_type: ChangeType
    namespace: str
    affected_targets: list[str]
