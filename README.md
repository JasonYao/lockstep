# Lockstep

## Overview
> Say you have a server and want it secured and
  locked down, but want to allow GitHub Action
  runners access. Since [GitHub Actions runners' IP addresses](https://api.github.com/meta)
  change so often, you'd otherwise need to make constant
  manual changes to your firewall rules to properly allow
  access, wasting time and introducing lots of toil. Or worse,
  decide that a secure environment would be too much effort,
  and choose to just allow all access.

Enter Lockstep.

Lockstep is a simple, open source, and **auditable** linux firewall
(ufw) updater, that is able to dynamically keep track of making
your server both secure **and** accessible without having to
compromise between security and ease.

You can run Lockstep:
  - [Recommended] As a [systemctl service](#TODO) to keep your
    firewall rules constantly updated per user-defined targets
    and frequencies
  - Manually in order to verify the behavior of expected
    firewall changes, and to build up confidence in running
    Lockstep autonomously

Lockstep maintains an _auditable_ list of changes over time,
enabling you to see the firewall rules diff per namespace in
an easily parseable json history file, enabling fast
reversions if required.

## Usage
### Defining your mapping of ip address targets and scrape intervals

```python
# Inside of the lockstep/config/targets.py file
from lockstep.core import DynamicFirewallTarget
import requests

def retrieve_github_actions_ip_ranges() -> list[str]:
    r = requests.get('https://api.github.com/meta')
    if r.status_code != 200:
        raise RuntimeError("An error occurred when trying to talk to the GitHub API, please try again later")

    return r.json()['actions']


GITHUB_SCRAPING_TARGET = DynamicFirewallTarget(
    namespace="GitHub Actions IP Ranges",
    supplier=retrieve_github_actions_ip_ranges,
)

ALL_TARGETS: dict[str, DynamicFirewallTarget] = {
    GITHUB_SCRAPING_TARGET.namespace: GITHUB_SCRAPING_TARGET,
}
```

## Installation

### Pre-requisites
- Python 3.10+
- Installing the library requirements with `pip install -r requirements.txt`

### [Recommended] Installing the systemctl service
TODO

## Running lockstep manually

## Testing

## License
Distributed under the [Apache v2 license](LICENSE)
