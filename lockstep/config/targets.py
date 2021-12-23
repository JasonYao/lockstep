from lockstep.core import DynamicFirewallTarget
import requests

"""
GitHub comes as a default for this library as an example,
feel free to remove or add in new ScrapingTargets as you
require
"""


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
