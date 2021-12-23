from lockstep.config import ALL_TARGETS
from lockstep.core import FirewallTarget
from lockstep.core import FirewallChange
from lockstep.core import ChangeType

from lockstep.firewall import get_all_entries
from lockstep.firewall import remove_namespace
from lockstep.firewall import remove_entry
from lockstep.firewall import add_entry


def run():
    # TODO: Add in logging instead of raw printing
    print("Checking state of dynamic firewalls")

    # Identifies the target and current states
    current_entries = get_all_entries()
    target_entries = {namespace: FirewallTarget(namespace=namespace, affected_targets=targets.supplier()) for namespace, targets in ALL_TARGETS.items()}
    # print(target_entries)

    # Identifies the exact state change required to go to this desired state
    changelist = generate_changelist(target_entries, current_entries)
    # TODO: Add in persistence of changelist in an audit file
    for idx, (change_type, change) in enumerate(changelist.items()):
        print(f"{idx}: {change_type} --- {change}")

    print("Removing no longer included managed firewall namespaces")
    namespace_removal_changes = changelist.get(ChangeType.REMOVE_FIREWALL_NAMESPACE)
    for namespace_removal in namespace_removal_changes:
        remove_namespace(namespace_removal)

    print("Removing no longer included managed individual firewall rules")
    individual_firewall_rule_removals = changelist.get(ChangeType.REMOVE_FIREWALL_RULE)
    for firewall_rule_removal in individual_firewall_rule_removals:
        remove_entry(firewall_rule_removal)

    print("Adding in newly managed individual firewall rules")
    individual_firewall_rule_additions = changelist.get(ChangeType.ADD_FIREWALL_RULE)
    for firewall_rule_addition in individual_firewall_rule_additions:
        add_entry(firewall_rule_addition)

    # TODO: Add in error handling later on
    print("Dynamic firewalls have been successfully updated")


def generate_changelist(target_state: dict[str, FirewallTarget], current_state: dict[str, FirewallTarget]) -> dict[ChangeType, list[FirewallChange]]:
    changelist = {}

    # Identifies any target namespaces that need to be completely removed
    namespace_removal_changes = []
    target_namespaces = {namespace for namespace in target_state.keys()}
    current_namespaces = {namespace for namespace in current_state.keys()}
    namespaces_to_remove = current_namespaces.difference(target_namespaces)

    for namespace in namespaces_to_remove:
        namespace_removal_changes.append(FirewallChange(
            change_type=ChangeType.REMOVE_FIREWALL_NAMESPACE,
            namespace=namespace,
            affected_targets=current_state.get(namespace).affected_targets
        ))
    changelist[ChangeType.REMOVE_FIREWALL_NAMESPACE] = namespace_removal_changes

    # Identifies any individual firewall rules that need to be removed
    remove_firewall_rules = []
    namespaces_search_space = target_namespaces.intersection(current_namespaces)
    for namespace in namespaces_search_space:
        currently_deployed_firewall_rules = set(current_state.get(namespace).affected_targets)
        target_firewall_rules = set(target_state.get(namespace).affected_targets)

        firewall_rules_to_remove = currently_deployed_firewall_rules.difference(target_firewall_rules)
        if not firewall_rules_to_remove:
            continue

        remove_firewall_rules.append(
            FirewallChange(
                change_type=ChangeType.REMOVE_FIREWALL_RULE,
                namespace=namespace,
                affected_targets=list(firewall_rules_to_remove)
            )
        )
    changelist[ChangeType.REMOVE_FIREWALL_RULE] = remove_firewall_rules

    # Identifies any individual firewall rules that need to be added
    add_firewall_rules = []
    namespaces_search_space = target_namespaces
    for namespace in namespaces_search_space:
        currently_deployed_firewall_rules = [] if current_state.get(namespace) is None else set(current_state.get(namespace).affected_targets)
        target_firewall_rules = set(target_state.get(namespace).affected_targets)

        firewall_rules_to_add = target_firewall_rules.difference(currently_deployed_firewall_rules)
        if not firewall_rules_to_add:
            continue

        add_firewall_rules.append(
            FirewallChange(
                change_type=ChangeType.ADD_FIREWALL_RULE,
                namespace=namespace,
                affected_targets=list(firewall_rules_to_add)
            )
        )
    changelist[ChangeType.ADD_FIREWALL_RULE] = add_firewall_rules

    return changelist


if __name__ == "__main__":
    # At some point in the future, we can add in support for commandline argument passing
    run()
