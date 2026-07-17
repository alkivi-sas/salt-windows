# -*- coding: utf-8 -*-
'''
State for managing Windows Firewall rules via PowerShell (NetSecurity).
Identifies rules by DisplayName (name). Uses alkivi_win_firewall.ps_* functions.
'''
from __future__ import absolute_import, print_function, unicode_literals

import ipaddress

from salt.exceptions import CommandExecutionError


def __virtual__():
    if 'alkivi_win_firewall.ps_get_rule' in __salt__:
        return 'win_firewall_rule'
    return False


def _canonicalize_address(addr):
    '''
    Canonical form for a single address/subnet so that equivalent subnets compare equal.
    E.g. 51.83.58.98/28 and 51.83.58.96/255.255.255.240 both become 51.83.58.96/28.
    Plain IPs are returned as-is (or as x.x.x.x/32 if we want consistency; ip_network does that).
    '''
    addr = str(addr).strip()
    if not addr or addr == 'Any':
        return 'Any'
    try:
        return str(ipaddress.ip_network(addr, strict=False))
    except Exception:
        return addr


def _normalize_value(val):
    '''Normalize for comparison: list/tuple to sorted tuple, bool to bool, rest to str.'''
    if val is None:
        return None
    if isinstance(val, (list, tuple)):
        return tuple(sorted(str(x) for x in val)) if val else ()
    if isinstance(val, bool):
        return val
    return str(val).strip()


def _extract_port_value(val):
    '''
    Extract port value from ps_get_rule output. LocalPort/RemotePort can be
    a list, a dict with 'value' or 'Value' (PowerShell serialization), or a scalar.
    '''
    if val is None:
        return None
    if isinstance(val, dict) and ('value' in val or 'Value' in val):
        val = val.get('value') or val.get('Value')
    return val


def _normalize_remote_address(val):
    '''
    Canonical form for remote_address comparison: 'Any' or a sorted tuple of address strings.
    Treats scalar 127.0.0.1 and list [127.0.0.1] as equal.
    Subnets are canonicalized so e.g. 51.83.58.98/28 and 51.83.58.96/255.255.255.240 compare equal.
    '''
    if val is None:
        return None
    if isinstance(val, dict) and ('value' in val or 'Value' in val):
        val = val.get('value') or val.get('Value')
    if isinstance(val, str):
        s = val.strip()
        if not s or s == 'Any':
            return 'Any'
        return (_canonicalize_address(s),)
    if isinstance(val, (list, tuple)):
        if not val:
            return 'Any'
        canonical = tuple(sorted(_canonicalize_address(str(x).strip()) for x in val if str(x).strip()))
        return canonical if canonical else 'Any'
    return None


def _current_to_desired(current):
    '''Map ps_get_rule output (English keys) to state/module param names.'''
    if not current:
        return {}
    # RemoteAddress: use canonical form so scalar and list compare equal
    return {
        'direction': _normalize_value(current.get('Direction')),
        'action': _normalize_value(current.get('Action')),
        'protocol': _normalize_value(current.get('Protocol')),
        'local_port': _normalize_value(_extract_port_value(current.get('LocalPort'))),
        'remote_port': _normalize_value(_extract_port_value(current.get('RemotePort'))),
        'local_address': _normalize_value(current.get('LocalAddress')),
        'remote_address': _normalize_remote_address(current.get('RemoteAddress')),
        'profile': _normalize_value(current.get('Profile')),
        'enabled': current.get('Status') == 'Active',
        'description': _normalize_value(current.get('Description')) if current.get('Description') else None,
        'display_group': _normalize_value(current.get('DisplayGroup')),
    }


def absent(name):
    '''
    Ensure a Windows Firewall rule (by DisplayName) is absent.

    name
        DisplayName of the rule to remove.

    Example:

    .. code-block:: yaml

        remove_old_rule:
          win_firewall_rule.absent:
            - name: OldRuleName
    '''
    ret = {'name': name, 'result': True, 'changes': {}, 'comment': ''}
    try:
        current = __salt__['alkivi_win_firewall.ps_get_rule'](display_name=name)
    except CommandExecutionError as e:
        ret['result'] = False
        ret['comment'] = str(e)
        return ret

    if current is None:
        ret['comment'] = 'Rule already absent'
        return ret

    if __opts__.get('test'):
        ret['result'] = None
        ret['comment'] = 'Rule would be removed'
        ret['changes'] = {'rule': name}
        return ret

    try:
        deleted_rules = __salt__['alkivi_win_firewall.ps_del_rule'](display_name=name)
        ret['changes'] = {'rule': name, 'deleted_rules': deleted_rules}
        ret['comment'] = 'Rules removed' if isinstance(deleted_rules, list) and len(deleted_rules) > 1 else 'Rule removed'
    except CommandExecutionError as e:
        ret['result'] = False
        ret['comment'] = str(e)
    return ret


def present(
    name,
    direction=None,
    action=None,
    protocol=None,
    local_port=None,
    remote_port=None,
    local_address=None,
    remote_address=None,
    profile=None,
    enabled=None,
    description=None,
    display_group=None,
    **kwargs
):
    '''
    Ensure a Windows Firewall rule (by DisplayName) is present with the given settings.
    Only parameters explicitly passed in the state are compared and updated; unspecified
    parameters are left as-is on the existing rule.

    name
        DisplayName of the rule (required).

    direction
        Inbound or Outbound.

    action
        Allow or Block.

    protocol
        TCP, UDP, Any, etc.

    local_port, remote_port
        Port(s). Can be a single value (e.g. 80 or \"80,443\") or a YAML list
        (e.g. [5060, \"40000-60000\"]). Lists are normalized for comparison.

    local_address, remote_address
        Address(es), e.g. Any or 192.168.0.0/24.

    profile
        Domain, Private, Public (comma-separated).

    enabled
        True to enable, False to disable the rule.

    description, display_group
        Optional description and display group.

    remote_address
        Can be a single string (\"Any\", \"1.2.3.4,5.6.7.8\") or a YAML list of
        addresses/subnets. Lists are compared as unordered sets of strings, so
        order does not matter for idempotence.

    Example:

    .. code-block:: yaml

        allow_http:
          win_firewall_rule.present:
            - name: HTTP
            - direction: Inbound
            - protocol: TCP
            - local_port: 80
            - action: Allow
    '''
    ret = {'name': name, 'result': True, 'changes': {}, 'comment': ''}
    # Only include explicitly passed params so we only compare/update what the user specified
    explicit = {}
    if direction is not None:
        explicit['direction'] = direction
    if action is not None:
        explicit['action'] = action
    if protocol is not None:
        explicit['protocol'] = protocol
    if local_port is not None:
        explicit['local_port'] = local_port
    if remote_port is not None:
        explicit['remote_port'] = remote_port
    if local_address is not None:
        explicit['local_address'] = local_address
    if remote_address is not None:
        explicit['remote_address'] = remote_address
    if profile is not None:
        explicit['profile'] = profile
    if enabled is not None:
        explicit['enabled'] = enabled
    if description is not None:
        explicit['description'] = description
    if display_group is not None:
        explicit['display_group'] = display_group
    explicit.update(kwargs)

    desired = {}
    for k, v in explicit.items():
        if v is None:
            continue
        if k == 'remote_address':
            desired[k] = _normalize_remote_address(v)
        else:
            desired[k] = _normalize_value(v)

    try:
        current = __salt__['alkivi_win_firewall.ps_get_rule'](display_name=name)
    except CommandExecutionError as e:
        ret['result'] = False
        ret['comment'] = str(e)
        return ret

    if current is None:
        if __opts__.get('test'):
            ret['result'] = None
            ret['comment'] = 'Rule would be added'
            ret['changes'] = {'rule': name}
            return ret
        add_kw = dict(
            display_name=name,
            direction=explicit.get('direction', 'Inbound'),
            action=explicit.get('action', 'Allow'),
            protocol=explicit.get('protocol', 'TCP'),
            enabled=explicit.get('enabled', True),
        )
        for k in ('local_port', 'remote_port', 'local_address', 'remote_address', 'profile', 'description', 'display_group'):
            if explicit.get(k) is not None:
                add_kw[k] = explicit[k]
        try:
            __salt__['alkivi_win_firewall.ps_add_rule'](**add_kw)
            ret['changes'] = {'rule': name}
            ret['comment'] = 'Rule added'
        except CommandExecutionError as e:
            ret['result'] = False
            ret['comment'] = str(e)
        return ret

    current_norm = _current_to_desired(current)
    diff = {}
    for key in desired:
        if key not in current_norm:
            continue
        if desired[key] != current_norm[key]:
            diff[key] = explicit.get(key)
    if not diff:
        ret['comment'] = 'Rule already present with correct config'
        return ret

    if __opts__.get('test'):
        ret['result'] = None
        ret['comment'] = 'Rule would be updated: {0}'.format(', '.join(diff.keys()))
        ret['changes'] = {'rule': name}
        return ret

    set_kw = dict(display_name=name)
    for k, v in diff.items():
        set_kw[k] = v
    try:
        __salt__['alkivi_win_firewall.ps_set_rule'](**set_kw)
        ret['changes'] = {'rule': name}
        ret['comment'] = 'Rule updated'
    except CommandExecutionError as e:
        ret['result'] = False
        ret['comment'] = str(e)
    return ret
