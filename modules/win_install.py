# -*- coding: utf-8 -*-
'''
Manage Alkivi setup on mac
'''

# Import python libs
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import logging
import random
import string
import time

# Import salt libs
try:
    from salt.utils import platform
except ImportError:
    import salt.utils as platform
from salt.exceptions import CommandExecutionError, SaltInvocationError

logger = logging.getLogger(__name__)

# Define the module's virtual name
__virtualname__ = 'install'


def __virtual__():
    '''
    Only works on Windows systems
    '''
    if platform.is_windows():
        return __virtualname__
    return False

def _install_reg_key(hive, key, vname, vdata, vtype):
    '''
    Helpers to install a reg edit key
    Check if the key is already present with the correct value.
    If so, return already OK.
    If not, install the key
    '''

    test = __salt__['reg.read_value'](hive=hive, key=key, vname=vname)

    # Testing the value using str, not the best way to do it
    if test['success'] and str(test['vdata']) == str(vdata):
        return 'Already OK'
    else:
        res = __salt__['reg.set_value'](hive=hive, key=key, vname=vname,
                vdata=vdata, vtype=vtype)
        if res:
            return 'OK'
        else:
            logger.warning('Error when adding {0} to {1}/{2}'.format(vname, hive, key))
            logger.warning(res)
            return 'Error'


def _package_present(name):
    '''
    Helpers to see if a package is installed
    Return True is present (i.e. in pkg.list_pkgs
    Return False otherwise
    '''
    is_present = False

    test = __salt__['pkg.list_pkgs']()
    for pkg in test.keys():
        to_test = '{0}'.format(pkg)
        if to_test.startswith(name):
            is_present = True

    return is_present


def _delete_package(name):
    '''
    Helpers to remove a package
    Return 'Already OK' if not present
    Return 'OK' if delete
    Otherwise return Error
    '''

    if _package_present(name):
        # Old Way : not OK
        #cmd = 'wmic product where name=\"' + name + '\" call uninstall /nointeractive'
        #test = __salt__['cmd.run'](cmd, cwd='c:\\Windows\\System32')

        cmd = '(Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name = \'{0}\'").uninstall()'.format(name)
        test = __salt__['cmd.powershell'](cmd)
        if test:
            return test
            return 'OK'
        else:
            logger.warning('Error when removing {0}'.format(name))
            logger.warning(test)
            return 'Error'
    else:
        return 'Already OK'



def _perform_cmd(test_module, test_args, test_result, exec_module, exec_args, test_method='if'):
    '''
    Perform a test if return is not correct execute command
    '''
    res = __salt__[test_module](**test_args)
    if test_method not in ['if', 'ifnot']:
        raise Exception('test_method should be if or ifnot')

    should_exec = False
    if test_method == 'if':
        if res == test_result:
            should_exec = True
    else:
        if res != test_result:
            should_exec = True

    if should_exec:
        return __salt__[exec_module](**exec_args)
    else:
        return 'Already OK'


def users(password, local_user):
    '''
    Perform a series of test related to users for windows
    Create Alkivi with admin right
    Fix password for both Administrator and Alkivi
    If local_user, remove Administrator Grant for user
    '''
    result = {}

    name = 'User Alkivi'

    groups = ['Administrateurs', 'Utilisateurs']
    user_groups_to_add = ['Utilisateurs']
    user_groups_to_del = ['Administrateurs']

    # If virtual plateform, change this
    if __salt__['grains.get']('virtual'):
        groups = ['Administrators', 'Users']
        user_groups_to_add = ['Users']
        user_groups_to_del = ['Administrators']

    data = {
            'test_args': {'name': 'alkivi'},
            'test_module': 'user.info',
            'test_method': 'if',
            'test_result': False,
            'exec_module': 'user.add',
            'exec_args': {
                'name': 'alkivi', 
                'password': password,
                'fullname': 'Alkivi Support User',
                'groups': groups,
            },
           }
    result[name] = _perform_cmd(**data)

    name = 'Password for Alkivi never expire'
    result[name] = __salt__['user.update']('alkivi', password_never_expires=True)

    name = 'Password for Alkivi'
    result[name] = __salt__['user.setpassword']('alkivi', password)

    name = 'Password for Administrateur'
    result[name] = __salt__['user.setpassword']('Administrateur', password)

    groups = __salt__['user.list_groups'](local_user)

    for user_group in user_groups_to_add:
        name = '{0} in group {1}'.format(local_user, user_group)
        if user_group not in groups:
            test = __salt__['user.addgroup'](local_user, user_group)
            if test:
                result[name] = 'OK'
            else:
                logger.error(test)
                result[name] = 'Error'
        else:
            result[name] = 'Already OK'

    for user_group in user_groups_to_del:
        name = '{0} not in group {1}'.format(local_user, user_group)
        if user_group in groups:
            test = __salt__['user.removegroup'](local_user, user_group)
            if test:
                result[name] = 'OK'
            else:
                logger.error(test)
                result[name] = 'Error'
        else:
            result[name] = 'Already OK'

    return result


def system():
    '''
    Perform a series of test on the minion to match alkivi criteria
    '''

    result = {}

    name = 'Regedit EnablePlainTextPassword'
    params = { 
        'hive': 'HKEY_LOCAL_MACHINE',
        'key': 'SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters',
        'vname': 'EnablePlainTextPassword',
        'vdata': 1,
        'vtype': 'REG_DWORD',
    }
    result[name] = _install_reg_key(**params)

    return result


def clean_mcafee():
    '''
    Remove McAfee shit
    '''
    result = {}

    #name = 'Removing McAfee LiveSafe'
    #cmd = 'cmd /c "C:\\Program Files\\McAfee\\MSC\\mcuihost.exe" /body:misp://MSCJsRes.dll::uninstall.html /id:uninstall'
    #test = __salt__['cmd.powershell'](cmd)
    #result[name] = test

    name = 'McAfee Uninstaller'
    params = {
            'path': 'salt://desktop/windows/files/mcafee_uninstaller.exe',
            'dest': 'c:/alkivi/mcafee_uninstaller.exe',
            }
    test = __salt__['cp.get_url'](**params)
    if test:
        result[name] = 'OK'
    else:
        logger.error(test)
        result[name] = 'Error'

    name = 'Starting Uninstaller'
    cmd = 'C:\\alkivi\\mcafee_uninstaller.exe'
    test = __salt__['cmd.run_all'](cmd)
    result[name] = test

    return result

def clean_dell():
    '''
    Remove all Dell product that we dont want
    '''
    result = {}

    products = [
            'Aide et support Dell',
            'Dell Command | Power Manager',
            'Dell Command | Update',
            'Dell ControlVault Host Components Installer 64 bit',
            'Dell Data Vault',
            'Dell Digital Delivery',
            'Dell Edoc Viewer',
            'Dell Foundation Services',
            'Dell Protected Workspace',
            'Dell SupportAssist Remediation',
            'Dell SupportAssist',
            'Dell SupportAssistAgent',
            'Dell Update - SupportAssist Update Plugin',
            'Dell Update',
            'Dropbox 20 GB',
            'Enregistrement du produit Dell',
            'Enregistrement du produit',
        ]

    for product in products:
        name = 'Remove Software {0}'.format(product)
        result[name] = _delete_package(product)

    return result


def openvpn(local_user):
    '''
    Install OpenVPN and perform command using subinacl to allow service 
    to run by local_user
    '''
    result = {}

    test = __salt__['pkg.list_pkgs']()

    should_install_openvpn = True
    should_install_subinacl = True
    if _package_present('subinacl'):
        should_install_subinacl = False
    if _package_present('OpenVPN'):
        should_install_openvpn = False

    refresh_winrepo = should_install_subinacl or should_install_openvpn
    if refresh_winrepo:
        __salt__['pkg.refresh_db']()

    name = 'Install subinacl'
    if should_install_subinacl:
        test = __salt__['pkg.install']('subinacl')
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'
    else:
        result[name] = 'Already OK'

    name = 'Install OpenVPN'
    if should_install_openvpn:
        test = __salt__['pkg.install']('openvpn')
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'
    else:
        result[name] = 'Already OK'

    name = 'Grant ACL to {0}'.format(local_user)
    cmd = 'C:\\Program Files (x86)\\Windows Resource Kits\\Tools\\subinacl.exe /SERVICE OpenVPNService'
    test = __salt__['cmd.run_all'](cmd)
    text = unicode(test['stdout'], 'cp1255')
    if text.find('\{0}'.format(local_user)):
        result[name] = 'Already OK'
    else:
        cmd = 'C:\\Program Files (x86)\\Windows Resource Kits\\Tools\\subinacl.exe /SERVICE OpenVPNService /GRANT={0}=to'.format(local_user)
        test = __salt__['cmd.run'](cmd)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

    #name = 'Launch OpenVPN-Gui'
    #cmd = 'C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe'
    #test = __salt__['cmd.run_all'](cmd)
    #if test:
    #    result[name] = 'OK'
    #else:
    #    logger.error(test)
    #    result[name] = 'Error'

    name = 'Regedit allow_edit=0'
    params = { 
        'hive': 'HKEY_LOCAL_MACHINE',
        'key': 'SOFTWARE\OpenVPN-GUI',
        'vname': 'allow_edit',
        'vdata': 0,
        'vtype': 'REG_SZ',
    }
    result[name] = _install_reg_key(**params)

    name = 'Regedit allow_password=0'
    params = { 
        'hive': 'HKEY_LOCAL_MACHINE',
        'key': 'SOFTWARE\OpenVPN-GUI',
        'vname': 'allow_password',
        'vdata': 0,
        'vtype': 'REG_SZ',
    }
    result[name] = _install_reg_key(**params)

    name = 'Regedit allow_service=0'
    params = { 
        'hive': 'HKEY_LOCAL_MACHINE',
        'key': 'SOFTWARE\OpenVPN-GUI',
        'vname': 'allow_service',
        'vdata': 1,
        'vtype': 'REG_SZ',
    }
    result[name] = _install_reg_key(**params)

    name = 'Regedit service_only=0'
    params = { 
        'hive': 'HKEY_LOCAL_MACHINE',
        'key': 'SOFTWARE\OpenVPN-GUI',
        'vname': 'service_only',
        'vdata': 1,
        'vtype': 'REG_SZ',
    }
    result[name] = _install_reg_key(**params)

    return result


def firewall():
    '''
    Perform a series of test on the minion to match alkivi criteria
    '''

    result = {}

    def _generic_add(test_cmd, test_result, rule):
        test = __salt__['cmd.run_all'](test_cmd, python_shell=False)
        if test['retcode'] == 0:
            return 'Already OK'
        else:
            cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                   'name={0}'.format(rule['name']),
                   'protocol={0}'.format(rule['protocol']),
                   'dir={0}'.format(rule['dir']),
                   'action={0}'.format(rule['action'])]
            if 'localport' in rule:
                cmd.append('localport={0}'.format(rule['localport']))

            ret = __salt__['cmd.run'](cmd, python_shell=False)
            if isinstance(ret, str):
                if ret.strip() == 'Ok.':
                    return 'OK'
            else:
                log.error('firewall.add_rule failed: {0}'.format(ret))
                return 'Error'

    name = 'Rule ICMP V4'
    params = {
        'test_cmd': ['Powershell', '-NonInteractive', 'Get-NetFirewallRule -Displayname "All ICMP v4" | ft name,enabled'],
        'test_result': 0,
        'rule': {
            'name': 'All ICMP v4',
            'protocol': 'icmpv4',
            'dir': 'in',
            'action': 'allow',
        }
    }
    result[name] = _generic_add(**params)

    name = 'Rule Rsync TCP 873'
    params = {
        'test_cmd': ['Powershell', '-NonInteractive', 'Get-NetFirewallRule -Displayname "Alkivi Rsync Port" | ft name,enabled'],
        'test_result': 0,
        'rule': {
            'name': 'Alkivi Rsync Port',
            'protocol': 'TCP',
            'dir': 'in',
            'action': 'allow',
            'localport': 873,
        }
    }
    result[name] = _generic_add(**params)

    name = 'Rule Zabbix TCP 10050'
    params = {
        'test_cmd': ['Powershell', '-NonInteractive', 'Get-NetFirewallRule -Displayname "Alkivi Zabbix Port" | ft name,enabled'],
        'test_result': 0,
        'rule': {
            'name': 'Alkivi Zabbix Port',
            'protocol': 'TCP',
            'dir': 'in',
            'action': 'allow',
            'localport': 10050,
        }
    }
    result[name] = _generic_add(**params)
    return result

def zabbix(server):
    '''Install zabbix related data
    '''

    result = {}

    '''Test directory'''
    name = 'Directory c:/alkivi'
    if not os.path.isdir('c:/alkivi'):
        params = {
            'dir_path': 'c:/alkivi',
            'user': 'alkivi',
        }
        result[name] = __salt__['file.mkdir'](**params)
    else:
        result[name] = 'Already OK'



    '''TODO test for changes'''
    name = 'Zabbix Conf'
    content = 'Server={0}\r\nServerActive={0}\r\nHostname={1}'.format(server,__salt__['grains.get']('id'))
    params = {
        'path': 'c:/alkivi/zabbix_agentd.conf',
        'args': content,
    }
    test = __salt__['file.write'](**params)
    if test:
        result[name] = 'OK'
    else:
        logger.error(test)
        result[name] = 'Error'

    
    '''Test if service already there'''
    name = 'Zabbix Exe'
    test = __salt__['service.enabled']('Zabbix Agent')
    if test:
        result[name] = 'Already OK, skipping exe'
    else:
        params = {
            'path': 'salt://desktop/windows/files/zabbix_agentd.exe',
            'dest': 'c:/alkivi/zabbix_agentd.exe',
        }
        test = __salt__['cp.get_file'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

        name = 'Install Zabbix Service'
        params = {
            'cmd': 'c:/alkivi\zabbix_agentd.exe --config c:/alkivi\zabbix_agentd.conf --install'
        }
        test = __salt__['cmd.run'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

    '''Test if service is active'''
    name = 'Start Zabbix Service'
    test = __salt__['service.status']('Zabbix Agent')
    if test:
        result[name] = 'Already started'
    else:
        test = __salt__['service.start']('Zabbix Agent')
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'


    return result

def backup(password, server):
    '''Install cwRsyncServer_Installer.exe'''
    result = {}

    '''Test directory'''
    name = 'Directory c:/alkivi'
    if not os.path.isdir('c:/alkivi'):
        params = {
            'dir_path': 'c:/alkivi',
            'user': 'alkivi',
        }
        result[name] = __salt__['file.mkdir'](**params)
    else:
        result[name] = 'Already OK'

    '''Test if service is enable, if not install'''
    name = 'cwRsyncServer Exe'
    test = __salt__['service.enabled']('RsyncServer')
    if test:
        result[name] = 'Already OK, skipping exe'
    else:
        params = {
            'path': 'salt://desktop/windows/files/cwRsyncServer_Installer.exe',
            'dest': 'c:/alkivi/cwRsyncServer_Installer.exe',
        }
        test = __salt__['cp.get_file'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

        name = 'Install RsyncServer Service'
        params = {
            'cmd': 'c:/alkivi/cwRsyncServer_Installer.exe /u=alkivi /p={0} /S'.format(password)
        }
        test = __salt__['cmd.run'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

        '''TODO test for changes'''
        name = 'RsyncServer Password'
        content = 'alkivi:{0}'.format(password)
        params = {
            'path': 'c:\Program Files (x86)/ICW/passwd',
            'args': content,
        }
        test = __salt__['file.write'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

        '''TODO test for changes'''
        name = 'RsyncServer Conf'
        content = [
                'use chroot = false',
                'strict modes = false',
                'hosts allow = {0}'.format(server),
                'log file = rsyncd.log',
                'secrets file = passwd',
                '',
                '# Module definitions',
                '# Remember cygwin naming conventions : c:\work becomes /cygwin/c/work',
                '#',
                '[c]',
                'gid = 0',
                'uid = 0',
                'auth users = alkivi',
                'path = /cygdrive/c',
                'transfer logging = yes']
        params = {
            'path': 'c:\Program Files (x86)/ICW/rsyncd.conf',
            'args': '\r\n'.join(content),
        }
        test = __salt__['file.write'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'


        name = 'Enable Service'
        test = __salt__['service.enable']('RsyncServer')
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

        name = 'Start Service'
        test = __salt__['service.start']('RsyncServer')
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

    return result

def ninite():
    '''Install base packages using ninite'''
    result = {}

    '''Test directory'''
    name = 'Directory c:/alkivi'
    if not os.path.isdir('c:/alkivi'):
        params = {
            'dir_path': 'c:/alkivi',
            'user': 'alkivi',
        }
        result[name] = __salt__['file.mkdir'](**params)
    else:
        result[name] = 'Already OK'

    # TODO test for changes, maybe state.sls ?
    name = 'Ninite Exe'
    params = {
        'path': 'salt://desktop/windows/files/ninite.exe',
        'dest': 'c:/alkivi/ninite.exe',
    }
    test = __salt__['cp.get_url'](**params)
    if test:
        result[name] = 'OK'
    else:
        logger.error(test)
        result[name] = 'Error'

    name = 'Install Ninite'
    params = {
        'cmd': 'c:/alkivi/ninite.exe',
    }
    test = __salt__['cmd.run_all'](**params)
    if test:
        result[name] = 'OK'
    else:
        logger.error(test)
        result[name] = 'Error'

    return result

def office365():
    '''Install office365 base'''
    result = {}

    # TODO test for changes, maybe state.sls ?

    name = 'Install Office'
    test = __salt__['pkg.list_pkgs']()

    if _package_present('Microsoft Office 365 Business'):
        result[name] = 'Already OK'
    else:
        name = 'Office 365 Exe'
        params = {
            'path': 'salt://desktop/windows/files/office365.exe',
            'dest': 'c:/alkivi/office365.exe',
        }
        test = __salt__['cp.get_url'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

        name = 'Install Office'
        params = {
            'cmd': 'c:/alkivi/office365.exe',
        }
        test = __salt__['cmd.run_all'](**params)
        if test:
            result[name] = 'OK'
        else:
            logger.error(test)
            result[name] = 'Error'

    return result

def network_credentials(user,password,domain,server):
    '''Install Windows Credentials to connect to the NAS'''

    # TODO wait for cmd.run to implement runas for windows
    # Here is the command
    cmd = 'cmdkey /add:{0} /user:{1}\{2} /pass:{3}'.format(server,domain,user,password)
    return cmd
