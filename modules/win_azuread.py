# -*- coding: utf-8 -*-
'''
Module for running alkivi custom functions
'''
from __future__ import absolute_import

# Import python libs
import sys
from difflib import get_close_matches
import xml.etree.ElementTree as ET

# Import Salt libs
import salt
import salt.version
import salt.loader
from salt.utils.decorators import depends
from salt.exceptions import CommandExecutionError
try:
    from salt.utils import platform
except ImportError:
    import salt.utils as platform
from salt.exceptions import CommandExecutionError, SaltInvocationError

# Don't shadow built-in's.
__func_alias__ = {
    'true_': 'true',
    'false_': 'false'
}

__virtualname__ = 'azuread'

def __virtual__():
    '''
    Only works on Windows systems
    '''
    if platform.is_windows():
        return __virtualname__
    return False


def matches(file_path):
    '''
    Compare session username with the list of emails to get a close match
    '''
    path = file_path
    xml_file = ET.parse(path)
    accounts = xml_file.getroot()
    
    azureAccounts = []
    localUsers = []
    data = __pillar__.get('users')
    for user, userData in data.items():
        localUsers.append({"UserPrincipalName": user, "DisplayName": userData.get('fullname')})
    results = []
    for account in accounts.findall('User'):
        userPrincipalName = account.find('UserPrincipalName').text
        displayName = account.find('DisplayName').text
        if "alkivi" in displayName.casefold():
            continue
        if "package" in userPrincipalName:
            continue
        azureAccounts.append({"UserPrincipalName": userPrincipalName, "DisplayName": displayName})
        
    for localUser in localUsers:
        for azureAccount in azureAccounts:
            if localUser["DisplayName"] in azureAccount["DisplayName"]:
                results.append({"TargetAccount": azureAccount["UserPrincipalName"], "SourceAccount": localUser["UserPrincipalName"]})

    return results
