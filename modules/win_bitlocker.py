# -*- coding: utf-8 -*-
'''
BitLocker Management Execution Module
=====================================

This module provides functions to manage BitLocker on Windows minions.
It relies on the Windows PowerShell cmdlets.
'''

# Import the Salt-native execution module loader
__virtualname__ = 'bitlocker'

import json
import logging
import salt.utils.platform

log = logging.getLogger(__name__)

def __virtual__():
    """
    Set the system module of the kernel is Windows
    """
    # Verify Windows
    if not salt.utils.platform.is_windows():
        log.debug("Module PSGet: Only available on Windows systems")
        return False, "Module PSGet: Only available on Windows systems"

    # Verify PowerShell
    powershell_info = __salt__["cmd.shell_info"]("powershell")
    if not powershell_info["installed"]:
        log.debug("Module PSGet: Requires PowerShell")
        return False, "Module PSGet: Requires PowerShell"

    return __virtualname__


def _run_powershell(cmd):
    '''
    Helper function to run a PowerShell command and handle errors.
    Returns a dictionary of the parsed JSON output or False on failure.
    '''
    try:
        # Prepend 'powershell.exe -Command' for cmd.run fallback
        results = __salt__['cmd.run_all'](cmd, shell="powershell", python_shell=True)

        if "retcode" not in results or results["retcode"] != 0:
            # run_all logs an error to log.error, fail hard back to the user
            raise CommandExecutionError(f"Issue executing powershell {cmd}", info=results)

        return results["stdout"]
    except Exception as e:
        log.error('An exception occurred during PowerShell execution: %s', e)
        return e

def get_status(drive='C:'):
    '''
    Returns the BitLocker status for a specified drive as a dictionary.

    CLI Example:
        salt 'win_minion_id' bitlocker.get_status
        salt 'win_minion_id' bitlocker.get_status 'D:'
    '''
    log.info('Getting BitLocker status for drive: %s', drive)

    # Use a PowerShell expression to select key properties and output as JSON
    command = (
        f'Get-BitLockerVolume -MountPoint "{drive}" | '
        'Select-Object @{n="MountPoint";e={$_.MountPoint}}, '
        '@{n="VolumeStatus";e={$_.VolumeStatus}}, '
        '@{n="ProtectionStatus";e={$_.ProtectionStatus}}, '
        '@{n="EncryptionPercentage";e={$_.EncryptionPercentage}}, '
        '@{n="HasRecoveryKey";e={$_.KeyProtector -match "RecoveryPassword"}} | '
        'ConvertTo-Json'
    )
    
    ps_output = _run_powershell(command)

    if ps_output:
        try:
            # PowerShell can sometimes output extra blank lines, so strip them
            status_data = json.loads(ps_output.strip())
            return status_data
        except json.JSONDecodeError as e:
            log.error('Failed to decode JSON from PowerShell output: %s. Output: %s', e, ps_output)
            return {'error': 'Failed to parse status output.'}
    
    return {'error': 'Could not retrieve BitLocker status.'}

def _get_recovery_key(drive='C:'):
    '''
    Retrieves the BitLocker recovery key (RecoveryPassword) for a specified drive.
    NOTE: This is highly sensitive information.

    CLI Example:
        salt 'win_minion_id' bitlocker.get_recovery_key
    '''
    log.warning('Attempting to retrieve sensitive BitLocker recovery key for drive: %s', drive)
    
    # PowerShell command to select and expand the RecoveryPassword property
    command = (
        f'(Get-BitLockerVolume -MountPoint "{drive}").KeyProtector | '
        'Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"} | '
        'Select-Object -ExpandProperty RecoveryPassword'
    )
    
    recovery_key = _run_powershell(command)
    
    if recovery_key and recovery_key.strip():
        # Strip whitespace and newlines from the recovery key
        return recovery_key.strip()
    
    return None

def get_recovery_key(drive='C:'):
    '''
    Retrieves the BitLocker recovery key (RecoveryPassword) for a specified drive.
    NOTE: This is highly sensitive information.

    CLI Example:
        salt 'win_minion_id' bitlocker.get_recovery_key
    '''
    recovery_key = _get_recovery_key(drive)
    
    if recovery_key is None:
        # Strip whitespace and newlines from the recovery key
        return 'Recovery key not found or drive not protected.'
    else:
        return recovery_key
    

def sync_recovery_key(drive='C:'):
    # PowerShell command to select and expand the RecoveryPassword property
    recovery_key = _get_recovery_key(drive)
    if recovery_key is None:
        # Strip whitespace and newlines from the recovery key
        return 'Recovery key not found or drive not protected.'
    
    __salt__['event.send']('alkivi/password/set', {
        'name': 'recovery_key',
        'type': 'bitlocker',
        'password': recovery_key,
    })
    return "Event send"

def resume_protection(drive='C:'):
    '''
    Resumes BitLocker protection for a specified drive.

    CLI Example:
        salt 'win_minion_id' bitlocker.resume_protection
    '''
    log.info('Attempting to resume BitLocker protection on drive: %s', drive)
    
    # Simple PowerShell command to resume protection
    command = f'Resume-BitLockerVolume -MountPoint "{drive}" -Confirm:$false'
    
    ps_output = _run_powershell(command)
    
    # The command returns an object upon success; we check for known failure messages
    if ps_output is False or 'Error' in ps_output or 'A command that' in ps_output:
        return {'success': False, 'message': ps_output if ps_output else 'PowerShell execution failed.'}
    
    # If successful, Get-BitLockerVolume will show ProtectionStatus as On
    status = get_status(drive)
    if 'ProtectionStatus' in status and status['ProtectionStatus'] == 'On':
        return {'success': True, 'message': f'BitLocker protection successfully resumed on {drive}. Status: On'}
        
    return {'success': True, 'message': f'Resume command executed successfully on {drive}. Current Status: {status.get("ProtectionStatus", "Unknown")}'}
