from __future__ import absolute_import

# Import python libs
import ctypes
import string

# Import salt libs
import salt.ext.six as six
try:
    from salt.utils import platform
except ImportError:
    import salt.utils as platform

try:
    import win32api
except ImportError:
    pass

# Define the module's virtual name
__virtualname__ = 'collect'

if six.PY3:
    UPPERCASE = string.ascii_uppercase
else:
    UPPERCASE = string.uppercase


def __virtual__():
    '''
    Only works on Windows systems
    '''
    if platform.is_windows():
        return __virtualname__
    return False

def disks():
    '''
    Windows only
    Extract the list of letter to put in backup
    '''

    result = []
    if __salt__['grains.get']('os_family') != 'Windows':
        return result

    ret = {}
    drive_bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    # Ugly but ...
    for letter in ['A', 'B', 'C', 'D', 'E', 'F', 'G']:
        if drive_bitmask & 1:
            result.append(letter)
        drive_bitmask >>= 1
    return result
