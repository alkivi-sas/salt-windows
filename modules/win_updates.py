# -*- coding: utf-8 -*-
'''
Module around windows updates
'''
from __future__ import absolute_import

# Import python libs
import sys
import json

# Import urllib
import urllib
from urllib import request
from html.parser import HTMLParser

# Import salt libs
import salt
import salt.version
import salt.loader
from salt.utils.decorators import depends
from salt.exceptions import CommandExecutionError
try:
    from salt.utils import platform
except ImportError:
    import salt.utils as platform

__virtualname__ = "win_updates"

def __virtual__():
    '''
    Only works on Windows
    '''
    if salt.utils.platform.is_windows():
        return __virtualname__
    return False

releaseDate = ""

def history():
    '''
    Get the history of installed updates
    '''
    
    command = 'Get-Hotfix | Select-Object -Property @{Name="InstalledOn";Expression={$_.InstalledOn.ToString("yyyy-MM-dd")}},Description,HotFixID | ConvertTo-Json'
    Json_data = __salt__["cmd.powershell"](command)
    Json_data = json.loads(Json_data)
    base_url = "https://support.microsoft.com/kb/"
    class MyHTMLParser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag == "meta":
                for attr in attrs:
                    if attr[0] == "name" and attr[1] == "firstPublishedDate":
                        global releaseDate
                        releaseDate = attrs[1][1]

    data_to_return = []
    for item in Json_data:
        data = {
            "Description": item["Description"],
            "InstalledOn": item["InstalledOn"],
            "HotFixID": item["HotFixID"],
        }
        split_fixid = item["HotFixID"].split("KB")
        url = base_url + split_fixid[1]
        try:
            response = urllib.request.urlopen(url).read()
            response = response.decode('utf-8')
            parser = MyHTMLParser()
            parser.feed(response)
            data["ReleaseDate"] = releaseDate
        except:
            data["ReleaseDate"] = "Release date not found"
        data_to_return.append(data)
    return data_to_return 
