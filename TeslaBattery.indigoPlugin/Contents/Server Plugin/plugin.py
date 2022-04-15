#! /usr/bin/env python2.6
# -*- coding: utf-8 -*-

"""
Tesla - Battery Control
0.2.2
Prelim Version


"""
import logging
import datetime
import time
import time as t
#import urllib2
import os
#import shutil
import sys
import platform
#import urlparse
from urlparse import urlparse,parse_qs

import requests
import json
#import subprocess
import threading
from threading import Timer
import requests
#import urllib3
#urllib3.disable_warnings() # For 'verify=False' SSL warning
import urllib
import base64
import hashlib
import re
#import random
#import string
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

try:
    import indigo
except:
    pass

__author__ = "GlennNZ"
__build__ = "Unused"
__copyright__ = "Copyright 2017-2019 GlennNZ"
__license__ = "MIT"
__title__ = "TeslaBattery IndigoPlugin"
__version__ = "0.3.9"


# Establish default plugin prefs; create them if they don't already exist.
kDefaultPluginPrefs = {
    u'configMenuPollInterval': "300",  # Frequency of refreshes.
    u'configMenuServerTimeout': "15",  # Server timeout limit.
    # u'refreshFreq': 300,  # Device-specific update frequency
    u'showDebugInfo': False,  # Verbose debug logging?
    u'configUpdaterForceUpdate': False,
    u'configUpdaterInterval': 24,
    u'showDebugLevel': "5",  # Low, Medium or High debug output.
    u'updaterEmail': "",  # Email to notify of plugin updates.
    u'updaterEmailsEnabled': False  # Notification of plugin updates wanted.
}


class Plugin(indigo.PluginBase):
    def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
        indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
        self.startingUp = True
        self.pluginIsInitializing = True
        self.pluginIsShuttingDown = False
        self.prefsUpdated = False
        self.logger.info(u"")
        self.logger.info(u"{0:=^130}".format(" Initializing New Plugin Session "))
        self.logger.info(u"{0:<30} {1}".format("Plugin name:", pluginDisplayName))
        self.logger.info(u"{0:<30} {1}".format("Plugin version:", pluginVersion))
        self.logger.info(u"{0:<30} {1}".format("Plugin ID:", pluginId))
        self.logger.info(u"{0:<30} {1}".format("Indigo version:", indigo.server.version))
        self.logger.info(u"{0:<30} {1}".format("Python version:", sys.version.replace('\n', '')))
        self.logger.info(u"{0:<31} {1}".format("Mac OS Version:", platform.mac_ver()[0]))
        self.logger.info(u"{0:<31} {1}".format("Process ID:", os.getpid() ))

        self.logger.info(u"{0:=^130}".format(""))

        pfmt = logging.Formatter('%(asctime)s.%(msecs)03d\t[%(levelname)8s] %(name)20s.%(funcName)-25s%(msg)s',
                                 datefmt='%Y-%m-%d %H:%M:%S')
        self.plugin_file_handler.setFormatter(pfmt)

        try:
            self.logLevel = int(self.pluginPrefs[u"showDebugLevel"])

        except:
            self.logLevel = logging.INFO

        self.indigo_log_handler.setLevel(self.logLevel)
        self.logger.debug(u"logLevel = " + str(self.logLevel))
        self.triggers = {}
        self.changingoperationalmode = False
        #self.debug = self.pluginPrefs.get('showDebugInfo', False)
        #self.debugLevel = self.pluginPrefs.get('showDebugLevel', "1")
        self.debugextra = self.pluginPrefs.get('debugextra', False)
        self.debugtriggers = self.pluginPrefs.get('debugtriggers', False)
        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "24")) * 60.0 * 60.0
        self.next_update_check = t.time()

        self.openStore = self.pluginPrefs.get('openStore', False)
        self.serverip = self.pluginPrefs.get('ipAddress', '')
        self.username = self.pluginPrefs.get('username', '')
        self.password = self.pluginPrefs.get('password', '')
        self.allowOnline = self.pluginPrefs.get('allowOnline', False)
        self.batUsername = self.pluginPrefs.get('Batusername', '')
        self.batPassword = self.pluginPrefs.get('Batpassword', '')
        #self.serialnumber = self.pluginPrefs.get('serialnumber', '')
        self.version = '0.0.0'
        self.pairingToken = ""
        self.pairingTokenLocal = ""
        self.pairingTokenexpires_in = int(0)
        self.pairingTokencreated_at = int(0)
        self.pairingTokenrefresh_token = ""

        if 'Tesla Battery Gateway' not in indigo.devices.folders:
            indigo.devices.folder.create('Tesla Battery Gateway')
        self.folderId = indigo.devices.folders['Tesla Battery Gateway'].id

        self.sessionReq = requests.Session()
        self.sessionData = ""
        self.sessiontimeStamp = 0 ## unix date stamp of 2 hours post token...

        self.verifier_bytes = os.urandom(32)
        self.challenge = base64.urlsafe_b64encode(self.verifier_bytes).rstrip(b'=')
        self.challenge_bytes = hashlib.sha256(self.challenge).digest()
        self.challengeSum = base64.urlsafe_b64encode(self.challenge_bytes).rstrip(b'=')

        self.auth_header = {'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + self.pairingToken}
        self.TESLA_CLIENT_ID = '81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384'
        self.TESLA_CLIENT_SECRET = 'c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3'

        self.pluginIsInitializing = False





    def __del__(self):
        self.debugLog(u"__del__ method called.")
        indigo.PluginBase.__del__(self)

    def closedPrefsConfigUi(self, valuesDict, userCancelled):

        self.debugLog(u"closedPrefsConfigUi() method called.")

        if userCancelled:
            self.debugLog(u"User prefs dialog cancelled.")

        if not userCancelled:

            self.debugLog(u"User prefs saved.")
            #self.debug = valuesDict.get('showDebugInfo', False)
            self.debugextra = valuesDict.get('debugextra', False)
            self.debugtriggers = valuesDict.get('debugtriggers', False)
            self.serverip = valuesDict.get('ipAddress', '')
            self.username = valuesDict.get('username', '')
            self.password = valuesDict.get('password', '')
            self.allowOnline = valuesDict.get('allowOnline', False)
            self.batUsername = valuesDict.get('Batusername', '')
            self.batPassword = valuesDict.get('Batpassword', '')
            #self.serialnumber = valuesDict.get('serialnumber', '')
            self.prefsUpdated = True
            self.updateFrequency = float(valuesDict.get('updateFrequency', "24")) * 60.0 * 60.0

            try:
                self.logLevel = int(valuesDict[u"showDebugLevel"])
            except:
                self.logLevel = logging.INFO

            self.indigo_log_handler.setLevel(self.logLevel)

            self.openStore = valuesDict.get('openStore', False)
            self.logger.debug(u"logLevel = " + str(self.logLevel))
            self.logger.debug(u"User prefs saved.")
            self.logger.debug(u"Debugging on (Level: {0})".format(self.logLevel))

        return True

    # Start 'em up.
    def deviceStartComm(self, dev):

        self.debugLog(u"deviceStartComm() method called.")
        dev.stateListOrDisplayStateIdChanged()

    # Shut 'em down.
    def deviceStopComm(self, dev):
        if self.debugextra:
            self.debugLog(u"deviceStopComm() method called.")
        indigo.server.log(u"Stopping device: " + dev.name)
        dev.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")

        dev.setErrorStateOnServer(u'Device Offline')

    ###
    ###  Update ghpu Routines.


    def pluginstoreUpdate(self):
        iurl = 'http://www.indigodomo.com/pluginstore/'
        self.browserOpen(iurl)

    #####

    def runConcurrentThread(self):

        try:
            while self.pluginIsShuttingDown == False:
                self.prefsUpdated = False
                self.sleep(0.5)
                updateMeters = t.time() +5
                updateGrid = t.time() + 10
                updateGridFaults = t.time() + 55
                updateSite = t.time() + 30
                updateBatt = t.time() + 35
                updateOnlineSite = t.time()+30

                while self.prefsUpdated ==  False:

                    if t.time() > updateMeters:
                        for dev in indigo.devices.itervalues('self.teslaMeters'):
                            self.updateteslaMeters(dev)
                        updateMeters = t.time() +15

                    if t.time() > updateGrid:
                        for dev in indigo.devices.itervalues('self.teslaGridStatus'):
                            self.updateGridStatus(dev)
                        updateGrid = t.time() + 10

                    if t.time() > updateGridFaults:
                        for dev in indigo.devices.itervalues('self.teslaGridStatus'):
                            self.updateGridFaults(dev)
                        updateGridFaults = t.time() + 120

                    if t.time() > updateSite:
                        for dev in indigo.devices.itervalues('self.teslaSite'):
                            self.updateSiteInfo(dev)
                            # This can take up to 10 second to return
                            # Hangs the whole plugin - could thread it - but no worth the bother
                            #self.updateSitemaster(dev)
                        updateSite = t.time() + 600

                    if t.time() > updateBatt:
                        for dev in indigo.devices.itervalues('self.teslaBattery'):
                            self.updateBattery(dev)
                            if t.time() > updateOnlineSite and self.allowOnline:
                                self.parseonlineSiteInfo(dev)
                                updateOnlineSite = updateOnlineSite + 600
                        updateBatt = t.time() + 60

                    self.sleep(1)

        except self.StopThread:
            self.debugLog(u'Restarting/or error. Stopping  thread.')
            pass


    def updateteslaMeters(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Meters Called')
        meters = self.sendcommand('meters/aggregates')
        if meters is not None and meters !='Offline':
            self.fillmetersinfo(meters, dev)
        return

    def updateGridStatus(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Grid Status Called')
        gridstatus = self.sendcommand('system_status/grid_status')
        if gridstatus is not None and gridstatus !='Offline':
            self.fillgridstatusinfo(gridstatus, dev)
        return

    def updateGridFaults(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Grid Faults Called')
        gridfaults = self.sendcommand('system_status/grid_faults')
        if gridfaults is not None and gridfaults !='Offline':
            self.fillgridfaults(gridfaults, dev)
        return

# Below not used and not compatible wth 1.20.0 and above Tesla Software
    def updateSitemaster(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Site Master Called')
        sitemaster = self.sendcommand('sitemaster')
        if sitemaster is not None and sitemaster !='Offline':
            self.fillsitemaster(sitemaster, dev)
        return

    def updateBattery(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Battery Called')
        battery = self.sendcommand('system_status/soe')
        if battery is not None and battery !='Offline':
            self.fillbatteryinfo(battery, dev)
        return

    def updateSiteInfo(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Site Info Called')
        siteinfo = self.sendcommand('site_info')
        if siteinfo is not None and siteinfo !='Offline':
            self.fillsiteinfo(siteinfo, dev)
        return


    def shutdown(self):
        if self.debugextra:
            self.debugLog(u"shutdown() method called.")

    def startup(self):
        if self.debugextra:
            self.debugLog(u"Starting Plugin. startup() method called.")


    def validatePrefsConfigUi(self, valuesDict):
        if self.debugextra:
            self.debugLog(u"validatePrefsConfigUi() method called.")

        error_msg_dict = indigo.Dict()

        # self.errorLog(u"Plugin configuration error: ")
        # also allow retesting on reopening
        valuesDict['loginOK'] = False
        return True, valuesDict


    def toggleDebugEnabled(self):
        """ Toggle debug on/off. """


        self.logger.debug(u"toggleDebugEnabled() method called.")

        if self.logLevel == int(logging.INFO):
            self.debug = True
            self.pluginPrefs['showDebugInfo'] = True
            self.pluginPrefs['showDebugLevel'] = int(logging.DEBUG)
            self.logger.info(u"Debugging on.")
            self.logger.debug(u"Debug level: {0}".format(self.logLevel))
            self.logLevel = int(logging.DEBUG)
            self.logger.debug(u"New logLevel = " + str(self.logLevel))
            self.indigo_log_handler.setLevel(self.logLevel)

        else:
            self.debug = False
            self.pluginPrefs['showDebugInfo'] = False
            self.pluginPrefs['showDebugLevel'] = int(logging.INFO)
            self.logger.info(u"Debugging off.  Debug level: {0}".format(self.logLevel))
            self.logLevel = int(logging.INFO)
            self.logger.debug(u"New logLevel = " + str(self.logLevel))
            self.indigo_log_handler.setLevel(self.logLevel)

    # Generate Devices
    def generateTeslaDevices(self, valuesDict):
        if self.debugextra:
            self.debugLog(u'generate Devices run')
        try:
            # check Gatewway and IP up

            check = self.sendcommand('site_info/site_name')
            self.logger.debug(unicode(check))
            if check is None or check=='Offline':
                # Connection
                self.logger.info(u'Connection cannot be Established')
                valuesDict['loginOK'] = False
                return valuesDict

            # Generate and Check Site Info
            siteinfo = self.sendcommand('site_info')
            self.logger.debug(unicode(siteinfo))
            if siteinfo is not None and siteinfo !='Offline':
                devFound = False
                for device in indigo.devices.iter('self.teslaSite'):
                    devFound = True
                if devFound == False:
                    # no existing device - create one
                    self.logger.info(u'Creating Tesla Site Info Device')
                    device = indigo.device.create(address='Tesla Site Info', deviceTypeId='teslaSite', name='Tesla Site Info', protocol=indigo.kProtocol.Plugin, folder='Tesla Battery Gateway')
                    self.sleep(0.3)
                # Fill Site with data
                self.fillsiteinfo(siteinfo, device)
            # Next Device Battery
            battery = self.sendcommand('system_status/soe')
            self.logger.debug(unicode(battery))
            if battery is not None and battery !='Offline':
                devFound = False
                for device in indigo.devices.iter('self.teslaBattery'):
                    devFound = True

                if devFound == False:
                    # no existing device - create one
                    self.logger.info(u'Creating Tesla Battery Device')
                    device = indigo.device.create(address='Tesla Battery', deviceTypeId='teslaBattery',
                                                  name='Tesla Battery', protocol=indigo.kProtocol.Plugin,
                                                  folder='Tesla Battery Gateway')
                    self.sleep(0.3)
                # Fill Site with data
                self.fillbatteryinfo(battery, device)

            # Next Grid Status Device
            gridstatus = self.sendcommand('system_status/grid_status')
            #self.logger.debug(unicode(gridstatus))
            if gridstatus is not None and gridstatus !='Offline':
                devFound = False
                for device in indigo.devices.iter('self.teslaGridStatus'):
                    devFound = True

                if devFound == False:
                    # no existing device - create one
                    self.logger.info(u'Creating Tesla Grid Status Device')
                    device = indigo.device.create(address='Tesla Grid Status', deviceTypeId='teslaGridStatus',
                                                  name='Tesla Grid Status', protocol=indigo.kProtocol.Plugin,
                                                  folder='Tesla Battery Gateway')
                    self.sleep(0.3)
                # Fill Site with data
                self.fillgridstatusinfo(gridstatus, device)

                # Next Grid Meters Device

            meters = self.sendcommand('meters/aggregates')
            #self.logger.debug(unicode(meters))
            if meters is not None and meters !='Offline':
                devFound = False
                for device in indigo.devices.iter('self.teslaMeters'):
                    devFound = True
                if devFound == False:
                    # no existing device - create one
                    self.logger.info(u'Creating Tesla Meters Device')
                    device = indigo.device.create(address='Tesla Meters', deviceTypeId='teslaMeters',
                                                  name='Tesla Meters', protocol=indigo.kProtocol.Plugin,
                                                  folder='Tesla Battery Gateway')
                    self.sleep(0.3)
                # Fill Site with data
                self.fillmetersinfo(meters, device)
            #now fill with data
            self.sleep(2)

        except Exception as error:
            self.logger.exception(u'Exception within generate Devices'+unicode(error.message))


## Check Connection
    def testConnection(self, valuesDict):
        if self.debugextra:
            self.debugLog(u'check Connection run')
        try:
            # check Gatewway and IP up

            self.serverip = valuesDict['ipAddress']
            check = self.sendcommand('site_info/site_name')
            self.logger.debug(unicode(check))
            if check is None or check == 'Offline':
                # Connection
                self.logger.debug(u'Connection cannot be Established')
                valuesDict['loginOK'] = False
            else:
                valuesDict['loginOK'] = True

            return valuesDict

        except Exception as error:
            self.errorLog(u'error within checkConnection'+unicode(error.message))
    ##
    def sendcommandslowtimeout(self, cmd):

        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return
        try:
            self.url = "http://" + str(self.serverip) + '/api/'+ str(cmd)
            if self.debugextra:
                self.logger.debug(u'sendcommand called')

            r = requests.get(self.url, timeout=10)

            if r.status_code == 502:
                self.logger.debug(u'Status code'+unicode(r.status_code) )
                self.logger.debug(u'Text :'+unicode(r.text))  #r.text
                self.logger.debug(u'Error Running command.  ?Powerwall offline')
                return 'Offline'
            if r.status_code != 200:
                self.logger.debug(u'Status code'+unicode(r.status_code) )
                self.logger.debug(u'Text :'+unicode(r.text))  #r.text
                self.logger.debug(u'Error Running command')
                return 'Offline'
            else:
                if self.debugextra:
                    self.logger.debug(u'SUCCESS Text :' + unicode(r.text))

            if self.debugextra:
                self.logger.debug(u'sendcommand r.json result:'+ unicode(r.json()))

            return r.json()

        except requests.exceptions.Timeout:
            self.logger.debug(u'sendCommand has timed out and cannot connect to Gateway.')
            self.sleep(5)
            pass
        except requests.exceptions.ConnectionError:
            self.logger.debug(u'sendCommand has ConnectionError and cannot connect to Gateway.')
            self.sleep(5)
            pass
    ## API Calls
    # def sendcommand(self, cmd):
    #     # change to threading given CURL and timeouts.. sigh...
    #     SendCommand = threading.Thread(target=self.Threadsendcommand,
    #                                        args=[self, cmd])
    #     timerkill= Timer(3,SendCommand.kill)
    #     try:
    #         SendCommand.start()
    #
    #         SendCommand.join(10)

    def killcurl(self, cmd, f):
    # call this to report timeouts from subprocess curl to Indigo
        if self.debugextra:
            self.logger.debug(u'TimeOut for Curl Subprocess. Called command:'+unicode(cmd))
        f.kill()
###
###  New Online Changes..
###
#     def rand_str(self, chars=43):
#         letters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "-" + "_"
#         return "".join(random.choice(letters) for i in range(chars))
#
#     def authUrl(self):
#         print "getting url"
#         getVars = {'client_id': 'ownerapi',
#                    'code_challenge': self.challengeSum,
#                    'code_challenge_method' : "S256",
#                    'redirect_uri' : "https://auth.tesla.com/void/callback",
#                    'response_type' : "code",
#                    'scope' : "openid email offline_access",
#                    'state' : "tesla_exporter"
#         }
#         url = 'https://auth.tesla.com/oauth2/v3/authorize'
#
#         # Python 2:
#         result = url + "?" + urllib.urlencode(getVars)
#         self.logger.debug(result)
#         return result
#
#     def authenticate_new(self, params=None):
#         ## from here with thanks!
#         ## https://github.com/fkhera/powerwallCloud/blob/master/powerwallBackup.py
#
#         try:
#             session = requests.Session()
#             self.logger.debug( "authenticate method")
#             auth_url = self.authUrl();
#             UA = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"
#             X_TESLA_USER_AGENT = "TeslaApp/3.10.9-433/adff2e065/android/10"
#             headers = {
#                 "User-Agent": UA,
#                 "x-tesla-user-agent": X_TESLA_USER_AGENT,
#                 "X-Requested-With": "com.teslamotors.tesla",
#             }
#             resp = session.get(auth_url, headers=headers)
#
#             csrf = re.search(r'name="_csrf".+value="([^"]+)"', resp.text).group(1)
#             transaction_id = re.search(r'name="transaction_id".+value="([^"]+)"', resp.text).group(1)
#
#             data = {
#                 "_csrf": csrf,
#                 "_phase": "authenticate",
#                 "_process": "1",
#                 "transaction_id": transaction_id,
#                 "cancel": "",
#                 "identity": self.username,
#                 "credential": self.password,
#             }
#             self.logger.debug( "Opening session with login")
#             self.logger.debug(unicode(auth_url))
#             self.logger.debug(unicode(headers))
#             self.logger.debug(unicode(data))
#             # Important to say redirects false cause this will result in 302 and need to see next data
#             resp = session.post(auth_url, headers=headers, data=data, allow_redirects=False)
#             # Determine if user has MFA enabled
#             # In that case there is no redirect to `https://auth.tesla.com/void/callback` and app shows new form with Passcode / Backup Passcode field
#             is_mfa = True if resp.status_code == 200 and "/mfa/verify" in resp.text else False
#
#             self.logger.debug( "isMFA: " + str(is_mfa) )
#
#             if is_mfa:
#                 getVars = {'transaction_id': transaction_id}
#                 url = 'https://auth.tesla.com/oauth2/v3/authorize/mfa/factors'
#                 mfaUrl = url + "?" + urllib.urlencode(getVars)
#                 resp = session.get(mfaUrl, headers=headers)
#                 # {
#                 #     "data": [
#                 #         {
#                 #             "dispatchRequired": false,
#                 #             "id": "41d6c32c-b14a-4cef-9834-36f819d1fb4b",
#                 #             "name": "Device #1",
#                 #             "factorType": "token:software",
#                 #             "factorProvider": "TESLA",
#                 #             "securityLevel": 1,
#                 #             "activatedAt": "2020-12-07T14:07:50.000Z",
#                 #             "updatedAt": "2020-12-07T06:07:49.000Z",
#                 #         }
#                 #     ]
#                 # }
#                 self.logger.debug(resp.text)
#                 factor_id = resp.json()["data"][0]["id"]
#
#                 # Can use Passcode
#                 data = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": "YOUR_PASSCODE"}
#                 resp = session.post("https://auth.tesla.com/oauth2/v3/authorize/mfa/verify", headers=headers, json=data)
#                 # ^^ Content-Type - application/json
#                 self.logger.debug(resp.text)
#                 # {
#                 #     "data": {
#                 #         "id": "63375dc0-3a11-11eb-8b23-75a3281a8aa8",
#                 #         "challengeId": "c7febba0-3a10-11eb-a6d9-2179cb5bc651",
#                 #         "factorId": "41d6c32c-b14a-4cef-9834-36f819d1fb4b",
#                 #         "passCode": "985203",
#                 #         "approved": true,
#                 #         "flagged": false,
#                 #         "valid": true,
#                 #         "createdAt": "2020-12-09T03:26:31.000Z",
#                 #         "updatedAt": "2020-12-09T03:26:31.000Z",
#                 #     }
#                 # }
#                 if "error" in resp.text or not resp.json()["data"]["approved"] or not resp.json()["data"]["valid"]:
#                     raise ValueError("Invalid passcode.")
#
#                 # Can use Backup Passcode
#                 data = {"transaction_id": transaction_id, "backup_code": "ONE_OF_BACKUP_CODES"}
#                 resp = session.post(
#                     "https://auth.tesla.com/oauth2/v3/authorize/mfa/backupcodes/attempt", headers=headers, json=data
#                 )
#                 # ^^ Content-Type - application/json
#                 self.logger.debug(resp.text)
#                 # {
#                 #     "data": {
#                 #         "valid": true,
#                 #         "reason": null,
#                 #         "message": null,
#                 #         "enrolled": true,
#                 #         "generatedAt": "2020-12-09T06:14:23.170Z",
#                 #         "codesRemaining": 9,
#                 #         "attemptsRemaining": 10,
#                 #         "locked": false,
#                 #     }
#                 # }
#                 if "error" in resp.text or not resp.json()["data"]["valid"]:
#                     raise ValueError("Invalid backup passcode.")
#
#                 data = {"transaction_id": transaction_id}
#                 resp = session.post(
#                     "https://auth.tesla.com/oauth2/v3/authorize",
#                     headers=headers,
#                     params=params,
#                     data=data,
#                     allow_redirects=False,
#                 )
#
#             # If not MFA This code plays instead , which is parising location
#             self.logger.debug( "Coming to non MFA flow:" )
#             code_url = resp.headers["location"]
#             self.logger.debug(unicode(code_url))
#             parsed = urlparse.urlparse(code_url)
#             code = urlparse.parse_qs(parsed.query)['code']
#
#             payload = {
#                 "grant_type": "authorization_code",
#                 "client_id": "ownerapi",
#                 "code_verifier": self.rand_str(108),
#                 "code": code,
#                 "redirect_uri": "https://auth.tesla.com/void/callback",
#             }
#
#             self.logger.debug(unicode(headers))
#             self.logger.debug(unicode(payload))
#
#             resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=headers, json=payload)
#             access_token = resp.json()["access_token"]
#
#             headers["authorization"] = "bearer " + access_token
#             payload = {
#                 "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
#                 "client_id": self.TESLA_CLIENT_ID,
#             }
#             resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=headers, json=payload)
#             owner_access_token = resp.json()["access_token"]
#
#             self.pairingToken = owner_access_token
#             self.auth_header = {'Authorization': 'Bearer ' + self.pairingToken}
#
#         except:
#             # printing stack trace
#             self.logger.exception("Exception in new Authenicate")
#
# ######


    def gen_params(self):
        verifier_bytes = os.urandom(86)
        code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=")
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
        state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
        return code_verifier, code_challenge, state

    # Either return a valid TeslaToken of None if login did fail
    def GetTokenFromLoginPW(self, teslalogin, teslapw):

        try:
            # see https://tesla-api.timdorr.com/api-basics/authentication for new api mandatory since feb 2021
            # Code inspired from https://github.com/enode-engineering/tesla-oauth2/blob/main/tesla.py

            self.logger.debug("GetTokenfromloginPW called.")
            # tesla client id and secret which are everywhere on internet
            CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
            # Avoid setting a User-Agent header that looks like a browser (such as Chrome or
            # Safari). The SSO service has protections in place that will require executing
            # JavaScript if a browser-like user agent is detected
            UA = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"
            X_TESLA_USER_AGENT = "TeslaApp/3.10.9-433/adff2e065/android/10"

            # Subsequent requests to the SSO service will require a "code verifier" and
            # "code challenge". These are a random 86-character alphanumeric string and
            # its SHA-256 hash encoded in URL-safe base64 (base64url).
            # You will also need a stable state value for requests, which is a random
            # string of any length

            headers = {
                "User-Agent": UA,
                "x-tesla-user-agent": X_TESLA_USER_AGENT,
                "X-Requested-With": "com.teslamotors.tesla",
            }

            # Step 1: Obtain the login page
            code_verifier, code_challenge, state = self.gen_params()

            # The request is made with a redirect_url of
            # "https://auth.tesla.com/void/callback", which is a non-existent page
            params = (
                ("client_id", "ownerapi"),
                ("code_challenge", code_challenge),
                ("code_challenge_method", "S256"),
                ("redirect_uri", "https://auth.tesla.com/void/callback"),
                ("response_type", "code"),
                ("scope", "openid email offline_access"),
                ("prompt","login"),
                ("audience",""),
                ("locale","en-US"),
                ("state", "tesla_explorer"),
            )

            self.logger.debug(unicode(headers))
            self.logger.debug(unicode(params))

            ## add to url
            urltouse = "https://auth.tesla.com/oauth2/v3/authorize" + "?" + urllib.urlencode(params)

            session = requests.Session()
            #resp = session.get("https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params, timeout=15)
            resp = session.get(urltouse, headers=headers,timeout=15)
            if not (resp.ok and "<title>" in resp.text):
                self.logger.debug("Returning None")
                self.logger.debug(unicode(resp.text))
                return ""

            #self.logger.debug(unicode(resp.text))
            # Step 2: Obtain an authorization code
            # This will simulate a user submitting the form from the previous request
            # in their browser. Ensure that the hidden <input>s are provided as POST
            # body parameters and the Cookie header is set
            csrf = re.search(r'name="_csrf".+value="([^"]+)"', resp.text).group(1)
            transaction_id = re.search(r'name="transaction_id".+value="([^"]+)"', resp.text).group(1)

            self.logger.debug(u"CSRF="+unicode(csrf))
            self.logger.debug(u"transaction_id="+unicode(transaction_id))

            data = {
                "_csrf": csrf,
                "_phase": "authenticate",
                "_process": "1",
                "transaction_id": transaction_id,
                "cancel": "",
                "identity": teslalogin,
                "credential": teslapw,
            }

            resp = session.post(
                "https://auth.tesla.com/oauth2/v3/authorize", headers=headers, params=params, data=data, timeout=25,
                allow_redirects=False
            )
            # This will respond with a 302 HTTP response code, which will attempt to
            # redirect to the redirect_uri with additional query parameters added.
            # Returns 200 if login/PW is invalid
            if not (resp.ok and (resp.status_code == 302 or "<title>" in resp.text)):
                self.logger.error("Error Here")
                self.logger.error(unicode(resp.text))
                return None

            # Step 3: Exchange authorization code for bearer token
            # This new URL is located in the location header. You should not follow it, as
            # it is non-existent. Instead, you should parse this URL and extract the
            # code query parameter, which is your authorization code.
            code = parse_qs(resp.headers["location"])["https://auth.tesla.com/void/callback?code"]

            # This is a standard OAuth 2.0 Authorization Code exchange. This endpoint uses
            # JSON for the request and response bodies
            #headers = {"User-Agent": UA } #, "x-tesla-user-agent": X_TESLA_USER_AGENT}
            payload = {
                "grant_type": "authorization_code",
                "client_id": "ownerapi",
                "code_verifier": code_verifier.decode("utf-8"),
                "code": code,
                "redirect_uri": "https://auth.tesla.com/void/callback",
            }

            resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=headers, json=payload)
            resp_json = resp.json()
            access_token = resp_json["access_token"]

            # Step 4: Exchange bearer token for access token
            headers["authorization"] = "bearer " + access_token
            payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "client_id": CLIENT_ID,
            }
            resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=headers, json=payload)

            # save our tokens
            tokens = resp.json()

            access_token = tokens["access_token"]
            self.pairingTokenexpires_in = int(tokens["expires_in"])
            self.pairingTokencreated_at = int(tokens["created_at"])
            self.pairingTokenrefresh_token = tokens["refresh_token"]

            self.logger.debug("New Pairing Token Returned:"+unicode(self.pairingToken))
            self.logger.debug("New token Expires_in:"+unicode(self.pairingTokenexpires_in))
            self.logger.debug("New token created_at:"+unicode(self.pairingTokencreated_at))

            return access_token
        except:
            self.logger.exception("Caught Login Exception GetTokenfromLogin")
            return ""

    # Either return a valid TeslaToken of None if login did fail
    def GetTokenFromRefreshToken(self,refreshtoken):
        try:
            self.logger.debug("Get new Token From RefreshToken called.")
            # tesla client id and secret which are everywhere on internet
            CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
            # Avoid setting a User-Agent header that looks like a browser (such as Chrome or
            # Safari). The SSO service has protections in place that will require executing
            # JavaScript if a browser-like user agent is detected
            UA = "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36"
            X_TESLA_USER_AGENT = "TeslaApp/3.10.9-433/adff2e065/android/10"

            headers = {"user-agent": UA, "x-tesla-user-agent": X_TESLA_USER_AGENT}

            ## remove all headers; probably need to change back... once tesla fixes WAF
            headers = {}

            payload = {
                "grant_type": "refresh_token",
                "client_id": "ownerapi",
                "refresh_token": refreshtoken,
                "scope": "openid email offline_access",
            }
            session = requests.Session()

            resp = session.post("https://auth.tesla.com/oauth2/v3/token", headers=headers, json=payload, timeout=15)
            resp_json = resp.json()
            try:
                # will not be found if refresh token was invalid
                access_token = resp_json["access_token"]
                self.logger.debug("** New bearer token received:"+unicode(access_token))
            except KeyError:
                self.logger.debug("Error with Refreshing Token")
                self.logger.debug(unicode(resp.text))
                return None

            # Step 4: Exchange bearer token for access token
            headers["authorization"] = "bearer " + access_token
            payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "client_id": CLIENT_ID,
            }
            resp = session.post("https://owner-api.teslamotors.com/oauth/token", headers=headers, json=payload, timeout=20)

            # save our tokens
            tokens = resp.json()
            self.pairingToken = tokens["access_token"]
            self.pairingTokenexpires_in = int(tokens["expires_in"])
            self.pairingTokencreated_at = int(tokens["created_at"])
            self.pairingTokenrefresh_token = tokens["refresh_token"]
            self.logger.debug("** Refresh Token renew successful")
            self.logger.debug("New Pairing Token Returned:"+unicode(self.pairingToken))
            self.logger.debug("New token Expires_in:"+unicode(self.pairingTokenexpires_in))
            self.logger.debug("New token created_at:"+unicode(self.pairingTokencreated_at))

            return self.pairingToken
        except:
            self.logger.exception("Error in Refresh Token")
            return ""

    def menurefreshToken(self):

        self.logger.debug("Refresh Online Token Called.")
        if self.pairingTokenrefresh_token !="":
            self.logger.debug("RefreshToken:"+unicode(self.pairingTokenrefresh_token))
            self.pairingToken = self.GetTokenFromRefreshToken(self.pairingTokenrefresh_token)

    def getauthTokenOnline(self):
        if self.debugextra:
            self.logger.debug(u'getauthTokenOnline. Number of Active Threads:' + unicode(
                    threading.activeCount()))

        if self.username == "" or self.password =="":
            #self.logger.info("Please set password and username within Plugin Config and try again")
            return
        ####

        if self.allowOnline == False:
            self.logger.info("Online access to Tesla disabled in Plugin Config.")
            return

        if self.pairingToken == "":
            self.logger.debug("Token Blank, Creating new.")
            self.pairingToken = self.GetTokenFromLoginPW(str(self.username),str(self.password))
        else:
            if self.pairingTokenexpires_in !=0 and self.pairingTokencreated_at !=0:
                if datetime.datetime.fromtimestamp(self.pairingTokencreated_at + self.pairingTokenexpires_in / 2) >= datetime.datetime.now():
                    # Token is still valid...
                    self.logger.debug("******** Token Valid, returning token...")
                    return self.pairingToken
                else:
                    self.logger.debug("*********** Token Not Valid, Refreshing with refresh Token")
                    self.pairingToken = self.GetTokenFromRefreshToken(self.pairingTokenrefresh_token)
                    if self.pairingToken == "":
                        self.logger.error("Refresh Token Failed.")
                    return self.pairingToken
            else:
                self.logger.error("ExpiresIn and CreateAt Token 0 - Error at beginning.")
                self.logger.error(u"PairingToken:"+unicode(self.pairingToken)+"    "+ unicode(self.pairingTokencreated_at))
        #self.authenticate_new()
        return


        try:
            self.pairingToken = ""
            url = "https://owner-api.teslamotors.com/oauth/token"
            payload = {"grant_type": "password", "email": str(self.username), "password": str(self.password),
                       "email": str(self.username),
                       "client_secret": "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3",
                       "client_id": "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"}
            headers = {'content-type': 'application/json'}
            self.logger.debug("Calling " + unicode(url) + " with payload:" + unicode(payload))
            r = requests.post(url=url, json=payload, headers=headers, timeout=20, verify=False)

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                jsonResponse = r.json()
                if 'access_token' in jsonResponse:
                    self.logger.debug(jsonResponse['access_token'])
                    self.pairingToken = jsonResponse['access_token']
            else:
                self.logger.debug(unicode(r.text))

                return r.text

            ## pairingToken should exists
            if self.pairingToken == "":
                self.logger.info("No Token received?  Ending.")
                return ""


        except Exception, e:
            self.logger.debug("Error getting Token : " + repr(e))
            self.logger.debug( "Error connecting"+unicode(e.message))
            self.connected = False

    def getauthToken(self):

        if self.debugextra:
            self.logger.debug(u'Thread Send Login Basic called. Number of Active Threads:' + unicode(
                    threading.activeCount()))

        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return

        try:
            self.pairingToken = ""
            url = "https://" + str(self.serverip) + '/api/login/Basic'
            payload = {"username": "installer", "password": str(self.password), "email": str(self.username), "force_sm_off": False }

            self.logger.debug("Calling " + unicode(url) + " with payload:" + unicode(payload))
            r = requests.post(url=url, json=payload, timeout=20, verify=False)

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                jsonResponse = r.json()
                if 'token' in jsonResponse:
                    self.logger.debug(jsonResponse['token'])
                    self.pairingToken = jsonResponse['token']
            else:
                self.logger.error(unicode(r.text))
                return ""

            ## pairingToken should exists
            if self.pairingToken == "":
                self.logger.info("No Token received?  Ending.")
                return ""

        except Exception, e:
            self.logger.debug("Error getting Token : " + repr(e))
            self.logger.debug( "Error connecting"+unicode(e.message))
            self.connected = False

    def changeOperation(self, mode, reservepercentage):

        if self.debugextra:
            self.logger.debug(u'Change Operation called. Number of Active Threads:' + unicode(
                threading.activeCount()))

        ## 1.20.0 Changes to https and SSL for Tesla Software
        # Not backward compatible with others... annoyingly
        # Use CURL to avoid dreaded SSL Error because of library issues
        #  https://forums.indigodomo.com/viewtopic.php?f=107&t=20794
        # curl can't timeout - attempt to use threading

        ## also - using requests here which means incompatibities for some versions of iMAC

        percentage = float("%.1f" % float(reservepercentage))

        #percentage = int(reservepercentage)

        self.logger.debug("Reserve Percentage is :"+unicode(percentage)+" and prior "+unicode(reservepercentage))

        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return False
        try:
            url = "https://" + str(self.serverip) + '/api/operation'
            headers = {'Authorization': 'Bearer '+str(self.pairingToken)  }

            payload = {"real_mode": str(mode), "backup_reserve_percent": percentage}
            self.logger.debug("Calling "+unicode(url)+" with headers:"+unicode(headers)+ " and payload "+unicode(payload))

            r = requests.post(url=url, json=payload, headers=headers,timeout=10, verify=False)

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                jsonResponse = r.json()
                if 'real_mode' in jsonResponse:
                    self.logger.debug(jsonResponse['real_mode'])
                    if str(jsonResponse['real_mode']) != str(mode):
                        self.logger.error(unicode("Did not change mode correctly!!"))
                        return False
                    return True
            else:
                self.logger.error(unicode(r.text))
                return False

        except Exception, e:
            self.logger.exception("Caught Exception setting Operation : " + repr(e))
            self.logger.debug("Exception setting Operation" + unicode(e.message))
            self.connected = False

    def getsiteInfoOnline(self):
        try:
            url = "https://owner-api.teslamotors.com/api/1/energy_sites/"+str(self.energysiteid)+"/site_info"

            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}
            self.logger.debug( "Calling " + unicode(url) + " with headers:" + unicode(headers) )
            r = requests.get(url=url, headers=headers, timeout=10, verify=False)
            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                return r.json()
            else:
                self.logger.error(unicode(r.text))
                return ""
            ##  Now update battery reserve percentage
        except Exception, e:
            self.logger.exception("Caught Exception setting Operation : " + repr(e))
            self.logger.debug("Exception setting Operation" + unicode(e.message))
            return ""

    def changeBatteryReserveOnline(self, reservepercentage):
        if self.debugextra:
            self.logger.debug(u'Change Battery Reserve Alone called. Number of Active Threads:' + unicode(
                threading.activeCount()))
        try:
            percentage = float("%.1f" % float(reservepercentage))

            # percentage = int(reservepercentage)

            self.logger.debug("Reserve Percentage is :" + unicode(percentage) + " and prior " + unicode(reservepercentage))

            url = "https://owner-api.teslamotors.com/api/1/energy_sites/" + str(self.energysiteid) + "/backup"
            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}
            payload = {"backup_reserve_percent": percentage}
            self.logger.debug(
                "Calling " + unicode(url) + " with headers:" + unicode(headers) + " and payload " + unicode(payload))
            r = requests.post(url=url, json=payload, headers=headers, timeout=10, verify=False)
            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                return True
            else:
                self.logger.error(unicode(r.text))
                return False
            ##  Now update battery reserve percentage

        except Exception, e:
            self.logger.exception("Caught Exception setting Operation : " + repr(e))
            self.logger.debug("Exception setting Operation" + unicode(e.message))
            self.connected = False

    def changeOperationOnline(self, mode, reservepercentage, setreserve):

        if self.debugextra:
            self.logger.debug(u'Change OperationOnline called. Number of Active Threads:' + unicode(
                threading.activeCount()))

        try:
            url = "https://owner-api.teslamotors.com/api/1/energy_sites/"+str(self.energysiteid)+"/operation"
            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}
            payload = {"default_real_mode": str(mode)}
            self.logger.debug( "Calling " + unicode(url) + " with headers:" + unicode(headers) + " and payload " + unicode(payload))
            r = requests.post(url=url, json=payload, headers=headers, timeout=10, verify=False)
            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
            else:
                self.logger.error(unicode(r.text))
                return False
            ##  Now update battery reserve percentage

            if setreserve is False:
                self.logger.debug("Skipping Setting Reserve as not selected to do so")
                return True
            try:
                percentage = float("%.1f" % float(reservepercentage))
            except:
                self.logger.error("Error in Setting Percentage - please correct input")
                return

            url = "https://owner-api.teslamotors.com/api/1/energy_sites/" + str(self.energysiteid) + "/backup"
            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}
            payload = {"backup_reserve_percent": percentage}
            self.logger.debug(
                "Calling " + unicode(url) + " with headers:" + unicode(headers) + " and payload " + unicode(payload))
            r = requests.post(url=url, json=payload, headers=headers, timeout=10, verify=False)
            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                return True
            else:
                self.logger.error(unicode(r.text))
                return False
        ##  Now update battery reserve percentage

        except Exception, e:
            self.logger.exception("Caught Exception setting Operation : " + repr(e))
            self.logger.debug("Exception setting Operation" + unicode(e.message))
            self.connected = False

    # def setOperationalMode(self, action):
    #
    #     try:
    #         self.logger.debug(u"setOperational Mode Called as Action.")
    #
    #         self.changingoperationalmode = True
    #
    #         self.logger.debug(unicode(action))
    #
    #         mode = action.props.get('mode',"")
    #         reserve = action.props.get("reserve","")
    #
    #         self.password = self.serialnumber
    #         self.getauthToken()
    #
    #         if self.pairingToken !="":
    #             if self.changeOperation(mode, reserve):  ## success do the rest
    #                 self.setconfigCompleted()
    #         # now cycle Powerwall
    #                 #self.getauthToken()
    #                 self.setsitemasterRun()
    #             else:
    #                 self.logger.info("Set Mode/Change Operation failed.  Check error message.")
    #                 self.logger.info("Restarting Sitemaster.")
    #                 self.setsitemasterRun()
    #
    #         else:
    #             self.logger.info("Failed to get Installer Pairing token.  Serial number should be installer password.")
    #
    #         self.changingoperationalmode = False
    #         return
    #
    #     except Exception, e:
    #         self.logger.exception("Error change Operatonal Mode : " + repr(e))
    #         self.logger.debug("Error change Operation Mode :" + unicode(e.message))
    #         self.changingoperationalmode = False

    def setBatteryReserve(self, action):

        try:
            self.logger.debug(u"setBatteryReserve Mode Online, given 1.50.1. changes Called as Action.")

            self.changingoperationalmode = True
            self.logger.debug(unicode(action))

            reserve = action.props.get("reserve","")

            #self.password = self.serialnumber
            self.getauthTokenOnline()
            #
            if self.pairingToken !="":
                ## need to get site info to know what to change..
                if self.getsiteInfo(self.pairingToken) != "":
                    #self.getsiteInfoOnline()
                    if self.changeBatteryReserveOnline(reserve):  ## success do the rest
                        self.logger.info(u'Battery Reserved changed to with backup reserve:'+unicode(reserve) )
                    else:
                        self.logger.info("Set Mode/Change Battery Reserve Operation failed.  Check debug log /and or error message.")
                        self.logger.info("Trying again, one more time..")
                        self.sleep(3)
                        self.getauthTokenOnline()
                        if self.getsiteInfo(self.pairingToken) != "":
                            if self.changeBatteryReserveOnline(reserve):  ## success do the rest
                                self.logger.info(u'Battery Reserved changed to with backup reserve:' + unicode(reserve))
                            else:
                                self.logger.info(  "Set Mode/Change Battery Reserve Operation failed Again, giving up.  Check debug log /and or error message.")
                else:
                    self.logger.info(u'Energy Site Info ID not found/returned..')

                # revoke token
                self.revokeToken()
                self.pairingToken=""

            else:
                self.logger.info("Failed to get Installer Pairing token.  Serial number should be installer password.")

            self.changingoperationalmode = False
            return

        except Exception, e:
            self.logger.exception("Error change Operatonal Mode : " + repr(e))
            self.logger.debug("Error change Operation Mode :" + unicode(e.message))
            self.changingoperationalmode = False

    def parseonlineSiteInfo(self, device):
        self.logger.debug("parse Online Site Info for usefulness...")

        try:
            self.getauthTokenOnline()
            #
            if self.pairingToken != "":
                ## need to get site info to know what to change..
                if self.getsiteInfo(self.pairingToken) != "":
                    data = self.getsiteInfoOnline()
                    if data == "":
                        self.logger.debug("No online site data obtained")
                        return

                    backupreservepercentage = int(0)
                    stormmode = False
                    batterymode = ""
                    version = ""
                    batterycount = 0

                    if 'response' in data:
                        if 'backup_reserve_percent' in data['response']:
                            backupreservepercentage = data['response']['backup_reserve_percent']
                        if 'default_real_mode' in data['response']:
                            batterymode = data['response']['default_real_mode']
                        if 'user_settings' in data['response']:
                            if 'storm_mode_enabled' in data['response']['user_settings']:
                                stormmode = data['response']['user_settings']['storm_mode_enabled']
                        if 'version' in data['response']:
                            version = data['response']['version']
                        if 'battery_count' in data['response']:
                            batterycount = data['response']['battery_count']


                    stateList = [
                            {'key': 'batteryMode', 'value': batterymode},
                            {'key': 'batteryReservePercentage', 'value': backupreservepercentage},
                            {'key': 'stormMode', 'value': stormmode},
                             {'key': 'batteryCount', 'value': batterycount},
                            {'key': 'version', 'value': version},
                                  ]
                    device.updateStatesOnServer(stateList)
                    device.updateStateOnServer('deviceIsOnline', value=True, uiValue="Online")
                    update_time = t.strftime('%c')
                    device.updateStateOnServer('deviceLastUpdated', value=str(update_time))

        except Exception, e:
            self.logger.exception("Error Getting Online Site Info : " + repr(e))
            self.logger.debug("Error Getting Online Site Info" + unicode(e.message))
            self.changingoperationalmode = False


    def setOperationalModeOnline(self, action):

        try:
            self.logger.debug(u"setOperational Mode Online, given 1.50.1. changes Called as Action.")

            self.changingoperationalmode = True
            self.logger.debug(unicode(action))

            mode = action.props.get('mode',"")
            setreserve = action.props.get('setbatteryreserve', False)
            reserve = action.props.get("reserve","")

            #self.password = self.serialnumber
            datareturned = self.getauthTokenOnline()
            #
            if self.pairingToken !="":
                ## need to get site info to know what to change..
                if self.getsiteInfo(self.pairingToken) != "":

                    self.getsiteInfoOnline()
                    if self.changeOperationOnline(mode, reserve, setreserve):  ## success do the rest
                        if setreserve:
                            self.logger.info(u'Successfully changed to mode:'+unicode(mode)+u" with backup reserve:"+unicode(reserve))
                        else:
                            self.logger.info(  u'Successfully changed to mode:' + unicode(mode) + u" with backup reserve not changed")

                    else:
                        self.logger.info("Set Mode/Change Operation failed.  Check error message, and/or debug log.")
                        self.logger.info("Trying again, one more time...")
                        self.sleep(3)
                        self.getauthTokenOnline()
                        if self.getsiteInfo(self.pairingToken) != "":
                            if self.changeOperationOnline(mode, reserve, setreserve):  ## success do the rest
                                if setreserve:
                                    self.logger.info(u'Successfully changed to mode:' + unicode(mode) + u" with backup reserve:" + unicode(reserve))
                                else:
                                    self.logger.info(u'Successfully changed to mode:' + unicode(mode) + u" with backup reserve not changed")
                            else:
                                self.logger.info(u"Set Mode/Change Operation failed Again, giving up.  Please check debug log/error message received.")
                else:
                    self.logger.info(u'Energy Site Info ID not found/returned..')

                # revoke token
                self.revokeToken()
                self.pairingToken=""

            else:
                self.logger.info("Failed to get Installer Pairing token.  .")
                if 'authorization_required' in datareturned:
                    self.logger.info("Check Username and Password.  Authenicated Fails for those Given")
                    self.logger.info("Should be your online Tesla Account Username/Password as uses online API for control")
            self.changingoperationalmode = False
            return

        except Exception, e:
            self.logger.exception("Error change Operatonal Mode : " + repr(e))
            self.logger.debug("Error change Operation Mode :" + unicode(e.message))
            self.changingoperationalmode = False

    def revokeToken(self):

        if self.debugextra:
            self.logger.debug(u'revokeToken - Called:' )

        try:
            url = "https://owner-api.teslamotors.com/oauth/revoke"
            payload = {'token': str(self.pairingToken)}

            headers = {'content-type': 'application/json'}


            self.logger.debug("Calling " + unicode(url) + " with payload:" + unicode(payload))
            r = requests.post(url=url, json=payload, headers=headers, timeout=20, verify=False)

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                jsonResponse = r.json()
            else:
                self.logger.debug("revoke Token Error:"+unicode(r.text)+" and return code:"+unicode(r.status_code))
                self.logger.debug(unicode(r.text))
                return ""

        except Exception, e:
            self.logger.exception("Error getsiteInfo Operation : " + repr(e))
            self.logger.debug("Error getsiteInfo Operation" + unicode(e.message))

    def getsiteInfo(self, localtoken):

        if self.debugextra:
            self.logger.debug(u'getsiteInfo - Called:' )

        try:
            url = "https://owner-api.teslamotors.com/api/1/products"
            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}

            self.logger.debug("Calling " + unicode(url) + " with headers:" + unicode(headers) )

            r = requests.get(url=url, timeout=15, headers=headers, verify=False)

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                jsonResponse = r.json()
                if 'response' in jsonResponse:
                    for results in jsonResponse['response']:
                        if 'energy_site_id' in results:
                            self.energysiteid = results['energy_site_id']
                            self.logger.debug("Energy Site ID:"+unicode(self.energysiteid))
                            return self.energysiteid
            else:
                self.logger.error("getSiteInfo Error:"+unicode(r.text)+" and return code:"+unicode(r.status_code))
                self.logger.error(unicode(r.text))
                self.energysiteid =""
                return ""

        except Exception, e:
            self.logger.exception("Error getsiteInfo Operation : " + repr(e))
            self.logger.debug("Error getsiteInfo Operation" + unicode(e.message))

    def setsitemasterRun(self):

        if self.debugextra:
            self.logger.debug(u'setSiteMasterRun - 0.5.2 called. Number of Active Threads:' + unicode(
                threading.activeCount()))

        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return
        try:
            url = "https://" + str(self.serverip) + '/api/sitemaster/run'
            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}

            self.logger.debug(
                "Calling " + unicode(url) + " with headers:" + unicode(headers) )

            r = requests.get(url=url, timeout=10, headers=headers, verify=False)

            if r.status_code == 202:
                self.logger.debug(unicode(r.text))
                self.logger.info("Sitemaster now Running again,following command success")
            else:
                self.logger.error("Sitemaster Error:"+unicode(r.text)+" and return code:"+unicode(r.status_code))
                self.logger.error(unicode(r.text))
                return ""


        except Exception, e:
            self.logger.exception("Error setconfigComplete Operation : " + repr(e))
            self.logger.debug("Error setting Operation" + unicode(e.message))


    def setconfigCompleted(self):

        if self.debugextra:
            self.logger.debug(u'setConfigCompleted called. Number of Active Threads:' + unicode(
                threading.activeCount()))

        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return
        try:
            url = "https://" + str(self.serverip) + '/api/config/completed'
            headers = {'Authorization': 'Bearer ' + str(self.pairingToken)}
            self.logger.debug( "Calling " + unicode(url) + " with headers:" + unicode(headers) )

            r = requests.get(url=url, timeout=10, headers=headers, verify=False)

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                self.logger.debug("Set Config Successfully run")
            else:
                self.logger.error("Setconfig Error"+ unicode(r.text)+ " return code:"+unicode(r.status_code))
                return ""

        except Exception, e:
            self.logger.exception("Error setconfigComplete Operation : " + repr(e))
            self.logger.debug("Error setting Operation" + unicode(e.message))
            self.connected = False

    def sendcommand(self, cmd):

        if self.debugextra:
            self.logger.debug(u'ThreadSendCOmmand called. Number of Active Threads:' + unicode(
                    threading.activeCount()))

        ## 1.20.0 Changes to https and SSL for Tesla Software
        # Not backward compatible with others... annoyingly
        # Use CURL to avoid dreaded SSL Error because of library issues
        #  https://forums.indigodomo.com/viewtopic.php?f=107&t=20794
        # curl can't timeout - attempt to use threading

        if self.changingoperationalmode:
            self.logger.debug("Changing Operational Mode pausing updating Powerwall")
            return

        if self.batUsername == "" or self.batPassword =="":
            self.logger.info("Please set Battery password and username within Plugin Config and try again. This is now required.")
            return

        headers = { 'Content-Type': 'application/json', }
        # data = ' {"username":"customer", "password":'+str(self.batPassword)+', "email": "customer@customer.domain",
        #           "force_sm_off": false} '
        data = '{"username":"customer","password":"'+str(self.batPassword)+'","email":"'+str(self.batUsername)+'","force_sm_off":false}'

       # self.logger.error(unicode(data))
        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return
        try:
            self.url = "https://" + str(self.serverip) + '/api/'+ str(cmd)
            if self.sessionData == "" or time.time() >=self.sessiontimeStamp:
                self.logger.debug("Setting up New Token Session Data")
                self.sessionReq = requests.Session()   ## renew session
                self.sessionData = self.sessionReq.post('https://' + self.serverip + '/api/login/Basic', headers=headers, data=data, verify=False, timeout=30)
                if self.sessionData.status_code == 200:
                    self.logger.debug(unicode(self.sessionData.text))
                    jsonsessionData = json.loads(self.sessionData.text)
                    if 'loginTime' in jsonsessionData:
                        self.logger.debug("LoginTime: "+unicode(jsonsessionData['loginTime']))
                        timetouse = jsonsessionData['loginTime'].split(".")[0]
                        #self.logger.debug(unicode(timetouse))
                        self.sessiontimeStamp = int(time.mktime(time.strptime(timetouse,"%Y-%m-%dT%H:%M:%S")))+ (60*60)  #1 hour update
                        self.logger.debug("Date TimeStamp 1 hour in future = "+unicode(self.sessiontimeStamp)       )
                else:
                    self.logger.error(unicode(self.sessionData.text))
                    self.sessionData = ""
                    return "Offline"

            if self.debugextra:
                self.logger.debug(u'sendcommand called: for url:'+unicode(self.url)+" with data:"+unicode(data))
            r = self.sessionReq.get(self.url, verify=False, timeout=10)
            #self.logger.info(r.text)
            #return json.loads(r.text)
            #return 'Offline'

            if r.status_code == 200:
                self.logger.debug(unicode(r.text))
                return json.loads(r.text)
            else:
                self.logger.error(unicode(r.text))
                return "Offline"

            if self.debugextra:
                self.logger.debug(u'sendcommand r.json result:'+ unicode(json.loads(out)))

            return json.loads(r.text)

        except IOError as ex:
            self.logger.debug(u'sendCommand has timed out and cannot connect to Gateway.')
            self.logger.debug(u'Error:'+unicode(ex)+":"+unicode(ex.message))
            self.sleep(5)
            self.sessionData =""
            return 'Offline'

    # Fill Device with Info
    def fillsiteinfo(self, data, device):
        self.logger.debug(u'fillsiteinfo called')
        try:
            if self.debugextra:
                self.logger.debug(u'data:'+unicode(data))
            site_name=''
            timezone=''
            nominal_system_energy_kW = ''
            nominal_system_power_kW =''
            grid_code=''
            grid_voltage_setting=''
            grid_freq_setting =''
            grid_phase_setting=''
            country=''
            state=''
            region = ''
            frequency = ''
            utility = ''
            distributor = ''
    #        data ={u'nominal_system_power_kW': 10, u'site_name': u'Home Energy Gateway', u'max_site_meter_power_kW': 1000000000,
    #               u'grid_code': {u'country': u'Australia', u'region': u'ASS4777.2', u'retailer': u'*', u'grid_voltage_setting': 230, u'grid_code': u'50Hz_230V_1_ASNZS4777.2:2015_AU',
     #                             u'state': u'New South Wales', u'grid_phase_setting': u'Single', u'grid_freq_setting': 50, u'distributor': u'Ausgrid', u'utility': u'*'},
     #              u'min_site_meter_power_kW': -1000000000, u'max_system_power_kW': 0, u'nominal_system_energy_kWh': 13.5, u'timezone': u'Australia/Sydney', u'max_system_energy_kWh': 0}

            # data = {u'nominal_system_power_kW': 10, u'site_name': u'Home Energy Gateway', u'measured_frequency': 60, u'max_site_meter_power_kW': 1000000000, u'grid_code': {u'country': u'United States', u'region': u'IEEE1547:2003', u'retailer': u'*', u'grid_voltage_setting': 240, u'grid_code': u'60Hz_240V_s_IEEE1547_2003', u'state': u'Florida', u'grid_phase_setting': u'Split', u'grid_freq_setting': 60, u'distributor': u'*', u'utility': u'Florida Power & Light, a part of NextEra Energy'}, u'min_site_meter_power_kW': -1000000000, u'max_system_power_kW': 0, u'nominal_system_energy_kWh': 13.5, u'timezone': u'America/New_York', u'max_system_energy_kWh': 0}

            if 'site_name' in data:
                site_name = data['site_name']
            if 'timezone' in data:
                timezone = data['timezone']
            if 'measured_frequency' in data:
                frequency = data['measured_frequency']
            if 'nominal_system_energy_kWh' in data:
                nominal_system_energy_kW = data['nominal_system_energy_kWh']
            if 'nominal_system_power_kW' in data:
                nominal_system_power_kW = data['nominal_system_power_kW']
            if 'grid_code' in data:
                grid_code_data = data['grid_code']
                if 'grid_code' in grid_code_data:
                    grid_code = grid_code_data['grid_code']
                if 'grid_voltage_setting' in grid_code_data:
                    grid_voltage_setting = grid_code_data['grid_voltage_setting']
                if 'grid_freq_setting' in grid_code_data:
                    grid_freq_setting = grid_code_data['grid_freq_setting']
                if 'grid_phase_setting' in grid_code_data:
                    grid_phase_setting = grid_code_data['grid_phase_setting']
                if 'country' in grid_code_data:
                    country = grid_code_data['country']
                if 'state' in grid_code_data:
                    state = grid_code_data['state']
                if 'region' in grid_code_data:
                    region = grid_code_data['region']
                if 'utility' in grid_code_data:
                    utility = grid_code_data['utility']
                if 'distributor' in grid_code_data:
                    distributor = grid_code_data['distributor']

            stateList = [
                {'key': 'sitename', 'value': site_name},
                {'key': 'timezone', 'value': timezone},
                {'key': 'nominalEnergy', 'value': nominal_system_energy_kW},
                {'key': 'gridCode', 'value': grid_code},
                {'key': 'gridVoltage', 'value': grid_voltage_setting},
                {'key': 'gridFreq', 'value': grid_freq_setting},
                {'key': 'gridPhase', 'value': grid_phase_setting},
                {'key': 'country', 'value': country},
                {'key': 'nominalPower', 'value': nominal_system_power_kW},
                {'key': 'frequency', 'value': frequency},
                {'key': 'utility', 'value': utility},
                {'key': 'distributor', 'value': distributor},
                {'key': 'state', 'value': state},
                {'key': 'region', 'value': region}
                ]
            device.updateStatesOnServer(stateList)
            device.updateStateOnServer('deviceIsOnline', value=True, uiValue="Online")
            device.updateStateImageOnServer(indigo.kStateImageSel.EnergyMeterOn)
            update_time = t.strftime('%c')
            device.updateStateOnServer('deviceLastUpdated', value=str(update_time))
            return

        except:
            self.logger.exception(u'Caught Exception in fillsiteinfo')
            device.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")
            #device.updateStateOnServer('deviceStatus', value='Offline')
            device.updateStateImageOnServer(indigo.kStateImageSel.EnergyMeterOff)
    ##
    def fillmetersinfo(self, data, device):
        self.logger.debug(u'fillmetersinfo called')
        try:
            # Test data no solar info
            #data = {u'battery': {u'i_a_current': 0, u'energy_imported': 4177440, u'i_b_current': 0, u'instant_power': -10, u'i_c_current': 0, u'instant_reactive_power': 620, u'frequency': 59.985, u'timeout': 1500000000, u'instant_total_current': -0.30000000000000004, u'last_communication_time': u'2020-10-19T15:27:22.590244174-07:00', u'instant_apparent_power': 620.0806399170998, u'instant_average_voltage': 239.25, u'energy_exported': 3704000}, u'load': {u'i_a_current': 0, u'energy_imported': 46553687.08194445, u'i_b_current': 0, u'instant_power': 67.71369113155662, u'i_c_current': 0, u'instant_reactive_power': -157.45170616463744, u'frequency': 60, u'timeout': 1500000000, u'instant_total_current': 0.5649398530514325, u'last_communication_time': u'2020-10-19T15:27:22.586977848-07:00', u'instant_apparent_power': 171.39481830211548, u'instant_average_voltage': 119.86000061035156, u'energy_exported': 0}, u'site': {u'i_a_current': 0, u'energy_imported': 48820683.64353368, u'i_b_current': 0, u'instant_power': 86.91000175476074, u'i_c_current': 0, u'instant_reactive_power': -786.9100036621094, u'frequency': 60, u'timeout': 1500000000, u'instant_total_current': 0, u'last_communication_time': u'2020-10-19T15:27:22.586977848-07:00', u'instant_apparent_power': 791.6948290020048, u'instant_average_voltage': 119.86000061035156, u'energy_exported': 1793556.5615892268}}

           # batterykW = float(data['battery']['instant_power'])/1000
            #If is between 0 and -100 set to Zero
            #if -0.1 <= batterykW <=0.1:
             #   batterykW = 0

            solar_instant_power = float(0)
            grid_instant_power = float(0)
            home_instant_power = float(0)
            battery_instant_power = float(0)
            solarkw = float(0)
            gridkw = float(0)
            homekw = float(0)
            batterykw = float(0)

            if 'solar' in data:
                if 'instant_power' in data['solar']:
                    solar_instant_power = data['solar']['instant_power']
                    solarkw = "{0:0.1f}".format(float(data['solar']['instant_power'])/1000)
            if 'site' in data:
                if 'instant_power' in data['site']:
                    grid_instant_power = data['site']['instant_power']
                    gridkw = "{0:0.1f}".format(float(data['site']['instant_power']) / 1000)
            if 'load' in data:
                if 'instant_power' in data['load']:
                    home_instant_power = data['load']['instant_power']
                    homekw = "{0:0.1f}".format(float(data['load']['instant_power']) / 1000)
            if 'battery' in data:
                if 'instant_power' in data['battery']:
                    battery_instant_power = data['battery']['instant_power']
                    batterykw = "{0:0.1f}".format(float(data['battery']['instant_power']) / 1000)
                    if -0.1 <= batterykw <= 0.1:
                        batterykw = 0

            stateList = [
                {'key': 'Solar', 'value': solar_instant_power},
                {'key': 'Grid', 'value':grid_instant_power},
                {'key': 'Home', 'value': home_instant_power},
                {'key': 'Battery', 'value': battery_instant_power},
                {'key': 'SolarkW', 'value': solarkw},
                {'key': 'GridkW', 'value': gridkw},
                {'key': 'HomekW', 'value': homekw},
                {'key': 'BatterykW', 'value': batterykw}
            ]

            device.updateStatesOnServer(stateList)
            # add this as can't test negatives at momemnt - need rain to stoP!

            batteryCharging = device.states['batteryCharging']
            batteryDischarging = device.states['batteryDischarging']
            sendingtoGrid = device.states['sendingtoGrid']

            try:
                #Grid Usage is essentially the summary
                # don't grid usage True/False unless more than 250 Watts being used or more than -100 being generated
                # Avoids flipping on and off when battery charging pulling etc.
                # Could add user adjustable level?

                if float(grid_instant_power) > 250 :
                    # Pulling something from Grid
                    device.updateStateOnServer('gridUsage', value=True)
                elif float(grid_instant_power) < -100 :
                    device.updateStateOnServer('gridUsage', value=False)
                    self.logger.debug(u'Grid Usage False')

                if float(battery_instant_power) < -100 :
                # Pulling something from Grid
                    if batteryCharging ==False:
                        self.triggerCheck(device, 'batteryCharging')
                    device.updateStateOnServer('batteryCharging', value=True)
                else:
                    device.updateStateOnServer('batteryCharging', value=False)

                if float(solar_instant_power) > 95:
                    # Solar Generating more than 150 watts
                    device.updateStateOnServer('solarGenerating', value=True)
                else:
                    device.updateStateOnServer('solarGenerating', value=False)

                if float(grid_instant_power) < -100:
                    # Solar Generating more than 150 watts
                    if sendingtoGrid == False:
                        self.triggerCheck(device, 'solarExporting')
                    device.updateStateOnServer('sendingtoGrid', value=True)
                elif float(grid_instant_power) > 100:
                    device.updateStateOnServer('sendingtoGrid', value=False)

                if float(battery_instant_power) > 150:
                    # Solar Generating more than 150 watts
                    if batteryDischarging==False:
                        self.triggerCheck(device, 'batteryDischarging')
                    device.updateStateOnServer('batteryDischarging', value=True)

                else:
                    device.updateStateOnServer('batteryDischarging', value=False)
            except:
                self.logger.info(u'Error in Calculation')
                pass

            device.updateStateOnServer('deviceIsOnline', value=True, uiValue="Online")
            device.updateStateOnServer('deviceStatus', value='Online')
            device.updateStateImageOnServer(indigo.kStateImageSel.EnergyMeterOn)
            update_time = t.strftime('%c')
            device.updateStateOnServer('deviceLastUpdated', value=str(update_time))
            return

        except:
            self.logger.exception(u'Caught Exception in fillsiteinfo')
            device.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")
            device.updateStateOnServer('deviceStatus', value='Offline')
            device.updateStateImageOnServer(indigo.kStateImageSel.EnergyMeterOff)

    def fillbatteryinfo(self, data, device):
        self.logger.debug(u'fill battery info called')
        try:

            percentage= float(data['percentage'])
            self.logger.debug(u'Battery Per:'+unicode(percentage))
            device.updateStateOnServer('charge', percentage)
            device.updateStateOnServer('chargeCP', int(percentage))
            if percentage > 95:
                device.updateStateImageOnServer(indigo.kStateImageSel.BatteryLevelHigh)
            elif percentage > 75:
                device.updateStateImageOnServer(indigo.kStateImageSel.BatteryLevel75)
            elif percentage > 50:
                device.updateStateImageOnServer(indigo.kStateImageSel.BatteryLevel50)
            elif percentage > 25:
                device.updateStateImageOnServer(indigo.kStateImageSel.BatteryLevel25)
            elif percentage < 25:
                self.logger.debug(u'Setting to Battery Level Low Image')
                device.updateStateImageOnServer(indigo.kStateImageSel.BatteryLevelLow)

            device.updateStateOnServer('deviceIsOnline', value=True, uiValue="Online")
            update_time = t.strftime('%c')
            device.updateStateOnServer('deviceLastUpdated', value=str(update_time))

        except:
            self.logger.exception(u'Caught Exception in Fillbattery Info')
            device.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")
            device.updateStateImageOnServer(indigo.kStateImageSel.BatteryLevelLow)

    def fillgridstatusinfo(self, data, device):
        self.logger.debug(u'fill grid status info called')
        try:
            gridConnected = device.states['gridConnected']

            device.updateStateOnServer('gridStatus', value=data['grid_status'])

            if data['grid_status'] == 'SystemGridConnected':
                # Grid must be restored
                if gridConnected ==False:
                    self.triggerCheck(device, 'gridRestored')
                    update_time = t.strftime('%c')
                    device.updateStateOnServer('timeGridUp', value=str(update_time))
                device.updateStateOnServer('gridConnected', value=True)
            elif data['grid_status'] == 'SystemIslandedActive' :
                if gridConnected == True:
                    self.triggerCheck(device, 'gridLoss')
                    update_time = t.strftime('%c')
                    device.updateStateOnServer('timeGridLoss', value=str(update_time))
                device.updateStateOnServer('gridConnected', value=False)

            device.updateStateOnServer('deviceIsOnline', value=True, uiValue="Online")
            update_time = t.strftime('%c')
            device.updateStateOnServer('deviceLastUpdated', value=str(update_time))

        except:
            self.logger.exception(u'Caught Exception in FillGridStatus Info')
            device.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")

    def fillgridfaults(self, data, device):
        self.logger.debug(u'fill grid faults info called')
        try:
            gridfaults = str(device.states['gridFaults'])

            if str(data) != '[]':
                self.logger.debug(u'Grid Faults -- BLANK --'+unicode(gridfaults))
            if str(data) !=gridfaults and gridfaults != '[]':
                # Data changed
                self.triggerCheck(device,'gridFault')

            device.updateStateOnServer('gridFaults', value=unicode(data))
        except:
            self.logger.exception(u'Caught Exception in Fill Grid faults Info')


    def fillsitemaster(self, data, device):
        self.logger.debug(u'fill grid SiteMaster called')
        try:
            sitemaster = device.states['sitemasterRunning']
            self.logger.debug(u'sitemaster Running Equals:'+unicode(data['running']))

            if data['running'] == 'true':
                # Sitemaster must have started
                if sitemaster == False:
                    self.triggerCheck(device, 'sitemasterOn')
                device.updateStateOnServer('sitemasterRunning', value=True)
            elif data['running'] == 'false' :
                if sitemaster == True:
                    self.triggerCheck(device, 'sitemasterOff')
                device.updateStateOnServer('sitemasterRunning', value=False)

        except:
            self.logger.exception(u'Caught Exception in fillsitemaster Info')
            #device.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")

##################  Trigger

    def triggerStartProcessing(self, trigger):
        self.logger.debug("Adding Trigger %s (%d) - %s" % (trigger.name, trigger.id, trigger.pluginTypeId))
        assert trigger.id not in self.triggers
        self.triggers[trigger.id] = trigger

    def triggerStopProcessing(self, trigger):
        self.logger.debug("Removing Trigger %s (%d)" % (trigger.name, trigger.id))
        assert trigger.id in self.triggers
        del self.triggers[trigger.id]

    def triggerCheck(self, device,  triggertype):

        self.logger.debug('triggerCheck run.  device.id:'+unicode(device.id)+' triggertype:'+unicode(triggertype))
        try:

            if device.states['deviceIsOnline'] == False:
                self.logger.debug(u'Trigger Cancelled as Device is Not Online')
                return

            for triggerId, trigger in sorted(self.triggers.iteritems()):

                self.logger.debug("Checking Trigger %s (%s), Type: %s,  and event : %s" % (trigger.name, trigger.id, trigger.pluginTypeId,  triggertype))
                #self.logger.error(unicode(trigger))
                if trigger.pluginTypeId == "gridLoss" and triggertype =='gridLoss':
                    if self.debugtriggers:
                        self.logger.debug("===== Executing gridLoss Trigger %s (%d)" % (trigger.name, trigger.id))
                    indigo.trigger.execute(trigger)
                elif trigger.pluginTypeId == "gridRestored" and triggertype =='gridRestored':
                    if self.debugtriggers:
                        self.logger.debug("===== Executing Grid Restored Trigger %s (%d)" % (trigger.name, trigger.id))
                    indigo.trigger.execute(trigger)
                elif trigger.pluginTypeId == "batteryCharging" and triggertype =='batteryCharging':
                    if self.debugtriggers:
                        self.logger.debug("===== Executing Battery Starts Charging Trigger %s (%d)" % (trigger.name, trigger.id))
                    indigo.trigger.execute(trigger)
                elif trigger.pluginTypeId == "batteryDischarging" and triggertype =='batteryDischarging':
                    if self.debugtriggers:
                        self.logger.debug("===== Executing Battery Starts Discharging Trigger %s (%d)" % (trigger.name, trigger.id))
                    indigo.trigger.execute(trigger)
                else:
                    if self.debugtriggers:
                        self.logger.debug("Not Run Trigger Type %s (%d), %s" % (trigger.name, trigger.id, trigger.pluginTypeId))
        except:
            self.logger.exception(u'Exception within Trigger Check')
            return


