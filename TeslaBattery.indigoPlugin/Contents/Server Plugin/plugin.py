#! /usr/bin/env python2.6
# -*- coding: utf-8 -*-

"""
Tesla - Battery Control
0.2.2
Prelim Version


"""
import logging
import datetime
import time as t
import urllib2
import os
import shutil
import sys
import requests
import json
import subprocess
import threading
from threading import Timer

from ghpu import GitHubPluginUpdater

try:
    import indigo
except:
    pass

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
        self.logger.info(u"{0:<30} {1}".format("Python Directory:", sys.prefix.replace('\n', '')))
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

        #self.debug = self.pluginPrefs.get('showDebugInfo', False)
        #self.debugLevel = self.pluginPrefs.get('showDebugLevel', "1")
        self.debugextra = self.pluginPrefs.get('debugextra', False)
        self.debugtriggers = self.pluginPrefs.get('debugtriggers', False)
        self.updateFrequency = float(self.pluginPrefs.get('updateFrequency', "24")) * 60.0 * 60.0
        self.next_update_check = t.time()

        self.openStore = self.pluginPrefs.get('openStore', False)
        self.serverip = self.pluginPrefs.get('ipAddress', '')

        self.version = '0.0.0'

        if 'Tesla Battery Gateway' not in indigo.devices.folders:
            indigo.devices.folder.create('Tesla Battery Gateway')
        self.folderId = indigo.devices.folders['Tesla Battery Gateway'].id


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

    def checkForUpdates(self):

        updateavailable = self.updater.getLatestVersion()
        if updateavailable and self.openStore:
            self.logger.info(u'Tesla Battery: Update Checking.  Update is Available.  Taking you to plugin Store. ')
            self.sleep(2)
            self.pluginstoreUpdate()
        elif updateavailable and not self.openStore:
            self.errorLog(u'Tesla Battery: Update Checking.  Update is Available.  Please check Store for details/download.')

    def updatePlugin(self):
        self.updater.update()

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
                while self.prefsUpdated == False:
                    if self.updateFrequency > 0:
                        if t.time() > self.next_update_check:
                            try:
                                self.checkForUpdates()
                                self.next_update_check = t.time() + self.updateFrequency
                            except:
                                self.logger.debug(
                                    u'Error checking for update - ? No Internet connection.  Checking again in 24 hours')
                                self.next_update_check = self.next_update_check + 86400

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
        sitemaster = self.sendcommandslowtimeout('sitemaster')
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
        self.updater = GitHubPluginUpdater(self)

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




    def sendcommand(self, cmd):

        if self.debugextra:
            self.logger.debug(u'ThreadSendCOmmand called. Number of Active Threads:' + unicode(
                    threading.activeCount()))

        ## 1.20.0 Changes to https and SSL for Tesla Software
        # Not backward compatible with others... annoyingly
        # Use CURL to avoid dreaded SSL Error because of library issues
        #  https://forums.indigodomo.com/viewtopic.php?f=107&t=20794
        # curl can't timeout - attempt to use threading


        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return
        try:
            self.url = "https://" + str(self.serverip) + '/api/'+ str(cmd)
            if self.debugextra:
                self.logger.debug(u'sendcommand called')


            f = subprocess.Popen(["curl", '-sk', self.url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            ## below is 3 second timeout...
            timerkill = Timer(3, f.kill)

            try:
                timerkill.start()
            # '-H', str(headers), "-k",
                out, err = f.communicate()
                self.logger.debug(u'HTTPS CURL result:' + unicode(err))
                self.logger.debug(u'ReturnCode:{0}'.format(unicode(f.returncode)))
                self.sleep(0.2)
            finally:
                timerkill.cancel()

            #r = requests.get(self.url, timeout=2)
            if (int(f.returncode) == 0):
                data = json.loads(out)
                if self.debugextra:
                    self.logger.debug(u'SUCCESS Text :' + unicode(data))
                    self.logger.debug(u'Json results:' + unicode(data))
            else:
                self.logger.debug(u'ReturnCode:'+unicode(f.returncode) )
                self.logger.debug(u'Text :'+unicode(f.stderr))  #r.text
                self.logger.debug(u'Error Running command.  ?Powerwall offline')
                return 'Offline'

            if self.debugextra:
                self.logger.debug(u'sendcommand r.json result:'+ unicode(json.loads(out)))

            return json.loads(out)

        except IOError:
            self.logger.debug(u'sendCommand has timed out and cannot connect to Gateway.')
            self.sleep(5)
            pass

    # Fill Device with Info
    def fillsiteinfo(self, data, device):
        self.logger.debug(u'fillsiteinfo called')
        try:
            if self.debugextra:
                self.logger.debug(u'data:'+unicode(data))

            stateList = [
                {'key': 'sitename', 'value': data['site_name']},
                {'key': 'timezone', 'value': data['timezone']},
                {'key': 'nominalEnergy', 'value': data['nominal_system_energy_kWh']},
                {'key': 'gridCode', 'value': data['grid_code']},
                {'key': 'gridVoltage', 'value': data['grid_voltage_setting']},
                {'key': 'gridFreq', 'value': data['grid_freq_setting']},
                {'key': 'gridPhase', 'value': data['grid_phase_setting']},
                {'key': 'country', 'value': data['country']},
                {'key': 'state', 'value': data['state']},
                {'key': 'region', 'value': data['region']}
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
            device.updateStateOnServer('deviceStatus', value='Offline')
            device.updateStateImageOnServer(indigo.kStateImageSel.EnergyMeterOff)
    ##
    def fillmetersinfo(self, data, device):
        self.logger.debug(u'fillmetersinfo called')
        try:
            batterykW = float(data['battery']['instant_power'])/1000
            #If is between 0 and -100 set to Zero
            if -0.1 <= batterykW <=0.1:
                batterykW = 0


            stateList = [
                {'key': 'Solar', 'value': data['solar']['instant_power']},
                {'key': 'Grid', 'value': data['site']['instant_power']},
                {'key': 'Home', 'value': data['load']['instant_power']},
                {'key': 'Battery', 'value': data['battery']['instant_power']},
                {'key': 'SolarkW', 'value': "{0:0.1f}".format(float(data['solar']['instant_power'])/1000)},
                {'key': 'GridkW', 'value': "{0:0.1f}".format(float(data['site']['instant_power'])/1000)},
                {'key': 'HomekW', 'value': "{0:0.1f}".format(float(data['load']['instant_power'])/1000)},
                {'key': 'BatterykW', 'value': "{0:0.1f}".format( batterykW )}
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

                if float(data['site']['instant_power']) > 250 :
                    # Pulling something from Grid
                    device.updateStateOnServer('gridUsage', value=True)
                elif float(data['site']['instant_power']) < -100 :
                    device.updateStateOnServer('gridUsage', value=False)
                    self.logger.debug(u'Grid Usage False')

                if float(data['battery']['instant_power']) < -100 :
                # Pulling something from Grid
                    if batteryCharging ==False:
                        self.triggerCheck(device, 'batteryCharging')
                    device.updateStateOnServer('batteryCharging', value=True)
                else:
                    device.updateStateOnServer('batteryCharging', value=False)

                if float(data['solar']['instant_power']) > 95:
                    # Solar Generating more than 150 watts
                    device.updateStateOnServer('solarGenerating', value=True)
                else:
                    device.updateStateOnServer('solarGenerating', value=False)

                if float(data['site']['instant_power']) < -100:
                    # Solar Generating more than 150 watts
                    if sendingtoGrid == False:
                        self.triggerCheck(device, 'solarExporting')
                    device.updateStateOnServer('sendingtoGrid', value=True)
                elif float(data['site']['instant_power']) > 100:
                    device.updateStateOnServer('sendingtoGrid', value=False)

                if float(data['battery']['instant_power']) > 150:
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


