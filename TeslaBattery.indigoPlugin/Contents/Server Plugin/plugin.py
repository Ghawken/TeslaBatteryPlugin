#! /usr/bin/env python2.6
# -*- coding: utf-8 -*-

"""
Tesla - Battery Control

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
    u'showDebugLevel': "1",  # Low, Medium or High debug output.
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

        self.debug = self.pluginPrefs.get('showDebugInfo', False)
        self.debugLevel = self.pluginPrefs.get('showDebugLevel', "1")
        self.debugextra = self.pluginPrefs.get('debugextra', False)

        self.prefServerTimeout = int(self.pluginPrefs.get('configMenuServerTimeout', "15"))
        self.configUpdaterInterval = self.pluginPrefs.get('configUpdaterInterval', 24)
        self.configUpdaterForceUpdate = self.pluginPrefs.get('configUpdaterForceUpdate', False)

        self.serverip = self.pluginPrefs.get('ipAddress', '')

        if 'Tesla Battery Gateway' not in indigo.devices.folders:
            indigo.devices.folder.create('Tesla Battery Gateway')
        self.folderId = indigo.devices.folders['Tesla Battery Gateway'].id


        self.pluginIsInitializing = False


    def __del__(self):
        if self.debugLevel >= 2:
            self.debugLog(u"__del__ method called.")
        indigo.PluginBase.__del__(self)

    def closedPrefsConfigUi(self, valuesDict, userCancelled):
        if self.debugLevel >= 2:
            self.debugLog(u"closedPrefsConfigUi() method called.")

        if userCancelled:
            self.debugLog(u"User prefs dialog cancelled.")

        if not userCancelled:
            self.debugLevel = self.pluginPrefs.get('showDebugLevel', "1")
            self.debugLog(u"User prefs saved.")

            try:
                self.logLevel = int(valuesDict[u"showDebugLevel"])
            except:
                self.logLevel = logging.INFO
            self.indigo_log_handler.setLevel(self.logLevel)

            self.logger.debug(u"logLevel = " + str(self.logLevel))
            self.logger.debug(u"User prefs saved.")
            self.logger.debug(u"Debugging on (Level: {0})".format(self.debugLevel))

        return True

    # Start 'em up.
    def deviceStartComm(self, dev):
        if self.debugLevel >= 2:
            self.debugLog(u"deviceStartComm() method called.")


    # Shut 'em down.
    def deviceStopComm(self, dev):
        if self.debugLevel >= 2:
            self.debugLog(u"deviceStopComm() method called.")
        indigo.server.log(u"Stopping device: " + dev.name)

    def forceUpdate(self):
        self.updater.update(currentVersion='0.0.0')

    def checkForUpdates(self):
        if self.updater.checkForUpdate() == False:
            indigo.server.log(u"No Updates are Available")

    def updatePlugin(self):
        self.updater.update()

    def runConcurrentThread(self):

        try:
            while self.pluginIsShuttingDown == False:
                self.prefsUpdated = False
                self.sleep(0.5)
                updateMeters = t.time() +5
                updateGrid = t.time() + 10
                updateSite = t.time() + 30
                updateBatt = t.time() +60
                while self.prefsUpdated == False:
                    if self.debugextra:
                        self.debugLog(u" ")

                    if t.time() > updateMeters:
                        for dev in indigo.devices.itervalues('self.teslaMeters'):
                            self.updateteslaMeters(dev)
                        updateMeters = t.time() +15

                    if t.time() > updateGrid:
                        for dev in indigo.devices.itervalues('self.teslaGridStatus'):
                            self.updateGridStatus(dev)
                        updateGrid = t.time() + 30

                    if t.time() > updateSite:
                        for dev in indigo.devices.itervalues('self.teslaSite'):
                            self.updateSiteInfo(dev)
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
        self.fillmetersinfo(meters, dev)
        return

    def updateGridStatus(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Grid Status Called')
        gridstatus = self.sendcommand('system_status/grid_status')
        self.fillgridstatusinfo(gridstatus, dev)
        return

    def updateBattery(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Battery Called')
        battery = self.sendcommand('system_status/soe')
        self.fillbatteryinfo(battery, dev)
        return

    def updateSiteInfo(self, dev):
        if self.debugextra:
            self.logger.debug(u'update Tesla Site Info Called')
        siteinfo = self.sendcommand('site_info')
        self.fillsiteinfo(siteinfo, dev)
        return


    def shutdown(self):
        if self.debugextra:
            self.debugLog(u"shutdown() method called.")

    def startup(self):
        if self.debugextra:
            self.debugLog(u"Starting Plugin. startup() method called.")
        self.updater = GitHubPluginUpdater(self)
        # See if there is a plugin update and whether the user wants to be notified.
        try:
            if self.configUpdaterForceUpdate:
                self.updatePlugin()

            else:
                self.checkForUpdates()
            self.sleep(1)
        except Exception as error:
            self.errorLog(u"Update checker error: {0}".format(error))

    def validatePrefsConfigUi(self, valuesDict):
        if self.debugLevel >= 2:
            self.debugLog(u"validatePrefsConfigUi() method called.")

        error_msg_dict = indigo.Dict()

        # self.errorLog(u"Plugin configuration error: ")
        # also allow retesting on reopening
        valuesDict['loginOK'] = False
        return True, valuesDict


    def toggleDebugEnabled(self):
        """ Toggle debug on/off. """


        self.logger.debug(u"toggleDebugEnabled() method called.")

        if self.debugLevel == int(logging.INFO):
            self.debug = True
            self.debugLevel = int(logging.DEBUG)
            self.pluginPrefs['showDebugInfo'] = True
            self.pluginPrefs['showDebugLevel'] = int(logging.DEBUG)
            self.logger.info(u"Debugging on.")
            self.logger.debug(u"Debug level: {0}".format(self.debugLevel))
            self.logLevel = int(logging.DEBUG)
            self.logger.debug(u"New logLevel = " + str(self.logLevel))
            self.indigo_log_handler.setLevel(self.logLevel)

        else:
            self.debug = False
            self.debugLevel = int(logging.INFO)
            self.pluginPrefs['showDebugInfo'] = False
            self.pluginPrefs['showDebugLevel'] = int(logging.INFO)
            self.logger.info(u"Debugging off.  Debug level: {0}".format(self.debugLevel))
            self.logLevel = int(logging.INFO)
            self.logger.debug(u"New logLevel = " + str(self.logLevel))
            self.indigo_log_handler.setLevel(self.logLevel)

    # Generate Devices
    def generateTeslaDevices(self, valuesDict):
        if self.debugLevel >= 2:
            self.debugLog(u'generate Devices run')
        try:
            # check Gatewway and IP up

            check = self.sendcommand('site_info/site_name')
            self.logger.debug(unicode(check))
            if check is None:
                # Connection
                self.logger.debug(u'Connection cannot be Established')
                valuesDict['loginOK'] = False
                return valuesDict

            # Generate and Check Site Info
            siteinfo = self.sendcommand('site_info')
            self.logger.debug(unicode(siteinfo))
            if siteinfo is not None:
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
            if battery is not None:
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
            if gridstatus is not None:
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
            self.logger.debug(unicode(meters))
            if meters is not None:
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
        if self.debugLevel >= 2:
            self.debugLog(u'check Connection run')
        try:
            # check Gatewway and IP up
            check = self.sendcommand('site_info/site_name')
            self.logger.debug(unicode(check))
            if check is None:
                # Connection
                self.logger.debug(u'Connection cannot be Established')
                valuesDict['loginOK'] = False
            else:
                valuesDict['loginOK'] = True

            return valuesDict

        except Exception as error:
            self.errorLog(u'error within checkConnection'+unicode(error.message))

    ## API Calls
    def sendcommand(self, cmd):

        if self.serverip == '':
            self.logger.debug(u'No IP address Entered..')
            return
        try:
            self.url = "http://" + str(self.serverip) + '/api/'+ str(cmd)
            if self.debugextra:
                self.logger.debug(u'sendcommand called')

            r = requests.get(self.url, timeout=2)

            if r.status_code == 502:
                self.logger.debug(u'Status code'+unicode(r.status_code) )
                self.logger.debug(u'Text :'+unicode(r.text))  #r.text
                self.logger.debug(u'Error Running command.  ?Powerwall offline')
                return 'Offline'
            if r.status_code != 200:
                self.logger.debug(u'Status code'+unicode(r.status_code) )
                self.logger.debug(u'Text :'+unicode(r.text))  #r.text
                self.logger.debug(u'Error Running command')
                return ''
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
    ##
    def fillmetersinfo(self, data, device):
        self.logger.debug(u'fillmetersinfo called')
        try:
            stateList = [
                {'key': 'Solar', 'value': data['solar']['instant_apparent_power']},
                {'key': 'Grid', 'value': data['site']['instant_apparent_power']},
                {'key': 'Home', 'value': data['load']['instant_apparent_power']},
                {'key': 'Battery', 'value': data['battery']['instant_apparent_power']}
            ]
            device.updateStatesOnServer(stateList)
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
            device.updateStateOnServer('gridStatus', value=data['grid_status'])
            if data['grid_status'] == 'SystemGridConnected':
                device.updateStateOnServer('gridConnected', value=True)
            elif data['grid_status'] == 'SystemIslandedActive':
                device.updateStateOnServer('gridConnected', value=False)

            device.updateStateOnServer('deviceIsOnline', value=True, uiValue="Online")
            update_time = t.strftime('%c')
            device.updateStateOnServer('deviceLastUpdated', value=str(update_time))

        except:
            self.logger.exception(u'Caught Exception in FillGridStatus Info')
            device.updateStateOnServer('deviceIsOnline', value=False, uiValue="Offline")


