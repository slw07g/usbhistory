from _winreg import *
import argparse
from datetime import *

class USBInfo:
	def __init__(self):
		self.properties = None
	
	def addProperty(self, key, value):
		if self.properties is None:
			self.properties = []
		self.properties += [(key,value)]
	
	def __str__(self):
		if self.properties == None:
			return None
		out = ""
		for p in self.properties:
			out += "%-20s: %s\r\n" % p
		return out
		
	def __repr__(self):
		return self.__str__() + "\r\n"
			
class DeviceClass:
	def __init__(self, hardwareID = None, instanceID = None):
		self.hardwareID = hardwareID
		self.instanceID = instanceID
	
	def __str__(self):
		return "(HW_ID: %s, I_ID: %s)" % (self.hardwareID, self.instanceID)
	
	def __repr__(self):
		return self.__str__()
		
def parseHardwareInstance(deviceInstance = None):
	if deviceInstance is None:
		return None
	
	if deviceInstance[0:4].upper() != "USB\\":
		return None
	
	print "Found USB"
	locSecondSlash = deviceInstance[4:].find("\\")
	if locSecondSlash is None:
		return None
		
	hardwareID = deviceInstance[4:4 + locSecondSlash]
	instanceID = deviceInstance[4 + locSecondSlash + 1:]
	
	return DeviceClass(hardwareID, instanceID)
	
def getUSBHistory(controlSet="CurrentControlSet"):
	controlSetKey = "SYSTEM\\" + controlSet + "\\"
	deviceClassesKey = controlSetKey + "Control\\DeviceClasses\\"
	usbEnumKey = controlSetKey + "Enum\\USB\\"
	#deviceParamsKey = usbEnumKey + hardwareID + "\\" + instanceID + "\\" + "Device Parameters\\"
	
	hHive = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
	startDate = datetime(1601, 1, 1)
	
	usbHistories = []
	try:
		hDeviceClassesKey = OpenKey(hHive,  deviceClassesKey)
	except Exception, e:
		print e
		return None
	
	for i in range(1024):
		try:
			hCurrentDeviceClassKey = OpenKey(hDeviceClassesKey, EnumKey(hDeviceClassesKey, i))
			currentDeviceClassSubkey = EnumKey(hCurrentDeviceClassKey, 0)
			devInstance = QueryValueEx(OpenKey(hCurrentDeviceClassKey, currentDeviceClassSubkey), "DeviceInstance")[0]
			
			di = parseHardwareInstance(devInstance)
			if di is None:
				continue
			hDevKey = OpenKey(hHive, usbEnumKey + di.hardwareID + "\\" + di.instanceID + "\\")
			usbHistory = USBInfo()
			firstCreated = QueryInfoKey(hCurrentDeviceClassKey)[2]
			lastModified = QueryInfoKey(hDevKey)[2]
			usbHistory.addProperty("First Created", str(startDate + timedelta(seconds=firstCreated*(10**-9)*100)) + " UTC")
			usbHistory.addProperty("Last Modified", str(startDate + timedelta(seconds=lastModified*(10**-9)*100)) + " UTC") 
			for j in range(1024):
				try:
					ui = EnumValue(hDevKey, j)
					
				except Exception, e:
					print e
					break
				
				
				usbHistory.addProperty(ui[0], ui[1])
			usbHistories += [usbHistory]

		except Exception, e:
			print e
			break
	return usbHistories

def main():
	controlSets = ["CurrentControlSet", "ControlSet001", "ControlSet002", "ControlSet003"]
	for c in controlSets:
		entries = getUSBHistory(c)
		print entries	

if __name__ ==  "__main__":
	main()
