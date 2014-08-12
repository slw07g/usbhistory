''' This source code is mostly derived from the perl source code
     for the parse-win32registry project available at: 
     https://code.google.com/p/parse-win32registry/'''
import argparse
import struct
import sys
from regparser_key import *

class RegParser:
	
	REGF_HEADER_LENGTH = 0X200
	
	ERROR_LENGTH = "ERROR: Invalid data length"	
	
	@staticmethod	
	def printError(msg):
		print msg
	
	@staticmethod
	def exitError(msg):
		RegParser.printError(msg)
		sys.exit(-1)
	
	@staticmethod
	def parseHive(regHive):
		rd = regHive.regData
		if len(rd) < RegParser.REGF_HEADER_LENGTH:
			RegParser.exitError(RegParser.ERROR_LENGTH)
		
		t = (regHive.regType, 
		regHive.seq1, 
		regHive.seq2, 
		regHive.timestamp, 
		regHive.majorVersion, 
		regHive.minorVersion, 
		regHive.type, 
		regHive.offsetToRootKey, 
		regHive.total_hbin_length,  
		regHive.embeddedFileName) = struct.unpack_from('<4sIIQIII4xII4x64s', rd)
		
		regHive.offsetToRootKey += 0x1000
		regHive.embeddedFileName = regHive.embeddedFileName.decode("Utf-16")
		
		checksum = 0
		for i in range(127):
			checksum ^= struct.unpack_from("H", rd[i*4:])[0]
		
		if checksum != struct.unpack_from("H", rd[508:])[0]:
			RegParser.exitError("Registry hive header checksum is not valid!")
	
		regHive.rootKey = regHive.getRootKey(regHive.embeddedFileName)
		#print regHive.rootKey.getSubkey(0)
		#print regHive.rootKey.findSubkey("System")
		control = RegParser_Key.openKey(regHive.rootKey, "ControlSet002\\Control")
		control.getAllValues()
		
		return regHive
			
class RegNTHive:	
	def __init__(self, hiveFileName, hiveShortName="LoadedHive"):
		self.hiveShortName = hiveShortName
		f = None
		try:
			f = open(hiveFileName, "rb")
		except Exception, e:
			print e
			sys.exit(-1)
		self.regData = f.read()
		f.close()
		if len(self.regData) < 4:
			RegParser.exitError("Invalid data length")
			
			
		self.hive = RegParser.parseHive(self)
		
		
	def getRootKey(self, embeddedFileName):
		return RegParser_Key(self.offsetToRootKey, None, self.regData) 

def main():
	p = argparse.ArgumentParser(description="Parse a registry hive. Based heavily on the source code for parse-win32registry project at https://code.google.com/p/parse-win32registry/")
	p.add_argument("-f", "--hiveFileName", help="Full path+filename of the registry hive to parse", required=True)
	args = p.parse_args()
	rH = RegNTHive(args.hiveFileName)
	None
		
if __name__ == "__main__":
	main()