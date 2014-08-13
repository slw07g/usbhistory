''' This source code is mostly derived from the perl source code
     for the parse-win32registry project available at: 
     https://code.google.com/p/parse-win32registry/'''
import argparse
import struct
import sys
from regparser_hive import *
from regparser_key import *
from datetime import *

class RegParser:
		
	def __init__(self, fileName, hiveName=None):
		self.hive = RegNTHive(fileName, hiveName)
	
	'''Returns the root key of the hive, which is needed before accessing any of its subkeys'''
	def getHiveRootKey(self):
		return self.hive.rootKey
		
		
	'''Returns a subkey. keyName may be a path'''	
	@classmethod
	def openKey(cls, key, keyName):
		return RegParser_Key.openKey(key, keyName)
	
	'''Returns time in 100s of nanoseconds since Jan 1, 1601. '''
	@classmethod
	def getKeyTimestamp(cls, key):
		return key.queryTimestamp()
	
	@classmethod
	def timestampToDate(cls, timestamp):
		if timestamp is None:
			return None
		startDate = datetime(1600,1,1)
		return startDate + timedelta(seconds=timestamp*(10**-9)*100)
	
	'''Returns a list of (valuename, valuedata) tuples'''
	@classmethod
	def getAllKeyValues(cls, key):
		return key.getAllValues()
	
	@classmethod
	def getKeyValue(cls, key, valueName):
		return key.queryValueByName(valueName)	
	
	@classmethod
	def getKeyValueByIndex(cls, key, index):
		return key.queryValueByIndex(index)
		
	@staticmethod
	def exitError(msg):
		RegParser.printError(msg)
		sys.exit(-1)
	
			
def main():
	p = argparse.ArgumentParser(description="Parse a registry hive. Based heavily on the source code for parse-win32registry project at https://code.google.com/p/parse-win32registry/")
	p.add_argument("-f", "--hiveFileName", help="Full path+filename of the registry hive to parse", required=True)
	p.add_argument("-k", "--key", help="key path(s) to query, separated by commas", required=False)
	args = p.parse_args()
	r = RegParser(args.hiveFileName, "lolwut")
	keyPaths = args.key
	
	for keyPath in keyPaths.split(","):
		rk = r.getHiveRootKey()
		rp = RegParser
		k = RegParser.openKey(rk, keyPath)
		v = RegParser.getAllKeyValues(k)
		print k
		print RegParser.timestampToDate(RegParser.getKeyTimestamp(k))
		print v
		print rp.getKeyValueByIndex(k, 0)
	None
		
if __name__ == "__main__":
	main()