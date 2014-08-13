''' This source code is mostly derived from the perl source code
     for the parse-win32registry project available at: 
     https://code.google.com/p/parse-win32registry/ '''
import sys
import struct
from regparser_value import *

class RegParser_KeyError:
	def __init__(self, msg):
		self.value = msg
	
	def __str__(self):
		return repr(self.value)
		
class RegParser_Key:
	REGPARSER_KEY_HEADER_LENGTH = 0x50
	REGPARSER_KEY_OFFSET_TO_FIRST_HBIN = 0x1000
	
	REGPARSER_KEY_ERROR_LENGTH = "ERROR: Invalid data length"

	def __init__(self, offset, parent, regData):
		self.parentKey = parent
		self.regData = regData
		self.allocated = 0
		if len(self.regData) < RegParser_Key.REGPARSER_KEY_HEADER_LENGTH:
			RegParser_Key.exitError(RegParser_Key.REGPARSER_KEY_ERROR_LENGTH)
			
		t = (self.keyLen, 
		self.keySig, 
		self.flags, 
		self.timestamp,  
		self.parentOffset, 
		self.numKeys,  
		self.subkeyListOffset, 
		self.numValues, 
		self.valueListOffset, 
		self.securityOffset, 
		self.classNameOffset, 
		self.maxSubkeyNameLength,
		self.maxClassNameLength, 
		self.maxValueNameLength, 
		self.maxValueDataLength, 
		self.keyNameLength, 
		self.classNameLength) = struct.unpack_from("<I2sHQ4xII4xI4xIIIIIIII4xHH", self.regData[offset:])
		
		if len(regData[RegParser_Key.REGPARSER_KEY_HEADER_LENGTH:]) < self.keyNameLength:
			RegParser_Key.exitError("Invalid keyname Length")
			
		self.keyName = struct.unpack_from(str(self.keyNameLength) + "s", self.regData[offset+RegParser_Key.REGPARSER_KEY_HEADER_LENGTH:])[0]
		
		
		if self.flags & 0x20 != 0:
			self.keyName = self.keyName.decode("cp1252").encode("Utf-8")
		else:
			self.keyName = self.keyName.decode("Utf-16").encode("Utf-8")
	
		
		if self.keySig != "nk":
			RegParser.exitError("nk Signature not found where expected")
		
		if self.parentOffset != 0xffffffff:
			self.parentOffset += RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN
		if self.subkeyListOffset != 0xffffff:
			self.subkeyListOffset += RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN
		if self.securityOffset != 0xffffffff:
			self.securityOffset += RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN
		if self.valueListOffset != 0xffffffff:
			self.valueListOffset += RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN
		if self.classNameOffset != 0xffffffff:
			self.classNameOffset += RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN
		
		if self.keyLen> 0x7fffffff:
			self.allocated = 1
			self.keyLen = 0xffffffff - self.keyLen + 1
		
		if self.keyLen < RegParser_Key.REGPARSER_KEY_HEADER_LENGTH:
			RegParser_Key.exitError("Invalid key length")
		if self.isRoot() is True and parent is not None:
			self.parentKey = None
			self.keyName = parent
		self.key = self.parentKey + "\\" + self.keyName if self.parentKey is not None else self.keyName
		
		
	def queryTimestamp(self):
		return self.timestamp
	
	def getKeyPath(self):
		return self.key
		
	def getNumKeys(self):
		return self.numKeys
	
	def getKeyName(self):
		return self.keyName
		
	def getKeyPath(self):
		return self.key
		
	def isRoot(self):
		if (self.flags & 4) != 0 or (self.flags & 8) != 0:
			return True
		return False
		
	def getParentKey(self):
		if self.isRoot():
			return None
		return RegParser_Key(self.parentOffset, self.parentKey[:self.parentKey.rfind("\\")], self.regData)
	
	def __str__(self):
		return self.key
	
	def __repr__(self):
		return self.__str__()
	
	def getSubkeyOffsets(self, offset=None):
		if offset is None:
			offset = self.subkeyListOffset
			
		if offset == 0xffffffff or self.numKeys == 0:
			return None
			
		skl = self.regData[offset:]
		
		if len(skl) < 8:
			RegParser_Key.exitError("Invalid subkey list header length")
		lh = (length, sig, numEntries) = struct.unpack_from("<I2sH", skl)
		
		
		skl_len = 2 * 4 * numEntries if sig == "lf" or sig == "lh" else 4 * numEntries if sig == "ri" or sig == "li" else RegParser_Key.exitError("Invalid Subkey List Signature")
		
		if len(skl[8:]) < skl_len:
			RegParser_Key.exitError("Invalid subkey list length")
		
		skl = skl[8:8+skl_len]
		subkeyOffsets = []
		
		'''if sig == ri or sig == li'''
		dec = 4
		unpackStr = "<I"
		
		if sig == "lf" or sig == "lh":
			unpackStr = "<I4x"
			dec = 8
		
			while skl_len > 0:
				while numEntries > 0 and skl_len > 0:
					sko = RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN + struct.unpack_from(unpackStr, skl)[0]
					
					if sig == "ri":
						offset_ref = self.getSubkeyOffsets(sko)
						if sig is not None:
							for s in offset_ref:
								subkeyOffsets += [s]
					else:
						subkeyOffsets += [sko]
					skl = skl[dec:]
					skl_len -= dec
					numEntries -= 1
			
		return subkeyOffsets
	
	def getSubkey(self, i):
		offsets = self.getSubkeyOffsets()
		if offsets is None or i >= len(offsets):
			return None
		return RegParser_Key(offsets[i], self.key, self.regData)
		
		
	def getValueOffsets(self):
		vl = self.regData[self.valueListOffset:]
		vl_len = 4 + self.numValues * 4
		
		if len(vl) < vl_len:
			RegParser_Key.exitError("Invalid Value list length")
		vl = vl[:vl_len]
		#vl_len -= 4	
		numValues = self.numValues
		
		valueOffsets = []
		
		if numValues == 0:
			return valueOffsets
		
		while vl_len > 3 and numValues >= 0:
			vo = struct.unpack_from("<I", vl)[0] + RegParser_Key.REGPARSER_KEY_OFFSET_TO_FIRST_HBIN
			if vo is not None:
				valueOffsets += [vo]
			vl = vl[4:]
			vl_len -= 4
			numValues -= 1
		
		return valueOffsets
	
	@classmethod
	def openKey(cls, key, subkeyPath):
		if key is None or subkeyPath is None or len(subkeyPath) <= 0:
			return None
		locSlash = subkeyPath.find("\\")
		if locSlash != -1:
			return cls.openKey(key.findSubkey(subkeyPath[:locSlash]), subkeyPath[locSlash+1:])
		else:
			return key.findSubkey(subkeyPath)
	
	
	def findSubkey(self, subkeyName):
		s = subkeyName.lower()
		for i in range(self.numKeys):
			k = self.getSubkey(i)
			if str(k.keyName).lower() == s:
				return k
		return None
	
	'''Returns a tuple (<value name>, <value data>)'''	
	def queryValueByIndex(self,i):
		vo = self.getValueOffsets()[1:]
		v = None
		if i < len(vo) and i >= 0:
			v = RegParser_Value(vo[i], self.regData)
		if v is None:
			return None
		return (v.getName(), v.getValueData())
	
	'''Returns the value data'''
	def queryValueByName(self, valueName):
		if valueName is None:
			return None
		vo = self.getValueOffsets()[1:]
		vn = valueName.lower()
		for o in vo:
			v = RegParser_Value(o, self.regData)
			if v.getName().lower() == vn:
				return v.getValueData()
		
	def getAllValues(self):
		vo = self.getValueOffsets()[1:]
		v = []
		for i in range(len(vo)):
			tmp = RegParser_Value(vo[i], self.regData)
			if tmp is None:
				break
			v += [(tmp.getName(), tmp.getValueData())]
		return v
					
		
			
	@staticmethod
	def exitError(msg):
		raise RegParser_KeyError(msg)
			