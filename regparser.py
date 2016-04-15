''' This source code is mostly derived from the perl source code
     for the parse-win32registry project available at: 
     https://code.google.com/p/parse-win32registry/'''
import argparse
import struct
import sys
from datetime import *

import sys
import struct
import traceback

class RegParser_ValueError:
    def __init__(self, msg):
        self.value = msg
    def __str__(self):
        return repr(self.value)

class RegParser_Value:
    REGPARSER_VALUE_HEADER_LENGTH = 0x18
    REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN = 0x1000
    
    REGPARSER_VALUE_ERROR_LENGTH = "ERROR: Invalid data length"

    def __init__(self, offset, regFile):
        self.regFile = regFile
        self.regFile.seek(0,2)
        self.regFileSz = self.regFile.tell()
        self.allocated = 0
        self.regFile.seek(offset)
        rd = self.regFile.read(RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH)
        if len(rd) < RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH:
            RegParser_Value.exception(RegParser_Value.REGPARSER_VALUE_ERROR_LENGTH)
            
        t = (self.valueLen, 
        self.valueSig, 
        self.nameLength, 
        self.dataLength,  
        self.dataOffset, 
        self.dataType,  
        self.flags) = struct.unpack_from("<I2sHIIIH", rd)
        
        
        self.regFile.seek(offset + RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH)
        self.name = self.regFile.read(self.nameLength)    
        
        if len(self.name) < self.nameLength:
            RegParser_Value.exception("Invalid Value name Length")
        
        if self.valueSig != "vk":
            RegParser_Value.exception("vk Signature not found where expected")
        
        if self.flags & 1 != 0:
            self.name = self.name.decode("cp1252").encode("Utf-8")
        else:
            self.name = self.name.decode("Utf-16").encode("Utf-8")
            
        if self.valueLen> 0x7fffffff:
            self.allocated = 1
            self.valueLen = 0xffffffff - self.valueLen + 1
        
        
        dataInLine = (self.dataLength >> 31) & 1
        if dataInLine != 0:
            self.dataLength &= 0x7fffffff
            if self.dataLength > 4:
                RegParser_Value.exception("Invalid inline data")
            self.regFile.seek(offset + 0xC)
            self.data = self.regFile.read(self.dataLength)
        else:
            if self.dataOffset != 0 and self.dataOffset != 0xffffffff:
                self.dataOffset += RegParser_Value.REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN
                if self.dataOffset >= self.regFileSz - self.dataLength:
                    RegParser_Value.exception("Invalid data offset")
                self.data = self.extractValueData()
    
    def __str__(self):
        vn = "ValueName: %s" % self.name 
        vd = "ValueData: %s" % self.getValueData()
        return "%-40s\t%s\n" % (vn, vd)
    
    def __repr__(self):
        return self.__str__()
    
    def getName(self):
        return self.name
    
    def getDataType(self):
        return self.dataType
            
    def extractValueData(self):
        if self.dataOffset == 0 or self.dataOffset == 0xffffffff:
            return None
        data = None
        self.regFile.seek(self.dataOffset)
        d = self.regFile.read(4)
        if len(d) < 4:
            RegParser_Value.exitError("Data offset or length incorrect")
        
        maxDataLength = struct.unpack_from("<I", d)[0]
        dataAllocated = 0
        if maxDataLength > 0x7fffffff:
            dataAllocated = 1
            maxDataLength = 0xffffffff - maxDataLength + 1
        
        d = self.regFile.read(max(self.dataLength, maxDataLength))
        
        
        if self.dataLength < maxDataLength:
            data = d[:self.dataLength]
        
        else:
            if len(d) < 8:
                RegParser_Value.exitError("Invalid value data")
            t = (sig, numDataBlocks, dataBlockListOffset) = struct.unpack_from("<2sHI", d)
            
            if sig != "db":
                RegParser_Value.exitError("Invalid data block signature")
        
            dataBlockListOffset += RegParser_Value.REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN
            self.regFile.seek(dataBlockListOffset + 4)
            dbl_len = numDataBlocks * 4
            dbl = self.regFile.read(numDataBlocks * 4)
            
            if len(dbl) < dbl_len:
                RegParser_Value.exitError("Invalid data block list length")
        
            data = ""
            while numDataBlocks > 0 and dbl_len > 0:
                offset = struct.unpack_from("<I", dbl)[0] + RegParser_Value.REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN
                self.regFile.seek(offset)
                bh = self.regFile.read(4)
                if len(bh) < 4:
                    RegParser_Value.exitError("Invalid data block header")
            
                bl = struct.unpack_from("<I", bh)[0]
                if bl > 0x7fffffff:
                    bl = 0xffffffff - bl + 1
                self.regFile.seek(offset+4)
                b = self.regFile.read(bl - 8)
            
                if len(b) < bl - 8:
                    RegParser_Value.exitError("Invalid data block")
            
                data += b
            
                dbl_len -= 4
                dbl = dbl[4:]
                numDataBlocks -= 1
            if len(data) < self.dataLength:
                RegParser_Value.exitError("Error getting complete value data")
        
            data = data[:self.dataLength]
        return data
            
    def getValueData(self):
        REG_NONE = 0
        REG_SZ = 1
        REG_EXPAND_SZ = 2
        REG_BINARY = 3
        REG_DWORD = 4
        REG_DWORD_LITTLE_ENDIAN = REG_DWORD
        REG_DWORD_BIG_ENDIAN = 5
        REG_LINK = 6
        REG_MULTI_SZ = 7
        REG_QWORD = 11
        REG_QWORD_LITTLE_ENDIAN = REG_QWORD
        
        t = self.dataType
        d = self.data
        
        
        if d is None:
            return None
        data = None
        if t == REG_DWORD:
            if len(d) == 4:
                data = struct.unpack("<I", d)[0]
        
        elif t == REG_DWORD_BIG_ENDIAN:
            if len(d) == 4:
                data = struct.unpack("I", d)[0]
        
        elif t == REG_QWORD or t == REG_QWORD_LITTLE_ENDIAN:
            if len(d) == 8:
                data = struct.unpack("<Q", d)[0]
        
        elif t == REG_SZ or t == REG_EXPAND_SZ:
            data = d.decode("Utf-16").encode("utf-8").rstrip("\0")
        
        elif t == REG_MULTI_SZ:
            data = d.decode("Utf-16").encode("utf-8").rstrip("\0")
            
        elif t == REG_BINARY:
            data = d.encode("hex")
        else:
            data = d
        
        return data
        
        
    @staticmethod
    def exception(msg):
        raise RegParser_ValueError(msg)


class RegParser_KeyError:
    def __init__(self, msg):
        self.value = msg
    
    def __str__(self):
        return repr(self.value)
        
"""================================================================================"""

class RegParser_HiveError:
    def __init__(self, msg):
        self.value = msg
    def __str__(self):
        return repr(self.value)
        
class RegParser_Hive:
    
    REGF_HEADER_LENGTH = 0X200
    
    ERROR_LENGTH = "ERROR: Invalid data length"    
    
    @staticmethod    
    def printError(msg):
        print msg
    
    @staticmethod
    def exception(msg):
        raise RegParser_HiveError(msg)
    
    @staticmethod
    def parseHive(regHive, hiveNickName):
        rd = regHive.f.read(RegParser_Hive.REGF_HEADER_LENGTH)
        if len(rd) < RegParser_Hive.REGF_HEADER_LENGTH:
            RegParser_Hive.exception(RegParser_Hive.ERROR_LENGTH)
        
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
            RegParser_Hive.exception("Registry hive header checksum is not valid!")
    
        regHive.rootKey = regHive.getRootKey(regHive.embeddedFileName, hiveNickName)
        
        return regHive
            
class RegNTHive:    
    def __init__(self, hiveFileName, hiveNickName=None):
        f = None
        try:
            self.f = f = open(hiveFileName, "rb")
        except Exception, e:
            #print e
            raise(Exception(str(e)))
        self.reghdr = f.read(3)
        f.seek(0)
        
        if self.reghdr.lower() != "reg":
            RegParser_Hive.exception("Invalid registry hive header")
            
            
        self.hive = RegParser_Hive.parseHive(self, hiveNickName)
    
    def close(self):
        try:
            if self.f is not None:
                self.f.close()
        except Exception, e:
            "Could not close registry file"
            print e
        return
        
    def getRootKey(self, embeddedFileName, hiveNickName):
        return RegParser_Key(self.offsetToRootKey, hiveNickName, self.f) 

"""================================================================================"""


class RegParser_Key:
    REGPARSER_KEY_HEADER_LENGTH = 0x50
    REGPARSER_KEY_OFFSET_TO_FIRST_HBIN = 0x1000
    
    REGPARSER_KEY_ERROR_LENGTH = "ERROR: Invalid data length"

    def __init__(self, offset, parent, regFile):
        self.parentKey = parent
        self.regFile = regFile
        self.allocated = 0
        
        self.regFile.seek(offset)
        rd = self.regFile.read(RegParser_Key.REGPARSER_KEY_HEADER_LENGTH)

        if len(rd) < RegParser_Key.REGPARSER_KEY_HEADER_LENGTH:
            RegParser_Key.exception(RegParser_Key.REGPARSER_KEY_ERROR_LENGTH)
            
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
        self.classNameLength) = struct.unpack_from("<I2sHQ4xII4xI4xIIIIIIII4xHH", rd)
        
        
        
        self.keyName = struct.unpack_from(str(self.keyNameLength) + "s", self.regFile.read(self.keyNameLength))[0]
        
        if len(self.keyName) < self.keyNameLength:
            RegParser_Key.exception("Invalid keyname Length")
            
        if self.flags & 0x20 != 0:
            self.keyName = self.keyName.decode("cp1252").encode("Utf-8")
        else:
            self.keyName = self.keyName.decode("Utf-16").encode("Utf-8")
    
        
        if self.keySig != "nk":
            RegParser.exception("nk Signature not found where expected")
        
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
            RegParser_Key.exception("Invalid key length")
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
        return RegParser_Key(self.parentOffset, self.parentKey[:self.parentKey.rfind("\\")], self.regFile)
    
    def __str__(self):
        return self.key
    
    def __repr__(self):
        return self.__str__()
    
    def getSubkeyOffsets(self, offset=None):
        if offset is None:
            offset = self.subkeyListOffset
            
        if offset == 0xffffffff or self.numKeys == 0:
            return None
        
        self.regFile.seek(offset)
        skl_hdr = self.regFile.read(8)
        
        if len(skl_hdr) < 8:
            RegParser_Key.exception("Invalid subkey list header length")
        lh = (length, sig, numEntries) = struct.unpack_from("<I2sH", skl_hdr)
        
        
        skl_len = 2 * 4 * numEntries if sig == "lf" or sig == "lh" else 4 * numEntries if sig == "ri" or sig == "li" else RegParser_Key.exception("Invalid Subkey List Signature")
        
        skl = self.regFile.read(skl_len)
        if len(skl) < skl_len:
            RegParser_Key.exception("Invalid subkey list length")
        
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
        return RegParser_Key(offsets[i], self.key, self.regFile )
        
        
    def getValueOffsets(self):
        self.regFile.seek(self.valueListOffset)
        vl_len = 4 + self.numValues * 4
        vl = self.regFile.read(vl_len)
        
        if len(vl) < vl_len:
            RegParser_Key.exception("Invalid Value list length")
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
        raise Exception("RegParser Error - Could not find subkey")
    
    '''Returns a tuple (<value name>, <value data>)'''    
    def queryValueByIndex(self,i):
        vo = self.getValueOffsets()[1:]
        v = None
        if i < len(vo) and i >= 0:
            v = RegParser_Value(vo[i], self.regFile)
        if v is None:
            return None
        return (v.getName(), v.getValueData(), v.getDataType())
    
    '''Returns the value data'''
    def queryValueByName(self, valueName):
        if valueName is None:
            return None
        vo = self.getValueOffsets()[1:]
        vn = valueName.lower()
        for o in vo:
            v = RegParser_Value(o, self.regFile)
            if v.getName().lower() == vn:
                return (v.getValueData(), v.getDataType())
        
    def getAllValues(self):
        vo = self.getValueOffsets()[1:]
        v = []
        for i in range(len(vo)):
            tmp = RegParser_Value(vo[i], self.regFile)
            if tmp is None:
                break
            v += [(tmp.getName(), tmp.getValueData(), tmp.getDataType())]
        return v
                    
        
            
    @staticmethod
    def exception(msg):
        raise RegParser_KeyError(msg)

"""================================================================================"""
            

class RegParser:
        
    def __init__(self, fileName, hiveName=None):
        try:
            self.hive = RegNTHive(fileName, hiveName)
        except Exception, e:
            #print e
            raise Exception(str(e))
            
    
    '''Returns the root key of the hive, which is needed before accessing any of its subkeys'''
    def getHiveRootKey(self):
        return self.hive.rootKey
        
        
    '''Returns a subkey. keyName may be a path'''    
    @classmethod
    def openKey(cls, key, keyName):
        if keyName is None:
            return None
        keyName = keyName.rstrip("\\")
        return RegParser_Key.openKey(key, keyName)

    @classmethod
    def openSubkeyByIndex(cls, key, index):
        return key.getSubkey(index)
    
    '''Returns time in 100s of nanoseconds since Jan 1, 1601. '''
    @classmethod
    def getKeyTimestamp(cls, key):
        return key.queryTimestamp()
    
    @classmethod
    def timestampToDatetime(cls, timestamp):
        if timestamp is None:
            return None
        startDate = datetime(1601,1,1)
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
    
    @classmethod
    def getNumSubkeys(cls, key):
        return len(key.getSubkeyOffsets())
        
    @staticmethod
    def exception(msg):
        RegParser.printError(msg)
        #sys.exit(-1)
    
    def close(self):
        self.hive.close()
    
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
        print RegParser.timestampToDatetime(RegParser.getKeyTimestamp(k))
        print v
        print rp.getKeyValueByIndex(k, 0)
    None
        
if __name__ == "__main__":
    main()