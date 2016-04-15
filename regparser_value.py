import sys
import struct

class RegParser_ValueError:
	def __init__(self, msg):
		self.value = msg
	def __str__(self):
		return repr(self.value)

class RegParser_Value:
	REGPARSER_VALUE_HEADER_LENGTH = 0x18
	REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN = 0x1000
	
	REGPARSER_VALUE_ERROR_LENGTH = "ERROR: Invalid data length"

	def __init__(self, offset, regData):
		self.regData = regData
		self.allocated = 0
		if len(self.regData[offset:]) < RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH:
			RegParser_Value.exitError(RegParser_Value.REGPARSER_VALUE_ERROR_LENGTH)
			
		t = (self.valueLen, 
		self.valueSig, 
		self.nameLength, 
		self.dataLength,  
		self.dataOffset, 
		self.dataType,  
		self.flags) = struct.unpack_from("<I2sHIIIH", self.regData[offset:])
		
		if len(regData[offset + RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH:]) < self.nameLength:
			RegParser_Value.exitError("Invalid Value name Length")
			
		self.name = struct.unpack_from(str(self.nameLength) + "s", self.regData[offset+RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH:])[0]
		
		
		if self.valueSig != "vk":
			RegParser_Value.exitError("vk Signature not found where expected")
		
		if self.flags & 1 != 0:
			self.name = self.name.decode("cp1252").encode("Utf-8")
		else:
			self.name = self.name.decode("Utf-16").encode("Utf-8")
			
		if self.valueLen> 0x7fffffff:
			self.allocated = 1
			self.valueLen = 0xffffffff - self.valueLen + 1
		
		v = self.regData[RegParser_Value.REGPARSER_VALUE_HEADER_LENGTH:]
		if len(v) < self.valueLen:
			RegParser_Value.exitError("Invalid value length")
		
		v = v[:self.valueLen]
		
		dataInLine = (self.dataLength >> 31) & 1
		if dataInLine != 0:
			self.dataLength &= 0x7fffffff
			if self.dataLength > 4:
				RegParser_Value.exitError("Invalid inline data")
			self.data = self.regData[offset + 0xC : offset + 0xC + self.dataLength]
		else:
			if self.dataOffset != 0 and self.dataOffset != 0xffffffff:
				self.dataOffset += RegParser_Value.REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN
				if self.dataOffset >= len(self.regData) - self.dataLength:
					RegParser_Value.exitError("Invalid data offset")
				self.data = self.extractValueData()
	
	def __str__(self):
		vn = "ValueName: %s" % self.name 
		vd = "ValueData: %s" % self.getValueData()
		return "%-40s\t%s\n" % (vn, vd)
	
	def __repr__(self):
		return self.__str__()
	
	def getName(self):
		return self.name
			
	def extractValueData(self):
		if self.dataOffset == 0 or self.dataOffset == 0xffffffff:
			return None
		data = None
		
		d = self.regData[self.dataOffset:]
		if len(d) < 4:
			RegParser_Value.exitError("Data offset or length incorrect")
		
		maxDataLength = struct.unpack_from("<I", d)[0]
		dataAllocated = 0
		if maxDataLength > 0x7fffffff:
			dataAllocated = 1
			maxDataLength = 0xffffffff - maxDataLength + 1
		
		d = d[4:]
		
		
		if self.dataLength < maxDataLength:
			data = d[:self.dataLength]
		
		else:
			if len(d) < 8:
				RegParser_Value.exitError("Invalid value data")
			t = (sig, numDataBlocks, dataBlockListOffset) = struct.unpack_from("<2sHI", d)
			
			if sig != "db":
				RegParser_Value.exitError("Invalid data block signature")
		
			dataBlockListOffset += RegParser_Value.REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN
		
			dbl = self.regData[dataBlockListOffset+4:dataBlockListOffset + 4 + numDataBlocks * 4]
			dbl_len = numDataBlocks * 4
			if len(dbl) < dbl_len:
				RegParser_Value.exitError("Invalid data block list length")
		
			data = ""
			while numDataBlocks > 0 and dbl_len > 0:
				offset = struct.unpack_from("<I", dbl)[0] + RegParser_Value.REGPARSER_VALUE_OFFSET_TO_FIRST_HBIN
				bh = self.regData[offset:offset+4]
				if len(bh) < 4:
					RegParser_Value.exitError("Invalid data block header")
			
				bl = struct.unpack_from("<I", bh)[0]
				if bl > 0x7fffffff:
					bl = 0xffffffff - bl + 1
			
				b = self.RegData[offset+4:offset + 4 + (bl - 8)]
			
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
	def exitError(msg):
		raise RegParser_ValueError(msg)
			