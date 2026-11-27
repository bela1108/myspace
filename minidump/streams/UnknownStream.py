#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR

class MinidumpUnknownStream:
	"""
	Minimal structural evidence for a stream whose type is not recognized
	by this parser (e.g. MINIDUMP_USER_STREAM streams).
	Only the directory-level information is preserved, the contents are
	not interpreted. Contents are only available after an explicit read,
	and only the bytes that could actually be read are stored/summarized.
	"""
	def __init__(self):
		self.stream_type_value:int = None
		self.location:MINIDUMP_LOCATION_DESCRIPTOR = None
		self.data:bytes = None # bytes actually read, None until read_data is called

	@staticmethod
	def parse(buff):
		mus = MinidumpUnknownStream()
		mus.stream_type_value = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		mus.location = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
		return mus

	@staticmethod
	async def aparse(buff):
		mus = MinidumpUnknownStream()
		t = await buff.read(4)
		mus.stream_type_value = int.from_bytes(t, byteorder = 'little', signed = False)
		mus.location = await MINIDUMP_LOCATION_DESCRIPTOR.aparse(buff)
		return mus

	def read_data(self, buff):
		"""
		Reads the stream contents from the file. If the declared range is
		(partially) missing from the file, only the bytes that could
		actually be read are stored.
		"""
		pos = buff.tell()
		buff.seek(self.location.Rva, 0)
		self.data = buff.read(self.location.DataSize)
		buff.seek(pos, 0)
		return self.data

	async def aread_data(self, buff):
		pos = buff.tell()
		await buff.seek(self.location.Rva, 0)
		self.data = await buff.read(self.location.DataSize)
		await buff.seek(pos, 0)
		return self.data

	def summary(self, max_bytes = 16):
		"""
		Hex preview of the stream contents. Only content that was actually
		read via read_data/aread_data may be summarized, otherwise None.
		"""
		if self.data is None:
			return None
		return self.data[:max_bytes].hex()

	def __str__(self):
		t = 'UnknownStream Type: %s Size: %s File offset: %s' % (hex(self.stream_type_value), self.location.DataSize, self.location.Rva)
		return t
