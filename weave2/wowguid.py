from struct import unpack

class GUID(object):
	"""
	A generic GUID.
	
	Instantiating this will either return an object of type GUID or one of
	its subclasses (PlayerGUID, CreatureGUID, PetGUID, VehicleGUID).
	"""
	def __new__(cls, value, **kwargs):
		if isinstance(value, basestring):
			value, = unpack("<Q", value)
		
		guid_type = ((value >> 50) & 0xF) >> 2
		guid_map = dict((c.type, c) for c in (PlayerGUID, CreatureGUID, PetGUID, VehicleGUID))

		new_cls = cls

		try:
			new_cls = guid_map[guid_type]
		except KeyError:
			pass

		obj = super(GUID, new_cls).__new__(new_cls)

		if new_cls != cls:
			obj.__init__(value, **kwargs)

		return obj

	def __init__(self, value, **kwargs):
		if isinstance(value, basestring):
			value, = unpack("<Q", value)
		
		self._value = value
		
		if "build" in kwargs:
			self._build = kwargs["build"]
		else:
			self._build = None

	@property
	def type(self):
		return (self._value >> 50 & 0xF) >> 2

	@property
	def value(self):
		return self._value
	
	def __hash__(self):
		return self._value

	def __repr__(self):
		return "%s(%s)" % (self.__class__.__name__, self)

	def __str__(self):
		return "0x%016X" % (self._value)

	def __cmp__(self, other):
		return self._value.__cmp__(other._value)

class PlayerGUID(GUID):
	type = 0x00

class CreatureGUID(GUID):
	type = 0x03

	@property
	def unit_id(self):
		"""The ID that maps this creature to an entry in CreatureCache.wdb"""
		
		if self._build is not None and self._build > 10505:
			shift_by = 32
		else:
			shift_by = 24
		
		return (self._value >> shift_by) & 0xFFFFF

	@property
	def spawn_counter(self):
		"""
		Sequentially increasing number which distinguishes individual
		creatures with the same unit ID.
		"""
		return self._value & 0xFFFFFF

	def __repr__(self):
		return "%s(%s, unitID=%d, spawnCounter=%d)" % (self.__class__.__name__, self, self.unit_id, self.spawn_counter)

class PetGUID(GUID):
	type = 0x04

	@property
	def pet_id(self):
		"""Sequentially increasing identifier, unique among pets on this realm"""
		
		if self._build is not None and self._build > 10505:
			shift_by = 32 # Untested
		else:
			shift_by = 24
		
		return (self._value >> shift_by) & 0xFFFFF

	@property
	def spawn_counter(self):
		"""
		Sequentially increasing number which distinguishes individual
		creatures with the same unit ID.
		"""
		return self._value & 0xFFFFFF

	def __repr__(self):
		return "%s(%s, petID=%d, spawnCounter=%d)" % (self.__class__.__name__, self, self.pet_id, self.spawn_counter)

class VehicleGUID(GUID):
	type = 0x05
