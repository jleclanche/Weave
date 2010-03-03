# -*- coding: utf-8 -*-

from wdbc.structures import *


class SMSG_MONSTER_MOVE(Structure):
	fields = Skeleton(
		GUIDField("guid"),
		SmallIntegerField(),
		FloatField("x"),
		FloatField("y"),
		FloatField("z"),
		DurationField("time", unit="milliseconds"),
		SmallIntegerField(),
		BitMaskField("flags"),
		DurationField("travel_time", unit="milliseconds"),
		IntegerField("path_size"),
		IntegerField("path_size"),
	)

	#data.append((char*)path.GetNodes(start), pathSize * 4 * 3);

#MultiField("enchants",
	#fields = (
		#IntegerField("enchant"),
		#DurationField("enchant_duration", unit="milliseconds"),
		#IntegerField("enchant_charges"),
	#),
	#amount = 8
#),
class SMSG_AUCTION_LIST_RESULT(Structure):
	
	split_entries = True
	
	fields = Skeleton(
		IDField(),
		IntegerField("item"),
		IntegerField("enchant_1"),
		DurationField("enchant_duration_1", unit="milliseconds"),
		IntegerField("enchant_charges_1"),
		IntegerField("enchant_2"),
		DurationField("enchant_duration_2", unit="milliseconds"),
		IntegerField("enchant_charges_2"),
		IntegerField("enchant_3"),
		DurationField("enchant_duration_3", unit="milliseconds"),
		IntegerField("enchant_charges_3"),
		IntegerField("enchant_4"),
		DurationField("enchant_duration_4", unit="milliseconds"),
		IntegerField("enchant_charges_4"),
		IntegerField("enchant_5"),
		DurationField("enchant_duration_5", unit="milliseconds"),
		IntegerField("enchant_charges_5"),
		IntegerField("enchant_6"),
		DurationField("enchant_duration_6", unit="milliseconds"),
		IntegerField("enchant_charges_6"),
		IntegerField("enchant_7"),
		DurationField("enchant_duration_7", unit="milliseconds"),
		IntegerField("enchant_charges_7"),
		IntegerField("random_property"),
		IntegerField("suffix_factor"),
		IntegerField("count"),
		IntegerField("charges"),
		UnknownField(),
		GUIDField("owner"),
		MoneyField("start_bid"),
		MoneyField("minimum_bid"),
		MoneyField("buyout"),
		DurationField("expiration", unit="milliseconds"),
		GUIDField("bidder"),
		MoneyField("current_bid"),
	)
