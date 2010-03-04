/* 	This file is part of Weave.
	Based on work from the MaNGOS Open Source MMORPG Server Project
	
	Weave is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Weave is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Weave.  If not, see <http://www.gnu.org/licenses/>. */

/** \file
 * List of opcode numbers and their "canonical" names.
 * \todo Opcode naming within Weave itself is a temporary solution. Once binary
 * output to a file is implemented, this should be outsourced to another
 * application. */

/** Macro for better readability of the opcode_name() function */
#define OPCODE(c,n) case c: return n;

const char* opcode_name(int code);
