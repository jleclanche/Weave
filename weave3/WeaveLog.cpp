#include "WeaveLog.h"
#include <cstring>

namespace Weave {
	namespace Log {
		void write_header(std::ostream& stream)
		{
			Header header;
			
			memcpy(&header, ident, sizeof(ident));
			header.version[0] = version & 0xFF;
			header.version[1] = (version >> 8) & 0xFF;
			header.version[2] = (version >> 16) & 0xFF;
			header.version[3] = (version >> 24) & 0xFF;
			memset(&(header.reserved), 0, sizeof(header.reserved));
			
			stream.write((char*)&header, sizeof(header));
		}
		
		void write_entry_header(std::ostream& stream, TypeCode typecode, size_t size)
		{
			EntryHeader header = {
				{
					(uint16_t)typecode & 0xFF,
					((uint16_t)typecode >> 8) & 0xFF
				},
				{
					(size) & 0xFF,
					(size >> 8) & 0xFF,
					(size >> 16) & 0xFF,
					(size >> 24) & 0xFF
				}
			};
			
			stream.write((char*)&header, sizeof(header));
		}
		
		void write_entry(std::ostream& stream, TypeCode typecode, const char* data, size_t size)
		{
			write_entry_header(stream, typecode, size);
			stream.write(data, size);
		}
	}
}
