#include "WeavePtraceKeyFinder.h"

namespace Weave {

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */
	
#ifdef HAVE_SYS_PTRACE_H
	#include <signal.h>
	#include <sys/ptrace.h>

	#include <dirent.h>
	#include <regex.h>

	typedef struct {
		void* start;
		void* end;
	} MemoryRegion;

	pid_t find_wow_process()
	{
		regex_t pnregex;
		regcomp(&pnregex, "(/|wine\\s+[.\\/]*)?wow(\\.exe)?", REG_EXTENDED | REG_ICASE | REG_NOSUB);
		
		DIR* procDir = opendir("/proc");
		dirent* curDir;
		
		pid_t result = 0;
		while(curDir = readdir(procDir)) {
			pid_t pid = atoi(curDir->d_name);
			if(!pid) continue;
			
			char fname[64];
			snprintf(fname, sizeof(fname), "/proc/%d/cmdline", pid);
			
			FILE* cmdlinef = fopen(fname, "r");
			if(!cmdlinef)
				continue;
			
			char cmdline[256] = { 0 };
			if(fread(cmdline, 1, sizeof(cmdline), cmdlinef) == 0)
			{
				fclose(cmdlinef);
				continue;
			}
			
			fclose(cmdlinef);
			
			if(!regexec(&pnregex, cmdline, 0, NULL, 0))
			{
				result = pid;
				break;
			}
		}

		closedir(procDir);
		return result;
	}

	MemoryRegion* list_memory_regions(pid_t pid, size_t* count)
	{
		regex_t memoryRegionRegex;
		regcomp(&memoryRegionRegex, "([[:xdigit:]]{8})-([[:xdigit:]]{8}) rw[x-]p ([[:xdigit:]]{8}) 00:00", REG_EXTENDED | REG_NOSUB);
		
		char processMapFilename[128];
		sprintf(processMapFilename, "/proc/%d/maps", pid);
		FILE* processMapFile = fopen(processMapFilename, "r");
		
		MemoryRegion* regions = NULL;
		size_t regionsCount = 0;
		
		for(;;)
		{
			char lineBuffer[384];
			if(!fgets(lineBuffer, sizeof(lineBuffer), processMapFile))
				break;
			
			if(!regexec(&memoryRegionRegex, lineBuffer, 0, NULL, 0))
			{
				unsigned int regionStart, regionEnd;
				if(sscanf(lineBuffer, "%x-%x", &regionStart, &regionEnd) < 2)
					continue;
				
				MemoryRegion* r = NULL;
				
				if(regions == NULL)
				{
					regions = (MemoryRegion*)malloc(sizeof(MemoryRegion)*(regionsCount+1));
				} else {
					regions = (MemoryRegion*)realloc(regions, sizeof(MemoryRegion)*(regionsCount+1));
				}
				
				regions[regionsCount].start = (void*)regionStart;
				regions[regionsCount].end = (void*)regionEnd;
				
				regionsCount++;
			}
		}
		
		fclose(processMapFile);
		
		*count = regionsCount;
		return regions;
	}

	bool PtraceFastKeyFinder::findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output)
	{
		pid_t wowPID = find_wow_process();
		
		if(!wowPID)
			return false;
		
		if(ptrace(PTRACE_ATTACH, wowPID, NULL, NULL) == -1)
			return false;
		
		size_t regionsCount = 0;
		MemoryRegion* regions = list_memory_regions(wowPID, &regionsCount);
		
		const char* szAccountID = peer.connection.accountID();
		const size_t nAccountIDLength = strlen(szAccountID);
		
		for(int regionIndex = 0; regionIndex < regionsCount; regionIndex++)
		{
			size_t regionSize = (size_t)regions[regionIndex].end - (size_t)regions[regionIndex].start;
			unsigned char* buffer = new unsigned char[regionSize];
			
			for(size_t offset = 0; offset < regionSize; offset += sizeof(long))
			{
				long* result = (long*)(buffer + offset);
				*result = ptrace(PTRACE_PEEKDATA, wowPID, (void*)((size_t)regions[regionIndex].start + offset), NULL);
			}
			
			for(size_t offset = 0; offset < regionSize - nAccountIDLength - keyOffset - Crypt::session_key_size; offset++)
			{
				if(strcmp(szAccountID, (char*)buffer + offset) == 0)
				{
					const unsigned char* presumedKey = buffer + offset + keyOffset;

					if(isValidKey(peer, header, messageSize, presumedKey))
					{
						*output = (unsigned char*)malloc(Crypt::session_key_size);
						memcpy(*output, presumedKey, Crypt::session_key_size);

						delete buffer;
						
						ptrace(PTRACE_DETACH, wowPID, NULL, SIGCONT);
						free(regions);
						return true;
					}
				}
			}
			
			delete buffer;
		}
		
		ptrace(PTRACE_DETACH, wowPID, NULL, SIGCONT);
		
		if(regions)
			free(regions);
		
		return false;
	}
#endif /* HAVE_SYS_PTRACE_H */

}
