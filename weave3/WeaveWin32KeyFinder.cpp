#include "WeaveWin32KeyFinder.h"
#include <ios>
#include <iostream>

namespace Weave {

#ifdef WIN32
	#include <psapi.h>

	const TCHAR wow_process_name[] = _T("wow.exe");
	
	bool obtainDebugPrivileges()
	{
		HANDLE hToken = NULL;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		if(!hToken)
			return false;

		TOKEN_PRIVILEGES tkp;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
			return false;

		if(!AdjustTokenPrivileges(hToken, false, &tkp, 0, NULL, NULL))
			return false;

		CloseHandle(hToken);
		return true;
	}

	HANDLE openWoWProcess(DWORD dwDesiredAccess)
	{
		DWORD dwProcessIDs[2048];
		DWORD dwProcessSize = 0;

		if(!EnumProcesses(dwProcessIDs, sizeof(dwProcessIDs), &dwProcessSize))
			return NULL;

		DWORD dwProcessCount = dwProcessSize / sizeof(DWORD);

		for(int procIndex = 0; procIndex < dwProcessCount; procIndex++)
		{
			HANDLE hProcess = OpenProcess(dwDesiredAccess, FALSE, dwProcessIDs[procIndex]);
			
			if(hProcess)
			{
				HMODULE hBaseModule;
				DWORD dwModuleCount;

				if(EnumProcessModules(hProcess, &hBaseModule, sizeof(hBaseModule), &dwModuleCount))
				{
					TCHAR szProcessName[MAX_PATH] = { 0x00 };
					GetModuleBaseName(hProcess, hBaseModule, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));

					if(!_tcsicmp(wow_process_name, szProcessName))
						return hProcess;
				}

				CloseHandle(hProcess);
			}
		}

		return NULL;
	}

	bool Win32FastKeyFinder::findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output)
	{
		std::cerr << "Trying to find the key using the Win32 fast key finder." << std::endl;
		
		if(!obtainDebugPrivileges()) {
			std::cerr << "Could not obtain debug privileges." << std::endl;
			return false;
		}
		
		HANDLE hProcess = openWoWProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if(!hProcess) {
			std::cerr << "Could not obtain a handle to the WoW process." << std::endl;
			return false;
		}
		
		const char* szAccountID = peer.connection.accountID();
		const size_t nAccountIDLength = strlen(szAccountID);

		SYSTEM_INFO siSystemInfo;
		GetSystemInfo(&siSystemInfo);

		LPVOID lpMem = siSystemInfo.lpMinimumApplicationAddress;
		while(lpMem < siSystemInfo.lpMaximumApplicationAddress)
		{		
			MEMORY_BASIC_INFORMATION mbiMemoryInfo;
			if(!VirtualQueryEx(hProcess, lpMem, &mbiMemoryInfo, sizeof(mbiMemoryInfo)))
				break;

			if(mbiMemoryInfo.State == MEM_COMMIT && mbiMemoryInfo.Type == MEM_PRIVATE)
			{
				BYTE* buffer = new BYTE[mbiMemoryInfo.RegionSize];
				SIZE_T nBytesRead;

				std::cerr << "\tReading memory region " << mbiMemoryInfo.BaseAddress;
				std::cerr << ":" << ((int)mbiMemoryInfo.BaseAddress + mbiMemoryInfo.RegionSize) << "... ";
				ReadProcessMemory(hProcess, mbiMemoryInfo.BaseAddress, (LPVOID)buffer, mbiMemoryInfo.RegionSize, &nBytesRead);

				if(nBytesRead == mbiMemoryInfo.RegionSize)
				{
					std::cerr << "success." << std::endl;
					
					for(int offset = 0; offset < nBytesRead - nAccountIDLength - Crypt::session_key_size; offset++)
					{
						if(strcmp(szAccountID, (char*)buffer + offset) == 0)
						{
							std::cerr << "\t\tFound account ID at " << ((int)buffer + offset) << std::endl;
							
							if (offset + keyOffset < 0)
								continue;
							if (offset + keyOffset + Crypt::session_key_size > nBytesRead)
								break;
							
							const unsigned char* presumedKey = buffer + offset + keyOffset;
							
							if(isValidKey(peer, header, messageSize, presumedKey))
							{
								std::cerr << "\t\tFound valid key at " << ((int)presumedKey) << " (" << ((int)buffer + offset) << " + " << keyOffset << ")" << std::endl;
								
								*output = (unsigned char*)malloc(Crypt::session_key_size);
								memcpy(*output, presumedKey, Crypt::session_key_size);

								delete buffer;

								CloseHandle(hProcess);
								return true;
							}
						}
					}
				} else {
					std::cerr << "failed." << std::endl;
				}

				delete buffer;
			}

			lpMem = (LPVOID)((long)mbiMemoryInfo.BaseAddress + mbiMemoryInfo.RegionSize);
		}

		CloseHandle(hProcess);
		std::cerr << "Could not obtain a key using the Win32 fast key finder." << std::endl;
		return false;
	}

	bool Win32ExhaustiveKeyFinder::findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output)
	{
		std::cerr << "Trying to find the key using the Win32 exhaustive key finder." << std::endl;
		
		if(!obtainDebugPrivileges()) {
			std::cerr << "Could not obtain debug privileges." << std::endl;
			return false;
		}
		
		HANDLE hProcess = openWoWProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if(!hProcess) {
			std::cerr << "Could not obtain a handle to the WoW process." << std::endl;
			return false;
		}

		const char* szAccountID = peer.connection.accountID();
		const size_t nAccountIDLength = strlen(szAccountID);

		SYSTEM_INFO siSystemInfo;
		GetSystemInfo(&siSystemInfo);

		LPVOID lpMem = siSystemInfo.lpMinimumApplicationAddress;
		while(lpMem < siSystemInfo.lpMaximumApplicationAddress)
		{		
			MEMORY_BASIC_INFORMATION mbiMemoryInfo;
			if(!VirtualQueryEx(hProcess, lpMem, &mbiMemoryInfo, sizeof(mbiMemoryInfo)))
				break;

			if(mbiMemoryInfo.State == MEM_COMMIT && mbiMemoryInfo.Type == MEM_PRIVATE)
			{
				BYTE* buffer = new BYTE[mbiMemoryInfo.RegionSize];
				SIZE_T nBytesRead;

				std::cerr << "\tReading memory region " << std::ios::hex << mbiMemoryInfo.BaseAddress;
				std::cerr << ":" << ((int)mbiMemoryInfo.BaseAddress + mbiMemoryInfo.RegionSize) << "... ";
				ReadProcessMemory(hProcess, mbiMemoryInfo.BaseAddress, (LPVOID)buffer, mbiMemoryInfo.RegionSize, &nBytesRead);

				if(nBytesRead == mbiMemoryInfo.RegionSize)
				{
					std::cerr << "success." << std::endl;
					
					for(int offset = 0; offset < nBytesRead - nAccountIDLength - Crypt::session_key_size; offset++)
					{
						if(strcmp(szAccountID, (char*)buffer + offset) == 0)
						{
							std::cerr << "\t\tFound account ID at " << ((int)buffer + offset) << std::endl;
							
							for(int keyOffset = keySearchRangeMin; keyOffset < keySearchRangeMax; keyOffset++) {
								if (offset + keyOffset < 0)
									continue;
								if (offset + keyOffset + Crypt::session_key_size > nBytesRead)
									break;
								
								const unsigned char* presumedKey = buffer + offset + keyOffset;
								
								if(isValidKey(peer, header, messageSize, presumedKey))
								{
									std::cerr << "\t\tFound valid key at " << ((int)presumedKey) << " (" << ((int)buffer + offset) << " + " << keyOffset << ")" << std::endl;
									
									*output = (unsigned char*)malloc(Crypt::session_key_size);
									memcpy(*output, presumedKey, Crypt::session_key_size);

									delete buffer;

									CloseHandle(hProcess);
									return true;
								}
							}
						}
					}
				} else {
					std::cerr << "failed." << std::endl;
				}

				delete buffer;
			}

			lpMem = (LPVOID)((long)mbiMemoryInfo.BaseAddress + mbiMemoryInfo.RegionSize);
		}

		CloseHandle(hProcess);
		std::cerr << "Could not obtain a key using the Win32 exhaustive key finder." << std::endl;
		return false;
	}

#endif /* WIN32 */
	
}
