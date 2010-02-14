#include "WeaveWin32KeyFinder.h"

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
		if(!obtainDebugPrivileges())
			return false;

		HANDLE hProcess = openWoWProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if(!hProcess)
			return false;

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

				ReadProcessMemory(hProcess, mbiMemoryInfo.BaseAddress, (LPVOID)buffer, mbiMemoryInfo.RegionSize, &nBytesRead);

				if(nBytesRead == mbiMemoryInfo.RegionSize)
				{
					for(int offset = 0; offset < nBytesRead - nAccountIDLength - keyOffset - Crypt::session_key_size; offset++)
					{
						if(strcmp(szAccountID, (char*)buffer + offset) == 0)
						{
							const unsigned char* presumedKey = buffer + offset + keyOffset;

							if(isValidKey(peer, header, messageSize, presumedKey))
							{
								*output = (unsigned char*)malloc(Crypt::session_key_size);
								memcpy(*output, presumedKey, Crypt::session_key_size);

								delete buffer;

								CloseHandle(hProcess);
								return true;
							}
						}
					}
				}

				delete buffer;
			}

			lpMem = (LPVOID)((long)mbiMemoryInfo.BaseAddress + mbiMemoryInfo.RegionSize);
		}

		CloseHandle(hProcess);
		return false;
	}

	bool Win32ExhaustiveKeyFinder::findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output)
	{
		if(!obtainDebugPrivileges())
			return false;

		HANDLE hProcess = openWoWProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
		if(!hProcess)
			return false;

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

				ReadProcessMemory(hProcess, mbiMemoryInfo.BaseAddress, (LPVOID)buffer, mbiMemoryInfo.RegionSize, &nBytesRead);

				if(nBytesRead == mbiMemoryInfo.RegionSize)
				{
					for(int offset = 0; offset < nBytesRead - Crypt::session_key_size; offset++)
					{
						const unsigned char* presumedKey = buffer + offset;

						if(isValidKey(peer, header, messageSize, presumedKey))
						{
							*output = (unsigned char*)malloc(Crypt::session_key_size);
							memcpy(*output, presumedKey, Crypt::session_key_size);

							delete buffer;

							CloseHandle(hProcess);
							return true;
						}
					}
				}

				delete buffer;
			}

			lpMem = (LPVOID)((long)mbiMemoryInfo.BaseAddress + mbiMemoryInfo.RegionSize);
		}

		CloseHandle(hProcess);
		return false;
	}

#endif /* WIN32 */
	
}
