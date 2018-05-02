#include "Win32ProcessReader.h"


int readAllRunningProcesses(std::vector<PROCESSENTRY32> &procs)
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          
		return(FALSE);
	}

	do
	{
		procs.push_back(pe32);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}

int readAllProcessThreads(std::vector<THREADENTRY32> &threads, DWORD PID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return(FALSE);
	}

	do
	{
		if (te32.th32OwnerProcessID == PID)
		{
			threads.push_back(te32);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);
}

int readAllProcessModules(std::vector<MODULEENTRY32> &modules, DWORD PID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return(FALSE);
	}

	do
	{
		modules.push_back(me32);

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}

int getProcessPriorityClass(DWORD PID, DWORD &priority)
{
	DWORD dwPriorityClass = 0;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (hProcess)
	{
		dwPriorityClass = GetPriorityClass(hProcess);
		if (!dwPriorityClass)
		{
			CloseHandle(hProcess);
			return (FALSE);
		}
	}

	CloseHandle(hProcess);
	return (TRUE);
}

int getProcessPriorityClass(HANDLE hProcess, DWORD & priority)
{
	DWORD dwPriorityClass = 0;
	if (hProcess)
	{
		dwPriorityClass = GetPriorityClass(hProcess);
		if (!dwPriorityClass)
		{
			CloseHandle(hProcess);
			return (FALSE);
		}
	}
	return (TRUE);
}




bool enableDebugPrivilege(HANDLE process)
{
	LUID luid;
	HANDLE token;
	TOKEN_PRIVILEGES newPrivileges;

	if (!OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &token))
		return false;

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
		return false;

	newPrivileges.PrivilegeCount = 1;
	newPrivileges.Privileges[0].Luid = luid;
	newPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	return AdjustTokenPrivileges(
		token,                     // TokenHandle
		FALSE,                     // DisableAllPrivileges
		&newPrivileges,            // NewPrivileges
		sizeof(newPrivileges),     // BufferLength
		nullptr,                   // PreviousState (OPTIONAL)
		nullptr                    // ReturnLength (OPTIONAL)
	);
}

bool setDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	LUID luid;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		return FALSE;

	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		return FALSE;

	return TRUE;
}