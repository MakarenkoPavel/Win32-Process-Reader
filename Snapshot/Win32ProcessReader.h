#pragma once

#include <windows.h>
#include <tlhelp32.h>

#include <vector>


int readAllRunningProcesses(std::vector<PROCESSENTRY32> &procs);

int readAllProcessThreads(std::vector<THREADENTRY32> &threads, DWORD PID);
int readAllProcessModules(std::vector<MODULEENTRY32> &modules, DWORD PID);

int getProcessPriorityClass(DWORD PID, DWORD &priority);
int getProcessPriorityClass(HANDLE hProcess, DWORD &priority);

bool enableDebugPrivilege(HANDLE process);
bool setDebugPrivilege(BOOL enable);