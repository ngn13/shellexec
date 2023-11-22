#include <stdbool.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <winternl.h>
#include <intrin.h>

#include "debug.hpp"
#include "check.hpp"
#include "config.hpp"

const WCHAR* bad_procceses[50] = {
	L"processhacker",
	L"wireshark",
	L"regmon",
	L"tcpview",
	L"filemon",
	L"portmon",
	L"tcpdump",
	L"procdump",
	L"tcpview",
	L"sysmon",
	L"procmon",
	L"ettercap",
	L"httpdebuggerui",
	L"wireshark",
	L"fiddler",
	L"regedit",
	L"processhacker",
	L"ida64",
	L"ollydbg",
	L"pestudio",
	L"gdb",
	L"r2",
	L"x32dbg",
	L"x64dbg",
	L"x96dbg",
	L"prl_cc",
	L"prl_tools",
	L"joeboxcontrol",
	L"ksdumperclient",
	L"xenservice",
	L"joeboxserver",
	L"devenv",
	L"IMMUNITYDEBUGGER",
	L"ImportREC",
	L"reshacker",
	L"windbg",
	L"protection_id",
	L"scylla_x86",
	L"scylla_x64",
	L"scylla.exe",
	L"idau64.exe",
	L"idau.exe",
	L"idaq64.exe",
	L"idaq.exe",
	L"idaw.exe",
	L"idag64.exe",
	L"idag.exe",
	L"ida64.exe",
	L"ida.exe",
	L"pebear",
};

bool check_process(PROCESSENTRY32 process) {
	for (int i = 0; i < 50; i++) {
		_wcslwr_s(process.szExeFile);
		if (wcsstr(process.szExeFile, bad_procceses[i])) {
			return false;
		}
	}

	return true;
}

bool check_processes() {
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_handle == INVALID_HANDLE_VALUE) {
		debug("Error creating proccess snapshot");
		return false;
	}

	PROCESSENTRY32 process;
	process.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32First(snapshot_handle, &process)) {
		debug("Error getting first process entry");
		return false;
	}

	do {
		if (!check_process(process)) {
			debug("Found bad process");
			return false;
		}
	} while (Process32Next(snapshot_handle, &process));

	CloseHandle(snapshot_handle);
	debug("Process check completed");
	return true;
}

bool check_debug() {
	// https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
#ifdef _WIN64
	_PEB* peb = (_PEB*)(__readgsqword(0x60));
#else 
	_PEB* peb = (_PEB*)(__readfsdword(0x30));
#endif

	if (peb->BeingDebugged == 1) {
		debug("Debug check failed");
		return false;
	}

	debug("Debug check completed");
	return true;
}

bool check_vm() {
	int regs[4];
	__cpuid(regs, 1);

	if ((regs[2] & (1 << 31))) {
		debug("VM check failed");
		return false;
	}

	debug("VM check completed");
	return true;
}

bool do_checks() {
	if (DEBUG_CHECK) {
		if (!check_debug()) {
			return false;
		}
	}

	if (PROCESS_CHECK) {
		if (!check_processes()) {
			return false;
		}
	}

	if (VM_CHECK) {
		if (!check_vm()) {
			return false;
		}
	}

	return true;
}