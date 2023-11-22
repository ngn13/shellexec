#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "config.hpp"
#include "debug.hpp"

void debug(const char* format, ...) {
	if (!DEBUG) {
		return;
	}

	va_list args;
	va_start(args, format);

	printf("[DEBUG] ");
	vprintf(format, args);
	printf("\n");

	va_end(args);
}

void debugnl() {
	printf("\n");
}

void debugnp(const char* format, ...) {
	if (!DEBUG) {
		return;
	}

	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

void getlasterr() {
	if(DEBUG) {
		wprintf(L"[DEBUG] Error code: %d\n", GetLastError());
	}
}