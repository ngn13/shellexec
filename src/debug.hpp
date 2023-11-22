#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

void debugnl();
void getlasterr();
void debug(const char* format, ...);
void debugnp(const char* format, ...);
