#ifndef __INFO__
#define __INFO

#include <stdio.h>

#define info_out(str, ...) \
	 printf(str, ##__VA_ARGS__);

#ifndef _VERBOSE
#define debug_out(str, ...) ;
#endif

#ifdef _VERBOSE
#define debug_out(str, ...) \
	printf(str, ##__VA_ARGS__);
#endif

#endif