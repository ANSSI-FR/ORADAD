//
// Constants
//
#define MAX_OCTAL_SIZE           077777777777
#define DWORD_MAX                0xffffffffUL         // See ntintsafe.h
#define USE_GLOBAL_CREDENTIALS   DWORD_MAX
//
// Macros
//
#define _HeapAlloc(x) HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, (x))
#define _SafeHeapRelease(x) { if (NULL != x) { HeapFree(g_hHeap, 0, x); x = NULL; } }
#define _SafeCOMRelease(x) { if (NULL != x) { x->Release(); x = NULL; } }

#define _CallWriteAndGetMax(x, y) do { DWORD dwTempSizeResult; dwTempSizeResult = x; if (dwTempSizeResult>y) y=dwTempSizeResult; } while(FALSE)

//
// Defines
//
#define MAX_METADATA_KEY               255
#define MAX_METADATA_VALUE             1024

//
// Enum
//
enum class StartStatus
{
   Unkwnon = 0,
   Good = 1,
   Warning = 2,
   Expired = 3
};

enum class DbCompareMode
{
   Max,
   Last
};

//
// Include
//
#include "mla.hpp"
#include "Structures.h"
#include "Functions.h"

//
// TraceLogging
//
// Uncomment to enable tracing
//#define TRACELOGGING

#ifdef TRACELOGGING
#include <TraceLoggingProvider.h>
#include <winmeta.h>                            // for WINEVENT_LEVEL_* definitions

TRACELOGGING_DECLARE_PROVIDER(g_hOradadLoggingProvider);

#define ORADAD_PROVIDER_KEYWORD_MLA       0x1
#endif