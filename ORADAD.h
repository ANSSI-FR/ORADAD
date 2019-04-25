#include "Structures.h"
#include "Functions.h"

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
#define DC_LOCATOR_OPTION              L"[dsgetdc]"
#define MAX_METADATA_KEY               255
#define MAX_METADATA_VALUE             1024
