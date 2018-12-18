#include <windows.h>
#include <msxml6.h>
#include <stdio.h>
#include "ORADAD.h"

#pragma comment(lib, "msxml6.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "NetApi32.lib")

HANDLE g_hHeap = NULL;
HANDLE g_hLogFile = NULL;

GLOBAL_CONFIG g_GlobalConfig = { 0 };

int
wmain (
   int argc,
   wchar_t *argv[]
)
{
   HRESULT hr;
   SYSTEMTIME st;
   IXMLDOMDocument2 *pXMLDoc = NULL;

   //
   // Check command line parameters
   //
   if (argc != 2)
   {
      fprintf_s(stderr, "Usage: oradad.exe <outdir>\n");
      return EXIT_FAILURE;
   }

   //
   // Start logging
   //
   g_hLogFile = CreateFile(TEXT("oradad.log"), GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
   if (g_hLogFile == INVALID_HANDLE_VALUE)
   {
      fprintf_s(stderr, "[!] Unable to open log file. Exit.\n");
      return EXIT_FAILURE;
   }
   SetFilePointer(g_hLogFile, 0, 0, FILE_END);

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "Starting."
   );

   //
   // Initialization
   //
   g_hHeap = HeapCreate(0, 0, 0);
   if (g_hHeap == NULL)
   {
      return EXIT_FAILURE;
   }
   hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

   //
   // Read configuration
   //
   pXMLDoc = (IXMLDOMDocument2 *)XmlReadConfigFile((LPTSTR)TEXT("config-oradad.xml"), &g_GlobalConfig);
   if (pXMLDoc == NULL)
      goto End;

   //
   // Main process
   //
   DuplicateString(argv[1], &g_GlobalConfig.szOutDirectory);

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "Output directory is '%S'.", g_GlobalConfig.szOutDirectory
      );

   GetSystemTime(&st);
   swprintf_s(
      g_GlobalConfig.szSystemTime, 17,
      L"%04u%02u%02u-%02u%02u%02u",
      st.wYear, st.wMonth, st.wDay,
      st.wHour, st.wMinute, st.wSecond
   );

   Process(&g_GlobalConfig);

   //
   // Release
   //
End:
   _SafeHeapRelease(g_GlobalConfig.szOutDirectory);
   HeapDestroy(g_hHeap);

   _SafeCOMRelease(pXMLDoc);
   CoUninitialize();

   CloseHandle(g_hLogFile);

   return EXIT_SUCCESS;
}