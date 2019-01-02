#include <windows.h>
#include <msxml6.h>
#include <stdio.h>
#include <tchar.h>
#include "ORADAD.h"

#pragma comment(lib, "msxml6.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "Mincore.lib")

HANDLE g_hHeap = NULL;
HANDLE g_hLogFile = NULL;

GLOBAL_CONFIG g_GlobalConfig = { 0 };

//__declspec(dllexport)
int
wmain (
   int argc,
   wchar_t *argv[]
)
{
   HRESULT hr;
   SYSTEMTIME st;
   IXMLDOMDocument2 *pXMLDoc = NULL;
   TCHAR szPath[MAX_PATH];

   //
   // Check command line parameters
   //
   if (argc != 2)
   {
      fprintf_s(stderr, "Usage: oradad.exe <outdir>\n");
      return EXIT_FAILURE;
   }

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
   // Start logging
   //
   DuplicateString(argv[1], &g_GlobalConfig.szOutDirectory);
   _stprintf_s(szPath, MAX_PATH, TEXT("%s\\oradad.log"), g_GlobalConfig.szOutDirectory);

   g_hLogFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
   if (g_hLogFile == INVALID_HANDLE_VALUE)
   {
      fprintf_s(stderr, "[!] Unable to open log file. Exit.\n");
      return EXIT_FAILURE;
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "Starting."
   );
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "Output directory is '%S'.", g_GlobalConfig.szOutDirectory
   );

   //
   // Read configuration
   //
   pXMLDoc = (IXMLDOMDocument2 *)XmlReadConfigFile((LPTSTR)TEXT("config-oradad.xml"), &g_GlobalConfig);
   if (pXMLDoc == NULL)
      goto End;

   //
   // Main process
   //
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
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "End."
   );
   CloseHandle(g_hLogFile);

   // Move log file to output directory
   if (g_GlobalConfig.szFullOutDirectory[0] != 0)
   {
      TCHAR szFinalPath[MAX_PATH];

      _stprintf_s(szFinalPath, MAX_PATH, TEXT("%s\\oradad.log"), g_GlobalConfig.szFullOutDirectory);
      MoveFile(szPath, szFinalPath);
   }

   _SafeHeapRelease(g_GlobalConfig.szOutDirectory);
   HeapDestroy(g_hHeap);

   _SafeCOMRelease(pXMLDoc);
   CoUninitialize();

   return EXIT_SUCCESS;
}