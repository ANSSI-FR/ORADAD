#include <windows.h>
#include <msxml6.h>
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include "ORADAD.h"

#pragma comment(lib, "msxml6.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

HANDLE g_hHeap = NULL;
HANDLE g_hStdOut;
HANDLE g_hLogFile = NULL;

GLOBAL_CONFIG g_GlobalConfig = { 0 };
BOOL g_bSupportsAnsi;

//__declspec(dllexport)
int
wmain (
   int argc,
   wchar_t *argv[]
)
{
   LPWSTR szResult;
   BOOL bResult;
   HRESULT hr;
   SYSTEMTIME st;
   IXMLDOMDocument2 *pXMLDocConfig = NULL;
   IXMLDOMDocument2 *pXMLDocSchema = NULL;
   WCHAR szVersion[MAX_PATH];
   LPWSTR szConfigPath = NULL;
   LPWSTR szSchemaPath = NULL;

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
   g_hStdOut = CreateFile(L"CONOUT$", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
   if (g_hStdOut == INVALID_HANDLE_VALUE)
   {
      return EXIT_FAILURE;
   }

   // Set console output to 'ISO 8859-1 Latin 1; Western European (ISO)'
   SetConsoleOutputCP(28591);

   g_bSupportsAnsi = SetConsoleMode(g_hStdOut, ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
   SetConsoleTitle(L"ORADAD");

   // Get version
   bResult = GetFileVersion(szVersion, MAX_PATH);
   if (bResult == FALSE)
      return EXIT_FAILURE;

   if (cmdOptionExists(argv, argc, L"--version"))
   {
      wprintf_s(L"%s\n", szVersion);
      return EXIT_SUCCESS;
   }

   g_GlobalConfig.szOutDirectory = (LPWSTR)_HeapAlloc(MAX_PATH * sizeof(WCHAR));
   if (argc < 2)
      szResult = _wfullpath(g_GlobalConfig.szOutDirectory, L".", MAX_PATH);
   else
      szResult = _wfullpath(g_GlobalConfig.szOutDirectory, argv[1], MAX_PATH);
   if (szResult == NULL)
   {
      fprintf_s(stderr, "[!] Unable to get absolute path. Exit.\n");
      return EXIT_FAILURE;
   }

   _stprintf_s(g_GlobalConfig.szLogfilePath, MAX_PATH, TEXT("%s\\oradad.log"), g_GlobalConfig.szOutDirectory);

   g_hLogFile = CreateFile(g_GlobalConfig.szLogfilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
   if (g_hLogFile == INVALID_HANDLE_VALUE)
   {
      fprintf_s(stderr, "[!] Unable to open log file '%S'. Exit.\n", g_GlobalConfig.szLogfilePath);
      return EXIT_FAILURE;
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] %sStarting%s.", COLOR_CYAN, COLOR_RESET
   );
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[.] Output directory is '%S'.", g_GlobalConfig.szOutDirectory
   );

   //
   // Read configuration
   //
   if (cmdOptionExists(argv, argc, L"-c"))
   {
      if (GetCmdOption(argv, argc, L"-c", ConfigTypeString, &szConfigPath) == FALSE)
      {
         szConfigPath = NULL;
      }
   }

   if (szConfigPath == NULL)
   {
      szConfigPath = (LPWSTR)_HeapAlloc(MAX_PATH * sizeof(WCHAR));
      swprintf_s(szConfigPath, MAX_PATH, L"config-oradad.xml");
   }

   pXMLDocConfig = (IXMLDOMDocument2 *)XmlReadConfigFile(szConfigPath, &g_GlobalConfig);
   if (pXMLDocConfig == NULL)
      goto End;

   //
   // Read schema
   //
   if (cmdOptionExists(argv, argc, L"-s"))
   {
      if (GetCmdOption(argv, argc, L"-s", ConfigTypeString, &szSchemaPath) == FALSE)
      {
         szSchemaPath = NULL;
      }
   }

   if (szSchemaPath == NULL)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "[.] Using Resource Schema."
      );
   }
   else
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "[.] Using Alternative Schema %S.", szSchemaPath
      );
   }

   pXMLDocSchema = (IXMLDOMDocument2 *)XmlReadSchemaFile(szSchemaPath, &g_GlobalConfig, (PVOID)pXMLDocConfig);  // Use NULL for resource
   if (pXMLDocSchema == NULL)
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

   if (cmdOptionExists(argv, argc, L"-name"))
   {
      LPWSTR szInstanceName = NULL;

      if (GetCmdOption(argv, argc, L"-name", ConfigTypeString, &szInstanceName) != FALSE)
      {
         wcsncpy_s(g_GlobalConfig.szSystemTime, 17, szInstanceName, 16);
      }
   }

   Process(&g_GlobalConfig);

   //
   // Release
   //
End:
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] %sEnd.%s", COLOR_GREEN, COLOR_RESET
   );
   CloseHandle(g_hLogFile);

   // Move log file to output directory
   if (g_GlobalConfig.szFullOutDirectory[0] != 0)
   {
      TCHAR szFinalPath[MAX_PATH];

      _stprintf_s(szFinalPath, MAX_PATH, TEXT("%s\\oradad.log"), g_GlobalConfig.szFullOutDirectory);
      MoveFile(g_GlobalConfig.szLogfilePath, szFinalPath);
   }

   _SafeCOMRelease(pXMLDocConfig);
   _SafeCOMRelease(pXMLDocSchema);
   CoUninitialize();

   _SafeHeapRelease(szConfigPath);
   _SafeHeapRelease(szSchemaPath);
   _SafeHeapRelease(g_GlobalConfig.szOutDirectory);
   HeapDestroy(g_hHeap);

   return EXIT_SUCCESS;
}