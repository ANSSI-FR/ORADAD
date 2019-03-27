#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "ORADAD.h"

#define MSG_MAX_SIZE       8192
#define INFO_MAX_SIZE      MSG_MAX_SIZE + 256         // 256: "%04u/%02u/%02u - %02u:%02u:%02u.%03u\t%d\t%s\t%s\t%d\t" + ... + "\r\n",

extern HANDLE g_hHeap;
extern HANDLE g_hLogFile;
extern BOOL g_bSupportsAnsi;

VOID
Log (
   _In_z_ LPCSTR szFile,
   _In_z_ LPCSTR szFunction,
   _In_ DWORD dwLine,
   _In_ DWORD dwLevel,
   _In_z_ LPCSTR szFormat,
   ...
)
{
   int r;

   CHAR szMessage[MSG_MAX_SIZE];
   SYSTEMTIME st;

   va_list argptr;
   va_start(argptr, szFormat);

   GetLocalTime(&st);

   r = vsprintf_s(szMessage, MSG_MAX_SIZE, szFormat, argptr);
   if (r == -1)
   {
      return;
   }

   if (dwLevel <= LOG_LEVEL_INFORMATION)
      printf("%s\n", szMessage);

   if (dwLevel <= LOG_LEVEL_VERBOSE)
   {
      DWORD dwDataSize, dwDataWritten;
      CHAR szLine[INFO_MAX_SIZE];

      sprintf_s(
         szLine, INFO_MAX_SIZE,
         "%04u/%02u/%02u - %02u:%02u:%02u.%03u\t%d\t%s\t%s\t%d\t%s\r\n",
         st.wYear, st.wMonth, st.wDay,
         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
         dwLevel, szFile, szFunction, dwLine,
         szMessage
      );

      dwDataSize = (DWORD)strnlen_s(szLine, INFO_MAX_SIZE);
      WriteFile(g_hLogFile, szLine, dwDataSize, &dwDataWritten, NULL);
   }
}

VOID
DuplicateString (
   _In_z_ LPWSTR szInput,
   _Out_ LPWSTR *szOutput
)
{
   size_t InputSize;

   if ((szInput == NULL) || (szOutput == NULL))
      return;

   InputSize = wcslen(szInput);
   *szOutput = (LPWSTR)_HeapAlloc((InputSize + 1) * sizeof(WCHAR));
   memcpy(*szOutput, szInput, InputSize * sizeof(WCHAR));
}

//
// Convert "DC=domain,DC=tld" to "domain.tld"
//
LPWSTR
ConvertDnToDns (
   _In_z_ LPWSTR szString
)
{
   LPWSTR szCurrent;
   LPWSTR szNext;
   LPWSTR szReturn;
   size_t SizeString;
   DWORD dwPosition = 0;

   SizeString = wcslen(szString);
   szReturn = (LPWSTR)_HeapAlloc((SizeString + 1) * sizeof(WCHAR));
   if (szReturn == NULL)
      return NULL;

   szCurrent = szString;
   szCurrent += 3;            // Bypass first 'DC=' (3 chars)
   szNext = wcsstr(szCurrent, L",DC=");

   while ((szCurrent != NULL) && (szNext != NULL) && (szCurrent < (szString + SizeString)))
   {
      DWORD dwSize;

      dwSize = szNext - szCurrent;
      memcpy(szReturn + dwPosition, szCurrent, dwSize * sizeof(WCHAR));
      memset(szReturn + dwPosition + dwSize, 0, sizeof(WCHAR));         // Null terminates szReturn (otherwise wcscat_s failed)
      wcscat_s(szReturn, SizeString, L".");
      dwPosition += (dwSize + 1);      // +1 for '.'

      szCurrent = szNext;
      szCurrent += 4;         // Bypass ',DC=' (4 chars)
      szNext = wcsstr(szCurrent, L",DC=");
   }

   wcscat_s(szReturn, SizeString, szCurrent);

   return szReturn;
}

VOID
RemoveSpecialChars (
   _In_z_ LPWSTR szString
)
{
   // Remove \r \n \t
   if (szString)
   {
      while (*szString)
      {
         if (*szString == 0x0a)
            *szString = 0x20;
         else if (*szString == 0x0d)
            *szString = 0x20;
         else if (*szString == 0x09)
            *szString = 0x20;
         szString++;
      }
   }
}

BOOL
WriteTextFile (
   _In_ HANDLE hFile,
   _In_z_ LPCSTR szFormat,
   ...
)
{
   BOOL bReturn;
   DWORD dwDataSize, dwDataWritten;
   CHAR szMessage[MSG_MAX_SIZE];

   va_list argptr;
   va_start(argptr, szFormat);

   vsprintf_s(szMessage, MSG_MAX_SIZE, szFormat, argptr);

   dwDataSize = (DWORD)strnlen_s(szMessage, MSG_MAX_SIZE);
   bReturn = WriteFile(hFile, szMessage, dwDataSize, &dwDataWritten, NULL);

   return bReturn;
}

LPSTR
LPWSTRtoLPSTR (
   _In_opt_z_ LPWSTR szToConvert
)
{
   LPSTR szResult;
   int iSize;

   if (szToConvert == NULL)
      return NULL;

   iSize = WideCharToMultiByte(
      CP_ACP,
      0,
      szToConvert,
      -1,
      NULL, 0,
      NULL, NULL
   );

   if (iSize == 0)
      goto Fail;

   szResult = (LPSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, iSize + 1);

   if (szResult == NULL)
      goto Fail;

   iSize = WideCharToMultiByte(
      CP_ACP,
      0,
      szToConvert,
      -1,
      szResult, iSize,
      NULL, NULL
   );

   if (iSize == 0)
   {
      _SafeHeapRelease(szResult);
      goto Fail;
   }

   return szResult;

Fail:
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR, 0,
      "[!] %sLPWSTRtoLPSTR(%S) failed.%s", COLOR_RED, szToConvert, COLOR_RESET
   );

   return NULL;
}

//
// Metadata
//
BOOL
GetFileVersion (
   _Out_ wchar_t* const szVersion,
   _In_  size_t   const _BufferCount
)
{
   WCHAR szFilename[MAX_PATH];
   VS_FIXEDFILEINFO * pvi;
   DWORD dwHandle;
   DWORD dwSize;
   PBYTE pbBuf;

   GetModuleFileNameW(NULL, szFilename, MAX_PATH);
   dwSize = GetFileVersionInfoSizeW(szFilename, &dwHandle);
   if (0 == dwSize)
   {
      return FALSE;
   }

   pbBuf = (PBYTE)_HeapAlloc(dwSize);
   if (GetFileVersionInfoW(szFilename, dwHandle, dwSize, pbBuf) == FALSE)
   {
      _SafeHeapRelease(pbBuf);
      return FALSE;
   }

   dwSize = sizeof(VS_FIXEDFILEINFO);
   if (!VerQueryValueW(pbBuf, L"\\", (LPVOID*)&pvi, (unsigned int*)&dwSize))
   {
      _SafeHeapRelease(pbBuf);
      return FALSE;
   }

   swprintf(szVersion, _BufferCount, L"%d.%d.%d.%d",
      pvi->dwProductVersionMS >> 16,
      pvi->dwFileVersionMS & 0xFFFF,
      pvi->dwFileVersionLS >> 16,
      pvi->dwFileVersionLS & 0xFFFF
   );

   _SafeHeapRelease(pbBuf);
   return TRUE;
}

BOOL
MetadataWriteFile (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPCWSTR szKey,
   _In_z_ LPWSTR szValue
)
{
   BufferWrite(&pGlobalConfig->BufferMetadata, (LPWSTR)szKey);
   BufferWriteTab(&pGlobalConfig->BufferMetadata);
   BufferWrite(&pGlobalConfig->BufferMetadata, szValue);
   BufferWriteLine(&pGlobalConfig->BufferMetadata);

   return TRUE;
}

BOOL
MetadataCreateFile (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szRootDns
)
{
   BOOL bResult;

   WCHAR szMetadataFilename[MAX_PATH];
   WCHAR szMetadata[MAX_METADATA_VALUE];

   // Open metadata file
   swprintf(
      szMetadataFilename, MAX_PATH,
      L"%s\\%s\\%s\\metadata.tsv",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime
   );

   WriteTextFile(pGlobalConfig->hTableFile, "metadata.tsv\tmetadata\tmetadata\t2\tkey\tnvarchar(255)\tvalue\tnvarchar(1024)\n");

   bResult = BufferInitialize(&pGlobalConfig->BufferMetadata, szMetadataFilename);
   if (bResult != FALSE)
   {
      // Exe version
      GetFileVersion(szMetadata, MAX_METADATA_VALUE);
      MetadataWriteFile(pGlobalConfig, L"oradad_version", szMetadata);

      // Level
      swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->dwLevel);
      MetadataWriteFile(pGlobalConfig, L"oradad_level", szMetadata);
   }

   return TRUE;
}

BOOL
cmdOptionExists (
   _In_ wchar_t *argv[],
   _In_ int argc,
   _In_z_ const wchar_t *szOption
)
{
   for (int i = 1; i < argc; i++)
   {
      if (!wcscmp(argv[i], szOption))
         return TRUE;
   }
   return FALSE;
}

int
pConvertStringToInt (
   _In_z_ LPWSTR szInput
)
{
   int i;
   if (swscanf_s(szInput, L"%i", &i) > 0)
   {
      return i;
   }
   return 0;
}

BOOL
GetCmdOption (
   _In_ wchar_t *argv[],
   _In_ int argc,
   _In_z_ const wchar_t *szOption,
   _In_ TYPE_CONFIG ElementType,
   _Out_ PVOID pvElementValue
)
{
   size_t SizeArg;

   for (int i = 1; i < argc; i++)
   {
      if (!wcscmp(argv[i], szOption))
      {
         LPWSTR szNextArg;

         if (i < (argc - 1))
            szNextArg = argv[i + 1];
         else
            szNextArg = NULL;

         switch (ElementType)
         {
         case ConfigTypeBool:
            *(PBOOL)pvElementValue = TRUE;
            break;

         case ConfigTypeString:
            if (szNextArg == NULL)
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
                  "[!] %sNot enough arguments%s.", COLOR_RED, COLOR_RESET
               );
               return FALSE;
            }
            if ((SizeArg = wcslen(szNextArg)) > 0)
            {
               *(LPWSTR*)pvElementValue = (LPWSTR)_HeapAlloc((SizeArg + 1) * sizeof(wchar_t));
               memcpy(*(LPWSTR*)pvElementValue, szNextArg, SizeArg * sizeof(wchar_t));
            }
            else
               *(LPWSTR*)pvElementValue = NULL;
            break;

         case ConfigTypeUnsignedInterger:
            if (szNextArg == NULL)
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
                  "[!] %sNot enough arguments%s.", COLOR_RED, COLOR_RESET
               );
               return FALSE;
            }
            *(PDWORD)pvElementValue = pConvertStringToInt(szNextArg);
            break;

         default:
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
               "[!] %sUnknown config type%s.", COLOR_RED, COLOR_RESET
            );
            return FALSE;
         }
      }
   }

   // No error (but argument may be not present)
   return TRUE;
}