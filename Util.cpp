#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include "ORADAD.h"

#define MSG_MAX_SIZE       8192
#define INFO_MAX_SIZE      MSG_MAX_SIZE + 256         // 256: "%04u/%02u/%02u - %02u:%02u:%02u.%03u\t%d\t%s\t%s\t%d\t" + ... + "\r\n",

extern HANDLE g_hHeap;
extern HANDLE g_hLogFile;

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
      "LPWSTRtoLPSTR(%S) failed.", szToConvert
   );

   return NULL;
}

//
// Metadata
//
BOOL
pGetFileVersion (
   _Out_ wchar_t* const szVersion,
   _In_  size_t   const _BufferCount
)
{
   WCHAR szFilename[MAX_PATH];

   GetModuleFileNameW(NULL, szFilename, MAX_PATH);
   DWORD dwHandle;
   DWORD sz = GetFileVersionInfoSizeW(szFilename, &dwHandle);
   if (0 == sz)
   {
      return FALSE;
   }
   PBYTE pbBuf = (PBYTE)_HeapAlloc(sz);
   if (GetFileVersionInfoW(szFilename, dwHandle, sz, pbBuf) == FALSE)
   {
      _SafeHeapRelease(pbBuf);
      return FALSE;
   }
   VS_FIXEDFILEINFO * pvi;
   sz = sizeof(VS_FIXEDFILEINFO);
   if (!VerQueryValueW(pbBuf, L"\\", (LPVOID*)&pvi, (unsigned int*)&sz))
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
   return 0;
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
      pGetFileVersion(szMetadata, MAX_METADATA_VALUE);
      MetadataWriteFile(pGlobalConfig, L"oradad_version", szMetadata);

      // Level
      swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->dwLevel);
      MetadataWriteFile(pGlobalConfig, L"oradad_level", szMetadata);
   }

   return TRUE;
}