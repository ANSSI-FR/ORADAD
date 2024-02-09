#include <Windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <intsafe.h>
#include "ORADAD.h"

#define MSG_MAX_SIZE       (8192 - 256)
#define INFO_MAX_SIZE      MSG_MAX_SIZE + 256         // 256: "%04u/%02u/%02u - %02u:%02u:%02u.%03u\t%d\t%s\t%s\t%d\t" + ... + "\r\n",

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;
extern GLOBAL_CONFIG g_GlobalConfig;
extern HANDLE g_hLogFile;

VOID
Log (
   _In_z_ LPCSTR szFile,
   _In_z_ LPCSTR szFunction,
   _In_ DWORD dwLine,
   _In_ DWORD dwLevel,
   _In_z_ _Printf_format_string_ LPCSTR szFormat,
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

      (void)SIZETToDWord(strnlen_s(szLine, INFO_MAX_SIZE), &dwDataSize);
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
   if (*szOutput != NULL)
   {
      memcpy(*szOutput, szInput, InputSize * sizeof(WCHAR));
   }
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

      if (Int64ToDWord(szNext - szCurrent, &dwSize) != S_OK)
         break;

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
         if (*szString == 0x0a)           // \n
            *szString = 0x20;
         else if (*szString == 0x0d)      // \r
            *szString = 0x20;
         else if (*szString == 0x09)      // \t
            *szString = 0x20;
         szString++;
      }
   }
}

BOOL
WriteTextFile (
   _In_ PBUFFER_OUTPUT pOutput,
   _In_z_ LPCSTR szFormat,
   ...
)
{
   BOOL bResult, bReturn = TRUE;
   CHAR szMessage[MSG_MAX_SIZE];
   SIZE_T MessageSize;

   va_list argptr;
   va_start(argptr, szFormat);

   vsprintf_s(szMessage, MSG_MAX_SIZE, szFormat, argptr);
   MessageSize = strnlen_s(szMessage, MSG_MAX_SIZE);

   if (pOutput->hFile != NULL)
   {
      DWORD dwDataSize, dwDataWritten;

      (void)SIZETToDWord(MessageSize, &dwDataSize);
      bResult = WriteFile(pOutput->hFile, szMessage, dwDataSize, &dwDataWritten, NULL);
      if (bResult == FALSE)
         bReturn = FALSE;
   }

   if (pOutput->hMlaFile != NULL)
   {
      bResult = MlaBufferWrite(pOutput->hMlaFile, (PBYTE)szMessage, MessageSize);
      if (bResult == FALSE)
         bReturn = FALSE;
   }

   return bReturn;
}

LPSTR
LPWSTRtoUTF8 (
   _In_opt_z_ LPCWSTR szToConvert
)
{
   LPSTR szResult;
   int iSize;

   if (szToConvert == NULL)
      return NULL;

   iSize = WideCharToMultiByte(
      CP_UTF8,
      0,
      szToConvert,
      -1,
      NULL, 0,
      NULL, NULL
   );

   if (iSize == 0)
      goto Fail;

   szResult = (LPSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, (SIZE_T)iSize + 1);

   if (szResult == NULL)
      goto Fail;

   iSize = WideCharToMultiByte(
      CP_UTF8,
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
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
      "[!] %sLPWSTRtoUTF8(%S) failed%s.",
      COLOR_RED, szToConvert, COLOR_RESET
   );

   return NULL;
}

//
// Metadata
//
_Success_(return)
BOOL
GetFileVersion (
   _Out_ wchar_t* const szVersion,
   _In_  size_t   const _BufferCount
)
{
   BOOL bResult = FALSE;
   WCHAR szFilename[MAX_PATH];
   VS_FIXEDFILEINFO * pvi;
   DWORD dwHandle;
   DWORD dwSize;
   PBYTE pbBuf;

   *szVersion = NULL;
   GetModuleFileName(NULL, szFilename, MAX_PATH);
   dwSize = GetFileVersionInfoSize(szFilename, &dwHandle);
   if (0 == dwSize)
   {
      return FALSE;
   }

   pbBuf = (PBYTE)_HeapAlloc(dwSize);
   if (pbBuf == NULL)
   {
      return FALSE;
   }

   bResult = GetFileVersionInfo(szFilename, 0, dwSize, pbBuf);         // 0: dwHandle -> This parameter is ignored
   if (bResult == FALSE)
   {
      goto End;
   }

   dwSize = sizeof(VS_FIXEDFILEINFO);
   bResult = VerQueryValue(pbBuf, L"\\", (LPVOID*)&pvi, (unsigned int*)&dwSize);
   if (bResult == FALSE)
   {
      goto End;
   }

   swprintf(szVersion, _BufferCount, L"%d.%d.%d.%d",
      pvi->dwProductVersionMS >> 16,
      pvi->dwFileVersionMS & 0xFFFF,
      pvi->dwFileVersionLS >> 16,
      pvi->dwFileVersionLS & 0xFFFF
   );

End:
   _SafeHeapRelease(pbBuf);
   return bResult;
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
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   BOOL bResult;

   WCHAR szMetadata[MAX_METADATA_VALUE];

   DWORD dwComputerNameSize = MAX_METADATA_VALUE;

   // Open metadata file
   bResult = BufferInitialize(&pGlobalConfig->BufferMetadata, L"metadata.tsv", TRUE, FALSE);
   if (bResult == FALSE)
      return FALSE;

   WriteTextFile(&pGlobalConfig->TableFile, "metadata.tsv\tmetadata\tmetadata\t2\tkey\tnvarchar(255)\tvalue\tnvarchar(1024)\n");

   // Exe version
   GetFileVersion(szMetadata, MAX_METADATA_VALUE);
   MetadataWriteFile(pGlobalConfig, L"oradad_version", szMetadata);

   bResult = GetComputerNameEx(ComputerNameDnsFullyQualified, szMetadata, &dwComputerNameSize);
   if (bResult == TRUE)
      MetadataWriteFile(pGlobalConfig, L"computer_name", szMetadata);

   // Token and computer info
   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->TokenType);
   MetadataWriteFile(pGlobalConfig, L"token_type", szMetadata);
   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d (%d.%d)", pGlobalConfig->osvi.wProductType, pGlobalConfig->osvi.dwMajorVersion, pGlobalConfig->osvi.dwMinorVersion);
   MetadataWriteFile(pGlobalConfig, L"product_type", szMetadata);

   // Parameters from config
   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->dwLevel);
   MetadataWriteFile(pGlobalConfig, L"oradad|config|level", szMetadata);

   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->bAutoGetDomain);
   MetadataWriteFile(pGlobalConfig, L"oradad|config|autoGetDomain", szMetadata);

   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->bAutoGetTrusts);
   MetadataWriteFile(pGlobalConfig, L"oradad|config|autoGetTrusts", szMetadata);

   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->bOutputFiles);
   MetadataWriteFile(pGlobalConfig, L"oradad|config|outputFiles", szMetadata);

   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->bOutputMLA);
   MetadataWriteFile(pGlobalConfig, L"oradad|config|outputMla", szMetadata);

   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%d", pGlobalConfig->bWriteHeader);
   MetadataWriteFile(pGlobalConfig, L"oradad|config|writeHeader", szMetadata);

   for (DWORD i = 0; i < pGlobalConfig->dwDomainCount; i++)
   {
      WCHAR szMetadataKey[MAX_METADATA_VALUE];

      swprintf_s(szMetadataKey, MAX_METADATA_VALUE, L"oradad|config|server|%u", i);
      swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%s|%s", pGlobalConfig->DomainConfig[i].szServer,pGlobalConfig->DomainConfig[i].szDomainName);

      MetadataWriteFile(pGlobalConfig, szMetadataKey, szMetadata);
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

_Success_(return)
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

   *(LPWSTR)pvElementValue = NULL;
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
               LPWSTR szTmp;
               szTmp = (LPWSTR)_HeapAlloc((SizeArg + 1) * sizeof(wchar_t));
               if (szTmp == NULL)
               {
                  Log(
                     __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
                     "[!] %sCannot allocate memory%s (error %u).",
                     COLOR_RED, COLOR_RESET, GetLastError()
                  );
                  return FALSE;
               }
               memcpy(szTmp, szNextArg, SizeArg * sizeof(wchar_t));
               *(LPWSTR*)pvElementValue = szTmp;
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

StartStatus
GetBuildDateStatus (
)
{
   int r;
   CHAR szMonth[5] = { 0 };

   SYSTEMTIME BuildSystemTime = { 0 };

   r = sscanf_s(__DATE__, "%s %hu %hu", szMonth, 5, &BuildSystemTime.wDay, &BuildSystemTime.wYear);
   if (r == 3)
   {
      SYSTEMTIME StartSystemTime;
      FILETIME BuildFileTime, StartFileTime;

      ULARGE_INTEGER uliStart, uliBuild;

      if (!strcmp(szMonth, "Jan"))
         BuildSystemTime.wMonth = 1;
      else if (!strcmp(szMonth, "Feb"))
         BuildSystemTime.wMonth = 2;
      else if (!strcmp(szMonth, "Mar"))
         BuildSystemTime.wMonth = 3;
      else if (!strcmp(szMonth, "Apr"))
         BuildSystemTime.wMonth = 4;
      else if (!strcmp(szMonth, "May"))
         BuildSystemTime.wMonth = 5;
      else if (!strcmp(szMonth, "Jun"))
         BuildSystemTime.wMonth = 6;
      else if (!strcmp(szMonth, "Jul"))
         BuildSystemTime.wMonth = 7;
      else if (!strcmp(szMonth, "Aug"))
         BuildSystemTime.wMonth = 8;
      else if (!strcmp(szMonth, "Sep"))
         BuildSystemTime.wMonth = 9;
      else if (!strcmp(szMonth, "Oct"))
         BuildSystemTime.wMonth = 10;
      else if (!strcmp(szMonth, "Nov"))
         BuildSystemTime.wMonth = 11;
      else if (!strcmp(szMonth, "Dec"))
         BuildSystemTime.wMonth = 12;
      else
         return StartStatus::Unkwnon;

      GetSystemTime(&StartSystemTime);
      SystemTimeToFileTime(&StartSystemTime, &StartFileTime);
      SystemTimeToFileTime(&BuildSystemTime, &BuildFileTime);
      uliStart.HighPart = StartFileTime.dwHighDateTime;
      uliStart.LowPart = StartFileTime.dwLowDateTime;
      uliBuild.HighPart = BuildFileTime.dwHighDateTime;
      uliBuild.LowPart = BuildFileTime.dwLowDateTime;

      if (uliBuild.QuadPart >= uliStart.QuadPart)
      {
         return StartStatus::Good;
      }
      else
      {
         ULONGLONG ullDiff;

         ullDiff = uliStart.QuadPart - uliBuild.QuadPart;

         if (ullDiff < (ULONGLONG)10 * 1000 * 1000 * 3600 * 24 * 100)
            return StartStatus::Good;
         else if (ullDiff < (ULONGLONG)10 * 1000 * 1000 * 3600 * 24 * 200)
            return StartStatus::Warning;
         else
            return StartStatus::Expired;
      }
   }

   return StartStatus::Unkwnon;
}

BOOL
CheckAndCreateDirectory (
   _In_z_ LPCWSTR szDirectoryPath
)
{
   BOOL bResult;

   bResult = PathFileExists(szDirectoryPath);
   if (bResult == TRUE)
      return TRUE;

   bResult = CreateDirectory(szDirectoryPath, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sUnable to create directory '%S'%s (error %u).",
         COLOR_RED, szDirectoryPath, COLOR_RESET,
         GetLastError()
      );
      return FALSE;
   }

   return TRUE;
}

BOOL
FormatNameAndCreateDirectory (
   _Out_writes_z_(dwPathSize) LPWSTR szOutputPath,
   _In_ DWORD dwPathSize,
   _In_z_ LPCWSTR szFormat,
   ...
)
{
   BOOL bResult;
   va_list args;

   va_start(args, szFormat);

   vswprintf_s(
      szOutputPath, dwPathSize,
      szFormat, args
   );

   if (g_GlobalConfig.bOutputFiles == TRUE)
      bResult = CheckAndCreateDirectory(szOutputPath);
   else
      return TRUE;

   return bResult;
}