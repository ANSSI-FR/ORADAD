#include <Windows.h>
#include <Shlwapi.h>
#include <AclAPI.h>
#include <stdio.h>
#include "ORADAD.h"
#include "lz4/xxhash.h"

#define SYSVOL_ROW_COUNT         14
#define GUID_STR_SIZE            38             // {23456789-1234-6789-1234-678901234567}

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

DWORD g_dwSysvolMaxLength[SYSVOL_ROW_COUNT];

VOID
pProcessSysvolFolder(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPCWSTR szForestName,
   _In_z_ LPCWSTR szDomainName,
   _In_z_ LPWSTR szFolder,
   _In_opt_ HANDLE hToken,
   _In_ PBUFFER_DATA pBuffer
);

VOID
pProcessSysvolFile(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPCWSTR szForestName,
   _In_z_ LPCWSTR szDomainName,
   _In_z_ LPWSTR szFileName,
   _In_opt_ HANDLE hToken,
   _In_ PBUFFER_DATA pBuffer
);

//
// Public functions
//
VOID
ProcessSysvol (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szRootDns,                     // Forest DNS name
   _In_z_ LPCWSTR szPath1,                      // Alwas 'domain'
   _In_z_ LPCWSTR szPath2,                      // Domain DNS name
   _In_opt_z_ LPWSTR szServer
)
{
   BOOL bResult;
   WCHAR szOutput[MAX_PATH];
   WCHAR szRemoteName[MAX_PATH];
   HANDLE hToken = NULL;
   BUFFER_DATA Buffer;
   PBUFFER_DATA pBuffer;

   swprintf_s(
      szOutput, MAX_PATH,
      L"%s\\%s\\%s\\%s\\%s\\sysvol.tsv",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      szPath1,
      szPath2
   );

   //
   // Create output buffer
   //
   bResult = BufferInitialize(&Buffer, szOutput);
   if (bResult == FALSE)
   {
      return;
   }

   pBuffer = &Buffer;
   if (pGlobalConfig->bWriteHeader == TRUE)
   {
      // Be sure to have SYSVOL_ROW_COUNT entries
      BufferWrite(pBuffer, (LPWSTR)L"forest");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"domain");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"guid");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"path");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"filename");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"archivename");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"securitydescriptor");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"fileattributes");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"ftCreationTime");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"ftLastAccessTime");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"ftCreaftLastWriteTimetionTime");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"filesize");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"take");
      BufferWriteTab(pBuffer);
      BufferWrite(pBuffer, (LPWSTR)L"errorCode");
      BufferWriteLine(pBuffer);                 // New line for last column
   }

   wsprintf(szRemoteName, L"\\\\%s\\SYSVOL", szServer);

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] Processing sysvol: '%S'",
      szRemoteName
   );

   if (pGlobalConfig->szUsername != NULL)
   {
      bResult = LogonUser(
         pGlobalConfig->szUsername,
         pGlobalConfig->szUserDomain,
         pGlobalConfig->szUserPassword,
         LOGON32_LOGON_NEW_CREDENTIALS,
         LOGON32_PROVIDER_DEFAULT,
         &hToken);

      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to logon with explicit credentials (error %u).%s", COLOR_RED, GetLastError(), COLOR_RESET
         );
         return;
      }
   }

   pProcessSysvolFolder(pGlobalConfig, szRootDns, szPath2, szRemoteName, hToken, pBuffer);

   if (hToken != NULL)
      CloseHandle(hToken);
   BufferClose(&Buffer);
}

VOID
SysvolWriteTableInfo (
   _In_ HANDLE hTableFile,
   _In_z_ LPWSTR szDomainDns
)
{
   DWORD dwIdx = 0;

   WriteTextFile(hTableFile, "%S\\%S\\sysvol.tsv\t", STR_DOMAIN, szDomainDns);
   WriteTextFile(hTableFile, "%S_%S_sysvol\t", STR_DOMAIN, szDomainDns);
   WriteTextFile(hTableFile, "%S_sysvol\t", STR_DOMAIN);
   WriteTextFile(hTableFile, "%u\t", SYSVOL_ROW_COUNT);                 // Columns count
   WriteTextFile(hTableFile, "forest\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   WriteTextFile(hTableFile, "domain\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   WriteTextFile(hTableFile, "guid\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   WriteTextFile(hTableFile, "path\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   WriteTextFile(hTableFile, "filename\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   WriteTextFile(hTableFile, "archivename\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   // nvarchar(n) n must be from 1 through 4000
   if (((g_dwSysvolMaxLength[dwIdx] / 2) + 1) < 4000)
      WriteTextFile(hTableFile, "securitydescriptor\tnvarchar(%u)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   else
      WriteTextFile(hTableFile, "securitydescriptor\tnvarchar(max)\t", (g_dwSysvolMaxLength[dwIdx++] / 2) + 1);
   WriteTextFile(hTableFile, "fileattributes\tint\t");
   dwIdx++;
   WriteTextFile(hTableFile, "ftCreationTime\tdatetime2\t");
   dwIdx++;
   WriteTextFile(hTableFile, "ftLastAccessTime\tdatetime2\t");
   dwIdx++;
   WriteTextFile(hTableFile, "ftCreaftLastWriteTimetionTime\tdatetime2\t");
   dwIdx++;
   WriteTextFile(hTableFile, "filesize\tint\t");
   dwIdx++;
   WriteTextFile(hTableFile, "take\ttinyint\t");
   dwIdx++;
   WriteTextFile(hTableFile, "errorCode\tint\n");
   dwIdx++;
}

//
// Private functions
//

BOOL
pSysvolCrackName (
   _In_z_ LPWSTR szFilePath,
   _In_z_ LPWSTR szDomain,
   _Outptr_result_maybenull_z_ LPWSTR* szNewFilePath,
   _Outptr_result_maybenull_z_ LPWSTR* szGuid,
   _Outptr_result_maybenull_z_ LPWSTR* szFileName
)
{
   LPWSTR szStrippedFilename;
   size_t Position = 0;
   size_t FilePathSize;

   *szNewFilePath = NULL;
   *szGuid = NULL;
   *szFileName = NULL;

   szStrippedFilename = StrStrIW(szFilePath, L"\\SYSVOL\\");
   if (szStrippedFilename == NULL)
   {
      return TRUE;
   }

   FilePathSize = wcslen(szStrippedFilename);

   Position = 8;           // Bypass '\SYSVOL\'

   if (StrStrIW(szStrippedFilename + Position, szDomain) == szStrippedFilename + Position)
   {
      Position += wcslen(szDomain);
      if (Position == FilePathSize)
      {
         return TRUE;
      }
      else
      {
         if (Position < FilePathSize)
         {
            LPWSTR szSearch;

            *szNewFilePath = szStrippedFilename + Position + 1;

            szSearch = wcsrchr(szStrippedFilename + Position, '\\');
            if (szSearch != NULL)
            {
               *szFileName = szSearch + 1;               // +1: remove '\'
            }

            szSearch = StrStrIW(szStrippedFilename + Position, L"\\Policies\\{");
            if (szSearch != NULL)
            {
               if ((szSearch + 10) <= *szFileName)
               {
                  // Be sure of Guid string size
                  Position = wcslen(szSearch + 10);

                  if (Position >= GUID_STR_SIZE)
                     *szGuid = szSearch + 10;
               }
            }
         }
      }
   }

   return TRUE;
}

VOID
pProcessSysvolFolder (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPCWSTR szForestName,
   _In_z_ LPCWSTR szDomainName,
   _In_z_ LPWSTR szFolder,
   _In_opt_ HANDLE hToken,
   _In_ PBUFFER_DATA pBuffer
)
{
   BOOL bResult;
   WCHAR szOutPath[MAX_PATH];

   TCHAR szFindPattern[MAX_PATH];
   WIN32_FIND_DATA FindFileData;
   HANDLE hFindFile;

   PathCombine(szFindPattern, szFolder, L"*");

   if (hToken != NULL)
      (VOID)ImpersonateLoggedOnUser(hToken);
   hFindFile = FindFirstFile(szFindPattern, &FindFileData);
   if (hToken != NULL)
      RevertToSelf();

   swprintf_s(szOutPath, MAX_PATH, L"%s\\%s", pGlobalConfig->szFullSysvolOutDirectory, szDomainName);
   bResult = PathFileExists(szOutPath);
   if (bResult == FALSE)
      CreateDirectory(szOutPath, NULL);

   if (hFindFile != INVALID_HANDLE_VALUE)
   {
      do
      {
         TCHAR szFullPath[MAX_PATH];

         // Bypass '.' and '..'
         if ((wcscmp(FindFileData.cFileName, L".") == 0) || (wcscmp(FindFileData.cFileName, L"..") == 0))
            continue;

         PathCombine(szFullPath, szFolder, FindFileData.cFileName);

         if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
         {
            // found a subdirectory; recurse into it
            pProcessSysvolFile(pGlobalConfig, szForestName, szDomainName, szFullPath, hToken, pBuffer);
            pProcessSysvolFolder(pGlobalConfig, szForestName, szDomainName, szFullPath, hToken, pBuffer);
         }
         else
         {
            // found a file; do something with it
            pProcessSysvolFile(pGlobalConfig, szForestName, szDomainName, szFullPath, hToken, pBuffer);
         }
      } while (FindNextFile(hFindFile, &FindFileData));
      FindClose(hFindFile);
   }
}

VOID
pProcessSysvolFile (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPCWSTR szForestName,
   _In_z_ LPCWSTR szDomainName,
   _In_z_ LPWSTR szFileName,
   _In_opt_ HANDLE hToken,
   _In_ PBUFFER_DATA pBuffer
)
{
   DWORD dwRet;
   BOOL bResult;

   HANDLE hFile;
   DWORD dwInitialError = ERROR_SUCCESS;

   BOOL bHaveFileSecurityInfo = TRUE;
   PBYTE pbRelSD = NULL;
   DWORD dwSizeSD = 0;

   BOOL bHaveFileInfo = TRUE;
   WIN32_FILE_ATTRIBUTE_DATA fileAttributeData;

   if (hToken != NULL)
      (VOID)ImpersonateLoggedOnUser(hToken);

   hFile = CreateFile(
      szFileName,
      READ_CONTROL,
      FILE_SHARE_READ,
      NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
      NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      dwInitialError = GetLastError();
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot open sysvol file '%S'%s (error %u).",
         COLOR_RED, szFileName, COLOR_RESET, dwInitialError
      );
      bHaveFileSecurityInfo = FALSE;
   }

   bResult = GetFileAttributesEx(szFileName, GetFileExInfoStandard, &fileAttributeData);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot get file attributes for '%S'%s (error %u).",
         COLOR_RED, szFileName, COLOR_RESET, GetLastError()
      );
      bHaveFileInfo = FALSE;
   }

   if (hToken != NULL)
      RevertToSelf();

   //
   // Get security info
   //
   if (hFile != INVALID_HANDLE_VALUE)
   {
      PSID pSidOwner = NULL;
      PSECURITY_DESCRIPTOR pSD = NULL;
      SECURITY_DESCRIPTOR_CONTROL sdControl;

      dwRet = GetSecurityInfo(
         hFile,
         SE_FILE_OBJECT,
         OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
         &pSidOwner, // ppsidOwner
         NULL, // ppsidgroup
         NULL, // ppDacl
         NULL, // ppSacl
         &pSD  // ppsecurityDesriptor
      );

      if (dwRet != ERROR_SUCCESS)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot get security descriptor for '%S' (error %u).%s", COLOR_RED, szFileName, dwRet, COLOR_RESET
         );
         bHaveFileSecurityInfo = FALSE;
      }
      else
      {
         bResult = GetSecurityDescriptorControl(pSD, &sdControl, &dwSizeSD);
         if (bResult == FALSE)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot get security descriptor control for '%S' (error %u).%s", COLOR_RED, szFileName, GetLastError(), COLOR_RESET
            );
            bHaveFileSecurityInfo = FALSE;
         }
         else
         {
            // Check if SD is relative
            if (sdControl & SE_SELF_RELATIVE)
            {
               pbRelSD = (PBYTE)pSD;
               dwSizeSD = GetSecurityDescriptorLength(pbRelSD);
            }
            else
            {
               // SD should never be absolute, if necessary, should convert it here. For now, fail.
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
                  "[!] %sSecurity descriptor for '%S' is not relative.%s", COLOR_YELLOW, szFileName, COLOR_RESET
               );
               bHaveFileSecurityInfo = FALSE;
            }
         }
      }
   }

   //
   // Write data in tsv file
   //
   {
      DWORD dwIdx = 0;
      DWORD dwOutSize;
      LPWSTR szNewFilePath;
      LPWSTR szGuid;
      LPWSTR szShortFileName;
      LARGE_INTEGER largeInt;
      BOOL bCopyFile = FALSE;
      DWORD dwErrorCode = ERROR_SUCCESS;

      //
      // Check if get the actual file
      //
      if (pGlobalConfig->szSysvolFilter != NULL)
      {
         WCHAR szFilenameLower[MAX_PATH];

         if (0 == wcscpy_s(szFilenameLower, MAX_PATH, szFileName))
         {
            HRESULT hResult;

            _wcslwr_s(szFilenameLower, MAX_PATH);
            hResult = PathMatchSpecEx(szFilenameLower, pGlobalConfig->szSysvolFilter, PMSF_MULTIPLE);

            if (hResult == S_OK)
               bCopyFile = TRUE;
         }
      }

      pSysvolCrackName(szFileName, (LPWSTR)szDomainName, &szNewFilePath, &szGuid, &szShortFileName);

      //
      // Write sysvol.tsv
      //
      // Column 'forest'
      _CallWriteAndGetMax(BufferWrite(pBuffer, (LPWSTR)szForestName), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      // Column 'domain'
      _CallWriteAndGetMax(BufferWrite(pBuffer, (LPWSTR)szDomainName), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      // Column 'guid'
      _CallWriteAndGetMax(BufferWrite(pBuffer, szGuid, GUID_STR_SIZE * sizeof(WCHAR)), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      // Column 'path'
      _CallWriteAndGetMax(BufferWrite(pBuffer, szNewFilePath), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      // Column 'filename'
      _CallWriteAndGetMax(BufferWrite(pBuffer, szShortFileName), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      // Archivename
      XXH64_hash_t hArchiveName = XXH64(szFileName, wcslen(szFileName) * sizeof(WCHAR), 0);
      // Column 'archivename'
      _CallWriteAndGetMax(BufferWrite(pBuffer, hArchiveName), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      if (bHaveFileSecurityInfo == TRUE)
      {
         dwOutSize = BufferWriteHex(pBuffer, pbRelSD, dwSizeSD);
         // Column 'securitydescriptor'
         g_dwSysvolMaxLength[dwIdx] = __max(g_dwSysvolMaxLength[dwIdx], dwOutSize);
      }
      ++dwIdx;
      BufferWriteTab(pBuffer);

      if (bHaveFileInfo == TRUE)
      {
         _CallWriteAndGetMax(BufferWrite(pBuffer, fileAttributeData.dwFileAttributes), g_dwSysvolMaxLength[dwIdx]);
         ++dwIdx;
         BufferWriteTab(pBuffer);

         _CallWriteAndGetMax(BufferWrite(pBuffer, &(fileAttributeData.ftCreationTime)), g_dwSysvolMaxLength[dwIdx]);
         ++dwIdx;
         BufferWriteTab(pBuffer);

         _CallWriteAndGetMax(BufferWrite(pBuffer, &(fileAttributeData.ftLastAccessTime)), g_dwSysvolMaxLength[dwIdx]);
         ++dwIdx;
         BufferWriteTab(pBuffer);

         _CallWriteAndGetMax(BufferWrite(pBuffer, &(fileAttributeData.ftLastWriteTime)), g_dwSysvolMaxLength[dwIdx]);
         ++dwIdx;
         BufferWriteTab(pBuffer);

         largeInt.HighPart = fileAttributeData.nFileSizeHigh;
         largeInt.LowPart = fileAttributeData.nFileSizeLow;
         _CallWriteAndGetMax(BufferWrite(pBuffer, largeInt.QuadPart), g_dwSysvolMaxLength[dwIdx]);
         ++dwIdx;
         BufferWriteTab(pBuffer);
      }
      else
      {
         ++dwIdx;
         BufferWriteTab(pBuffer);
         ++dwIdx;
         BufferWriteTab(pBuffer);
         ++dwIdx;
         BufferWriteTab(pBuffer);
         ++dwIdx;
         BufferWriteTab(pBuffer);
         ++dwIdx;
         BufferWriteTab(pBuffer);
      }

      // Column 'take'
      _CallWriteAndGetMax(BufferWrite(pBuffer, (DWORD)bCopyFile), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteTab(pBuffer);

      //
      // Copy the file, if requested
      //
      if ((bCopyFile == TRUE) && (fileAttributeData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
      {
         HANDLE hFileRead;

         if (hToken != NULL)
            (VOID)ImpersonateLoggedOnUser(hToken);
         hFileRead = CreateFile(
            szFileName,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
         if (hToken != NULL)
            RevertToSelf();

         if (hFileRead == INVALID_HANDLE_VALUE)
         {
            dwErrorCode = GetLastError();
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot open sysvol file '%S' for read (error %u).%s", COLOR_RED, szFileName, dwErrorCode, COLOR_RESET
            );
         }
         else
         {
            WCHAR szOutPath[MAX_PATH];
            BUFFER_DATA Buffer;

            if (szGuid != NULL)
            {
               swprintf_s(szOutPath, MAX_PATH, L"%s\\%s\\%.*s", pGlobalConfig->szFullSysvolOutDirectory, szDomainName, GUID_STR_SIZE, szGuid);
               bResult = PathFileExists(szOutPath);
               if (bResult == FALSE)
                  CreateDirectory(szOutPath, NULL);

               if (szShortFileName != NULL)
               {
                  swprintf_s(szOutPath, MAX_PATH, L"%s\\%s\\%.*s\\%llu_%s", pGlobalConfig->szFullSysvolOutDirectory, szDomainName, GUID_STR_SIZE, szGuid, hArchiveName, szShortFileName);
               }
               else
               {
                  swprintf_s(szOutPath, MAX_PATH, L"%s\\%s\\%.*s\\%llu", pGlobalConfig->szFullSysvolOutDirectory, szDomainName, GUID_STR_SIZE, szGuid, hArchiveName);
               }
            }
            else
            {
               if (szShortFileName != NULL)
               {
                  swprintf_s(szOutPath, MAX_PATH, L"%s\\%s\\%llu_%s", pGlobalConfig->szFullSysvolOutDirectory, szDomainName, hArchiveName, szShortFileName);
               }
               else
               {
                  swprintf_s(szOutPath, MAX_PATH, L"%s\\%s\\%llu", pGlobalConfig->szFullSysvolOutDirectory, szDomainName, hArchiveName);
               }
            }

            bResult = BufferInitialize(&Buffer, szOutPath, TRUE);  // RAW BUFFER
            if (bResult == TRUE)
            {
               BufferWriteFromFile(&Buffer, hFileRead);
               BufferClose(&Buffer);
            }

            CloseHandle(hFileRead);
         }
      }
      else
      {
         dwErrorCode = dwInitialError;
      }

      // Column 'errorCode'
      _CallWriteAndGetMax(BufferWrite(pBuffer, (DWORD)dwErrorCode), g_dwSysvolMaxLength[dwIdx]);
      ++dwIdx;
      BufferWriteLine(pBuffer);                 // New line for last column
   }

   if (hFile != INVALID_HANDLE_VALUE)
      CloseHandle(hFile);
}