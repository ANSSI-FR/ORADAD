#include <stdio.h>
#include <Shlwapi.h>
#include <intsafe.h>
#include "tar.h"
#include "../ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

#define TAR_END_BLOCK_SIZE       1024
#define TAR_EXTENDED_DATA_SIZE   1024

BOOL
pTarWriteFile(
   _In_ HANDLE hTarFile,
   _In_z_ LPWSTR szFilename,
   _In_z_ LPWSTR szArchiveName,
   _In_ BOOL bExtendedTar
);

//
// Public functions
//
BOOL
TarInitialize (
   _Out_ PHANDLE phTarFile,
   _In_z_ LPWSTR szFilename,
   _In_ BOOL bExtendedTar
)
{
   HANDLE hFile;

   hFile = CreateFile(szFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot create tar file '%S'%s (error %u).", COLOR_RED, szFilename, COLOR_RESET, GetLastError()
      );
      *phTarFile = NULL;
      return FALSE;
   }
   else
   {
      if (bExtendedTar == TRUE)        // If requested, write extended POSIX.1-2001 Header to support file whose size is > MAX_OCTAL_SIZE
      {
         BOOL bResult;
         DWORD dwWritten;
         xstar_header TarExtHeader;

         //
         // Create POSIX.1-2001 Global Extended Header
         //
         TarPrepareHeader(&TarExtHeader);
         sprintf_s(TarExtHeader.t_name, NAMSIZ, "././@PaxHeader");
         sprintf_s(TarExtHeader.t_size, 12, "%011o", 0);
         TarExtHeader.t_typeflag = LF_GHDR;
         TarComputeChecksum(&TarExtHeader);

         bResult = WriteFile(hFile, &TarExtHeader, sizeof(TarExtHeader), &dwWritten, NULL);
         if (bResult == FALSE)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot write extended header to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
            );
            *phTarFile = NULL;
            CloseHandle(hFile);
            return FALSE;
         }
      }

      *phTarFile = hFile;
      return TRUE;
   }
}

VOID
TarFilesRecursively (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szFolder,
   _In_ HANDLE hTarFile,
   _In_ BOOL bExtendedTar
)
{
   BOOL bResult;

   TCHAR szFullPattern[MAX_PATH];
   WIN32_FIND_DATA FindFileData;
   HANDLE hFindFile;

   // first we are going to process any subdirectories
   PathCombine(szFullPattern, szFolder, L"*");
   hFindFile = FindFirstFile(szFullPattern, &FindFileData);
   if (hFindFile != INVALID_HANDLE_VALUE)
   {
      do
      {
         if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
         {
            // found a subdirectory; recurse into it
            if (FindFileData.cFileName[0] == '.')
               continue;
            PathCombine(szFullPattern, szFolder, FindFileData.cFileName);
            TarFilesRecursively(pGlobalConfig, szFullPattern, hTarFile, bExtendedTar);
         }
      } while (FindNextFile(hFindFile, &FindFileData));
      FindClose(hFindFile);
   }

   // now we are going to look for the matching files
   PathCombine(szFullPattern, szFolder, L"*");
   hFindFile = FindFirstFile(szFullPattern, &FindFileData);
   if (hFindFile != INVALID_HANDLE_VALUE)
   {
      do
      {
         if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
         {
            // found a file; do something with it
            PathCombine(szFullPattern, szFolder, FindFileData.cFileName);
            bResult = TarFile(pGlobalConfig, szFullPattern, NULL, hTarFile, bExtendedTar);
            if (bResult == FALSE)
               return;
         }
      } while (FindNextFile(hFindFile, &FindFileData));
      FindClose(hFindFile);
   }
}

BOOL
TarFile (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szFileName,
   _In_opt_z_ LPWSTR szPrefix,
   _In_ HANDLE hTarFile,
   _In_ BOOL bExtendedTar
)
{
   BOOL bResult;
   WCHAR szRelativePath[MAX_PATH];
   size_t stOutDirectoryLength;
   size_t stPathLen;

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[.] Processing file '%S'.", szFileName
   );

   // SKIP prefix
   stOutDirectoryLength = wcslen(pGlobalConfig->szOutDirectory) + 1;
   if (szPrefix == NULL)
      swprintf_s(szRelativePath, MAX_PATH, L"%s", szFileName + stOutDirectoryLength);
   else
      swprintf_s(szRelativePath, MAX_PATH, L"%s/%s", szPrefix, szFileName + stOutDirectoryLength);

   // Replace '\' by '/' for tar name
   stPathLen = wcslen(szRelativePath);
   for (size_t i = 0; i < stPathLen; ++i)
   {
      if (szRelativePath[i] == L'\\')
         szRelativePath[i] = L'/';
   }

   bResult = pTarWriteFile(hTarFile, szFileName, szRelativePath, bExtendedTar);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot write file to tar%s.", COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   return TRUE;
}

BOOL
TarClose (
   _In_ HANDLE hTarFile
)
{
   DWORD dwWritten = 0;
   BYTE pbendBlock[TAR_END_BLOCK_SIZE] = { 0 };

   if (hTarFile != NULL)
   {
      WriteFile(hTarFile, pbendBlock, TAR_END_BLOCK_SIZE, &dwWritten, NULL);
      return CloseHandle(hTarFile);
   }

   return FALSE;
}

BOOL
TarPrepareHeader (
   _Out_ PVOID pVoidTarHeader
)
{
   xstar_header* pTarHeader = (xstar_header*)pVoidTarHeader;

   if (pTarHeader != NULL)
   {
      ZeroMemory(pTarHeader, sizeof(xstar_header));
      strncpy_s(pTarHeader->t_magic, TMAGLEN, "ustar", 6);
      pTarHeader->t_version[0] = '0';
      pTarHeader->t_version[1] = '0';

      return TRUE;
   }

   return FALSE;
}

BOOL
TarComputeChecksum (
   _Out_ PVOID pVoidTarHeader
)
{
   xstar_header* pTarHeader = (xstar_header*)pVoidTarHeader;

   if (pTarHeader != NULL)
   {
      unsigned i = 0;
      unsigned res = 256;
      unsigned char* p = (unsigned char*)pTarHeader;

      for (i = 0; i < offsetof(xstar_header, t_chksum); ++i)
         res += p[i];

      for (i = offsetof(xstar_header, t_typeflag); i < sizeof(xstar_header); ++i)
         res += p[i];

      sprintf_s(pTarHeader->t_chksum, 8, "%06o ", res);

      return TRUE;
   }

   return FALSE;
}

//
// Private functions
//

BOOL
pTarWriteFile (
   _In_ HANDLE hTarFile,
   _In_z_ LPWSTR szFilename,
   _In_z_ LPWSTR szArchiveName,
   _In_ BOOL bExtendedTar
)
{
   BOOL bResult;
   HANDLE hFile;
   LARGE_INTEGER liFileSize;
   LARGE_INTEGER liPosition;
   DWORD dwWritten;
   LPSTR szArchiveNameA;
   size_t SizeArchiveName;

   if (hTarFile == NULL)
   {
      return FALSE;
   }

   // FILE_SHARE_WRITE is necessary for oradad.log which is open by current process
   hFile = CreateFile(szFilename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot open input file '%S'%s (error %u).", COLOR_RED, szFilename, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   bResult = GetFileSizeEx(hFile, &liFileSize);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot get file size%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   if ((liFileSize.QuadPart > MAX_OCTAL_SIZE) && (bExtendedTar==TRUE))
   {
      int sTmp;
      char szExtendedData[TAR_EXTENDED_DATA_SIZE] = { 0 };
      xstar_header TarExtHeader;

      //
      // Put size in a POSIX.1-2001 Extended Header
      //
      sTmp = sprintf_s(szExtendedData, TAR_EXTENDED_DATA_SIZE, " size=%llu\n", liFileSize.QuadPart);
      sTmp += sprintf_s(szExtendedData, TAR_EXTENDED_DATA_SIZE, "%d", sTmp);
      sTmp = sprintf_s(szExtendedData, TAR_EXTENDED_DATA_SIZE, "%d size=%llu\n", sTmp, liFileSize.QuadPart);

      TarPrepareHeader(&TarExtHeader);
      sprintf_s(TarExtHeader.t_name, NAMSIZ, "././@PaxHeader");
      sprintf_s(TarExtHeader.t_size, 12, "%011o", sTmp);
      TarExtHeader.t_typeflag = LF_XHDR;
      TarComputeChecksum(&TarExtHeader);

      bResult = WriteFile(hTarFile, &TarExtHeader, sizeof(TarExtHeader), &dwWritten, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot write extended header to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }
      bResult = WriteFile(hTarFile, szExtendedData, ((sTmp / TBLOCK) + 1) * TBLOCK, &dwWritten, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot write extended header to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }
   }

   //
   // Add file to TAR (header + data)
   //
   xstar_header TarHeader;

   TarPrepareHeader(&TarHeader);

   // Convert filename to ASCII and get size
   szArchiveNameA = LPWSTRtoLPSTR(szArchiveName);
   if (szArchiveNameA == NULL)
   {
      return FALSE;
   }
   SizeArchiveName = strlen(szArchiveNameA);

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[+] %sAdd file to tar%s '%S' -> '%s'.",
      COLOR_CYAN, COLOR_RESET,
      szFilename, szArchiveNameA
   );

   //
   // Process szArchiveName: split name in t_name and t_prefix if necessary.
   //
   if (SizeArchiveName < NAMSIZ)
   {
      strcpy_s(TarHeader.t_name, NAMSIZ, szArchiveNameA);
   }
   else if (SizeArchiveName < (NAMSIZ + PFXSIZ))
   {
      DWORD dwSplitOffset;

      if (SIZETToDWord(SizeArchiveName - 1, &dwSplitOffset) != S_OK)
         return FALSE;

      // Find where to split (i.e. szArchiveName -> t_prefix '/' t_name)
      while ((*(szArchiveNameA + dwSplitOffset) != '/') && (dwSplitOffset > 0))
      {
         dwSplitOffset--;
      }
      if (dwSplitOffset == 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sNo slash found in filename%s ('%s').",
            COLOR_RED, COLOR_RESET, szArchiveNameA
         );
         return FALSE;
      }
      else
      {
         if (((SizeArchiveName - (dwSplitOffset + 1)) <= (NAMSIZ -1))                           // +1 to remove '/', -1 to have '\0'
            && ((dwSplitOffset <= (PFXSIZ - 1))))                                               // -1 to have '\0'
         {
            // Split
            szArchiveNameA[dwSplitOffset] = 0;
            strcpy_s(TarHeader.t_prefix, PFXSIZ, szArchiveNameA);
            strcpy_s(TarHeader.t_name, NAMSIZ, szArchiveNameA + dwSplitOffset + 1);
         }
         else
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %s Unable to split filename%s ('%s').",
               COLOR_RED, COLOR_RESET, szArchiveNameA
            );
            return FALSE;
         }
      }
   }
   else
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sFile name is too long to fit in standard tar header%s ('%s').",
         COLOR_RED, COLOR_RESET, szArchiveNameA
      );
      return FALSE;
   }

   //
   // Fill header
   //
   sprintf_s(TarHeader.t_mode, 8, "%07o", 00777);
   sprintf_s(TarHeader.t_uid, 8, "%o", 0);
   sprintf_s(TarHeader.t_gid, 8, "%o", 0);
   sprintf_s(TarHeader.t_size, 12, "%011llo", liFileSize.QuadPart <= MAX_OCTAL_SIZE ? liFileSize.QuadPart : 0);
   TarHeader.t_typeflag = REGTYPE;

   TarComputeChecksum(&TarHeader);

   //
   // Write header to tar
   //
   bResult = WriteFile(hTarFile, &TarHeader, sizeof(TarHeader), &dwWritten, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot write header to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   //
   // Write data to tar
   //
   liPosition.QuadPart = 0;

   while (liPosition.QuadPart < liFileSize.QuadPart)
   {
      DWORD dwRead;
      CHAR buffer[TBLOCK];

      bResult = ReadFile(hFile, buffer, TBLOCK, &dwRead, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot read from input file%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      if (dwRead != TBLOCK)
      {
         memset(buffer + dwRead, 0, TBLOCK - dwRead);
      }

      bResult = WriteFile(hTarFile, buffer, TBLOCK, &dwWritten, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot write file to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      liPosition.QuadPart += dwRead;
   }

   CloseHandle(hFile);
   _SafeHeapRelease(szArchiveNameA);

   return TRUE;
}