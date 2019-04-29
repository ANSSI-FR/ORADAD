#include <stdio.h>
#include <Shlwapi.h>
#include "tar.h"
#include "../Structures.h"
#include "../Functions.h"
#include "../ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

#define TAR_END_BLOCK_SIZE       1024

BOOL
pTarWriteFile(
   _In_ HANDLE hTarFile,
   _In_z_ LPWSTR szFilename,
   _In_z_ LPWSTR szArchiveName
);

//
// Public functions
//
BOOL
TarInitialize (
   _Out_ PHANDLE phTarFile,
   _In_z_ LPWSTR szFilename
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
      *phTarFile = hFile;
      return TRUE;
   }
}

VOID
TarFilesRecursively (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szFolder,
   _In_ HANDLE hTarFile
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
            TarFilesRecursively(pGlobalConfig, szFullPattern, hTarFile);
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
            bResult = TarFile(pGlobalConfig, szFullPattern, hTarFile);
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
   _In_ HANDLE hTarFile
)
{
   BOOL bResult;
   WCHAR szRelativePath[MAX_PATH] = { 0 };
   size_t stOutDirectoryLength;
   size_t stPathLen;

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[.] Processing file '%S'.", szFileName
   );

   // SKIP prefix
   stOutDirectoryLength = wcslen(pGlobalConfig->szOutDirectory) + 1;
   memcpy_s(szRelativePath, MAX_PATH * sizeof(WCHAR), szFileName + stOutDirectoryLength, (MAX_PATH - stOutDirectoryLength) * sizeof(WCHAR));

   stPathLen = wcslen(szRelativePath);
   // Replace '\' by '/' for tar name
   for (size_t i = 0; i < stPathLen; ++i)
   {
      if (szRelativePath[i] == L'\\')
         szRelativePath[i] = L'/';
   }

   bResult = pTarWriteFile(hTarFile, szFileName, szRelativePath);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot write to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
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

//
// Private functions
//
BOOL
pTarPrepareHeader (
   _Out_ xstar_header* pTarHeader
)
{
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
pTarComputeChecksum (
   _In_ xstar_header* pTarHeader
)
{
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

BOOL
pTarWriteFile (
   _In_ HANDLE hTarFile,
   _In_z_ LPWSTR szFilename,
   _In_z_ LPWSTR szArchiveName
)
{
   BOOL bResult;
   HANDLE hFile;
   LARGE_INTEGER liFileSize;
   LARGE_INTEGER liPosition;
   DWORD dwWritten;
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

   if (liFileSize.QuadPart > MAX_OCTAL_SIZE)
   {
      // TODO: Implement POSIX.1-2001 extended header
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sFile size is too large to fit in standard tar header%s.", COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[+] %sWrite file to tar%s '%S' -> '%S'.", COLOR_CYAN, COLOR_RESET, szFilename, szArchiveName
   );

   xstar_header header;
   pTarPrepareHeader(&header);

   //
   // Process szArchiveName. Split name in t_name and t_prefix if necessary.
   //
   SizeArchiveName = wcslen(szArchiveName);

   if (SizeArchiveName < NAMSIZ)
   {
      sprintf_s(header.t_name, NAMSIZ, "%S", szArchiveName);
   }
   else if (SizeArchiveName < (NAMSIZ + PFXSIZ))
   {
      DWORD dwSplitOffset = PFXSIZ - 1;
      CHAR szArchiveNameA[NAMSIZ + PFXSIZ];

      // Convert to ASCSI
      sprintf_s(szArchiveNameA, NAMSIZ + PFXSIZ, "%S", szArchiveName);
      // Find where to split (i.e. szArchiveName -> t_prefix '/' t_name)
      while ((*(szArchiveNameA + dwSplitOffset) != '/') && (dwSplitOffset>0))
      {
         dwSplitOffset--;
      }
      if (dwSplitOffset == 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sDomain name is too large to fit in standard tar header%s.", COLOR_RED, COLOR_RESET
         );
         return FALSE;
      }
      else
      {
         if ((SizeArchiveName - (dwSplitOffset + 1)) < NAMSIZ)                               // +1 to remove '/'
         {
            // Split
            memcpy(header.t_prefix, szArchiveNameA, dwSplitOffset);
            sprintf_s(header.t_name, NAMSIZ, "%s", szArchiveNameA + dwSplitOffset + 1);      // +1 to remove '/'
         }
         else
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sDomain name is too large to fit in standard tar header%s.", COLOR_RED, COLOR_RESET
            );
            return FALSE;
         }
      }
   }
   else
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sFile name is too large to fit in standard tar header%s.", COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   //
   // Fill header
   //
   sprintf_s(header.t_mode, 8, "%07o", 00777);
   sprintf_s(header.t_uid, 8, "%o", 0);
   sprintf_s(header.t_gid, 8, "%o", 0);
   sprintf_s(header.t_size, 12, "%011llo", liFileSize.QuadPart);
   header.t_typeflag = REGTYPE;

   pTarComputeChecksum(&header);

   bResult = WriteFile(hTarFile, &header, sizeof(xstar_header), &dwWritten, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot write to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

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
            "[!] %sCannot write to tar%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      liPosition.QuadPart += dwRead;
   }

   CloseHandle(hFile);

   return TRUE;
}