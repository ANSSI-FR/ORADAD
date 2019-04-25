#include <stdio.h>
#include "tar.h"
#include "../Structures.h"
#include "../Functions.h"
#include "../ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

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
TarInitialize (
   _Out_ PHANDLE phTarFile,
   _In_z_ LPWSTR szFilename
)
{
   HANDLE hFile = CreateFile(szFilename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot create tar file %S%s (error %u).", COLOR_RED, szFilename, COLOR_RESET, GetLastError()
      );
      *phTarFile = NULL;
      return FALSE;
   }

   *phTarFile = hFile;
   return TRUE;
}

BOOL
TarClose (
   _In_ HANDLE hTarFile
)
{
   DWORD dwWritten = 0;
   BYTE pbendBlock[1024] = { 0 };

   if (hTarFile != NULL)
   {
      WriteFile(hTarFile, pbendBlock, 1024, &dwWritten, NULL);
      return CloseHandle(hTarFile);
   }

   return FALSE;
}

BOOL
TarWriteFile (
   _In_ HANDLE hTarFile,
   _In_z_ LPWSTR szFilename,
   _In_z_ LPWSTR szArchiveName
)
{
   BOOL bResult;
   LARGE_INTEGER liFileSize;
   LARGE_INTEGER liPosition;
   DWORD dwWritten;

   if (hTarFile == NULL)
   {
      return FALSE;
   }

   HANDLE hFile = CreateFile(szFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot open input file %S%s (error %u).", COLOR_RED, szFilename, COLOR_RESET, GetLastError()
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
      "[+] %sWrite file to tar%s [%S] -> [%S].", COLOR_CYAN, COLOR_RESET, szFilename, szArchiveName, GetLastError()
   );

   xstar_header header;
   pTarPrepareHeader(&header);

   sprintf_s(header.t_name, NAMSIZ, "%S", szArchiveName);
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
      DWORD dwWritten;
      CHAR buffer[512] = { 0 };

      bResult = ReadFile(hFile, buffer, 512, &dwRead, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot read from input file%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      if (dwRead != 512)
      {
         memset(buffer + dwRead, 0, 512 - dwRead);
      }

      bResult = WriteFile(hTarFile, buffer, 512, &dwWritten, NULL);
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

   return TRUE;
}