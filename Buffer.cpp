#include <Windows.h>
#include <tchar.h>
#include "ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

//
// Public functions
//
BOOL
BufferInitialize (
   _Out_ PBUFFER_DATA pBuffer,
   _In_z_ LPWSTR szFilename
)
{
   ZeroMemory(pBuffer, sizeof(BUFFER_DATA));

   pBuffer->hOutputFile = CreateFile(szFilename, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, NULL, 0);

   if (pBuffer->hOutputFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open outfile %S%s (error %u).", COLOR_RED, szFilename, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   pBuffer->BufferSize = 1024 * 1024;
   pBuffer->pbData = (PBYTE)_HeapAlloc(pBuffer->BufferSize);
   _tcscpy_s(pBuffer->szFileName, MAX_PATH, szFilename);

   if (GetLastError() == ERROR_ALREADY_EXISTS)
   {
      SetFilePointer(pBuffer->hOutputFile, 0, 0, FILE_END);
   }
   else
   {
      // Write UTF-16 BOM
      BYTE pbBomUTF16LE[2] = { 0xFF, 0xFE };
      BufferWrite(pBuffer, pbBomUTF16LE, 2);
   }

   return TRUE;
}

BOOL
BufferClose (
   _Out_ PBUFFER_DATA pBuffer
)
{
   BufferSave(pBuffer);
   _SafeHeapRelease(pBuffer->pbData);
   CloseHandle(pBuffer->hOutputFile);

   return TRUE;
}

DWORD
BufferWrite (
   _Out_ PBUFFER_DATA pBuffer,
   _In_reads_bytes_(dwNumberOfBytesToWrite) LPVOID pvData,
   _In_ DWORD dwNumberOfBytesToWrite
)
{
   if (pBuffer == NULL)
      return 0;

   if (pBuffer->pbData == NULL)
      return 0;

   if (dwNumberOfBytesToWrite >= pBuffer->BufferSize)
   {
      // Can't write data bigger than buffer size
      return 0;
   }
   else if ((pBuffer->BufferSize - pBuffer->Position) >= dwNumberOfBytesToWrite)
   {
      // Copy data to buffer
      memcpy(pBuffer->pbData + pBuffer->Position, pvData, dwNumberOfBytesToWrite);
      pBuffer->Position += dwNumberOfBytesToWrite;
      return dwNumberOfBytesToWrite;
   }
   else
   {
      BOOL bResult;

      // Save buffer
      bResult = BufferSave(pBuffer);

      // Copy data to buffer
      memcpy(pBuffer->pbData + pBuffer->Position, pvData, dwNumberOfBytesToWrite);
      pBuffer->Position += dwNumberOfBytesToWrite;
      return dwNumberOfBytesToWrite;
   }
}

DWORD
BufferWrite (
   _Out_ PBUFFER_DATA pBuffer,
   _Inout_opt_ LPWSTR szString
)
{
   size_t StringSize;

   if (pBuffer == NULL)
      return FALSE;

   if (pBuffer->pbData == NULL)
      return FALSE;

   if (szString == NULL)
      return TRUE;

   StringSize = wcslen(szString);
   RemoveSpecialChars(szString);

   if (StringSize == ((size_t)(-1)))
      return FALSE;
   else if (StringSize == 0)
      return TRUE;
   else
      return BufferWrite(pBuffer, szString, (DWORD)(StringSize * sizeof(WCHAR)));
}

DWORD
BufferWriteHex (
   _Out_ PBUFFER_DATA pBuffer,
   _In_reads_(dwDataSize) PBYTE pbData,
   _In_ DWORD dwDataSize
)
{
   DWORD dwDataSizeSum = 0;

   for (DWORD i = 0; i < dwDataSize; i++)
   {
      WCHAR szChar[3];

      swprintf_s(szChar, 3, L"%02x", pbData[i]);
      dwDataSizeSum += BufferWrite(pBuffer, szChar, 4);
   }

   return dwDataSizeSum;
}

DWORD
BufferWriteLine (
   _Out_ PBUFFER_DATA pBuffer
)
{
   return BufferWrite(pBuffer, (LPVOID)L"\r\n", 2 * sizeof(WCHAR));
}

DWORD
BufferWriteTab (
   _Out_ PBUFFER_DATA pBuffer
)
{
   return BufferWrite(pBuffer, (LPVOID)L"\t", 2);
}

DWORD
BufferWriteSemicolon (
   _Out_ PBUFFER_DATA pBuffer
)
{
   return BufferWrite(pBuffer, (LPVOID)L";", 2);
}

BOOL
BufferSave (
   _In_ PBUFFER_DATA pBuffer
)
{
   BOOL bReturn = FALSE;
   BOOL bResult;
   DWORD dwBytesWritten;

   if (pBuffer == NULL)
      return FALSE;

   //
   // Write buffer to file without modification
   //
   bResult = WriteFile(pBuffer->hOutputFile, pBuffer->pbData, pBuffer->Position, &dwBytesWritten, NULL);
   bReturn = bResult;

   // Reset buffer position
   pBuffer->Position = 0;

   return TRUE;
}