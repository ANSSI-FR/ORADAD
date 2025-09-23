#include <Windows.h>
#include <tchar.h>
#include <intsafe.h>
#include "ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;
extern GLOBAL_CONFIG g_GlobalConfig;

#define READ_BUFFER_SIZE 1024 * 1024

#define MAX_FIELD_SIZE   1024 * 1024

//
// Private functions
//
DWORD
pBufferWriteInternal(
   _In_ PBUFFER_DATA pBuffer,
   _In_reads_bytes_opt_(dwNumberOfBytesToWrite) LPVOID pvData,
   _In_ DWORD dwNumberOfBytesToWrite,
   _Inout_opt_ PDWORD pdwFieldWritten,
   _Inout_opt_ PBOOL pbWriteError,
   _In_opt_z_ LPWSTR szDn,
   _In_opt_z_ LPWSTR szAttribute
);

//
// Public functions
//
BOOL
BufferInitialize (
   _Out_ PBUFFER_DATA pBuffer,
   _In_z_ LPCWSTR szFilename,
   _In_ BOOL bWriteBomHeader,
   _In_ BOOL bSysvolOutput
)
{
   WCHAR szFilePath[MAX_PATH];

   // Create buffer
   ZeroMemory(pBuffer, sizeof(BUFFER_DATA));
   pBuffer->BufferSize = READ_BUFFER_SIZE;
   pBuffer->pbData = (PBYTE)_HeapAlloc(pBuffer->BufferSize);

   if (g_GlobalConfig.bOutputFiles == TRUE)
   {
      //
      // Format filename
      //
      swprintf(
         szFilePath, MAX_PATH,
         L"%s\\%s",
         bSysvolOutput ? g_GlobalConfig.szFileSysvolOutDirectory : g_GlobalConfig.szFileOutDirectory,
         szFilename
      );

      _tcscpy_s(pBuffer->szFileName, MAX_PATH, szFilePath);

      pBuffer->hOutputFile = CreateFile(pBuffer->szFileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, NULL, 0);
      if (pBuffer->hOutputFile == INVALID_HANDLE_VALUE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to open outfile%s '%S' (error %u).",
            COLOR_RED, COLOR_RESET,
            pBuffer->szFileName, GetLastError()
         );
         return FALSE;
      }
   }

   if (g_GlobalConfig.bOutputMLA == TRUE)
   {
      BOOL bResult;

      //
      // Format filename
      //
      swprintf(
         szFilePath, MAX_PATH,
         L"%s\\%s",
         bSysvolOutput ? g_GlobalConfig.szMlaSysvolOutDirectory : g_GlobalConfig.szMlaOutDirectory,
         szFilename
      );

      bResult = MlaAddFile(szFilePath, &pBuffer->hMlaFile);
      if (bResult == FALSE)
         return FALSE;
   }

   // Write UTF-16 BOM if buffer is not raw
   if (bWriteBomHeader == TRUE)
   {
      BYTE pbBomUTF16LE[2] = { 0xFF, 0xFE };

      pBufferWriteInternal(pBuffer, pbBomUTF16LE, 2, NULL, NULL, NULL, NULL);
   }

   return TRUE;
}

BOOL
BufferClose (
   _Inout_ PBUFFER_DATA pBuffer
)
{
   BOOL bResult;

   bResult = BufferSave(pBuffer);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to save buffer%s.",
         COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   _SafeHeapRelease(pBuffer->pbData);
   _SafeHeapRelease(pBuffer->pbDataCompress);
   _SafeHeapRelease(pBuffer->pbDataEncrypt);

   if (g_GlobalConfig.bOutputFiles == TRUE)
      CloseHandle(pBuffer->hOutputFile);

   if (g_GlobalConfig.bOutputMLA == TRUE)
   {
      MlaCloseFile(&pBuffer->hMlaFile);
   }

   return TRUE;
}

DWORD
BufferWrite (
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString,
   _Inout_opt_ PDWORD pdwFieldWritten,
   _Inout_opt_ PBOOL pbWriteError,
   _In_opt_z_ LPWSTR szDn,
   _In_opt_z_ LPWSTR szAttribute
)
{
   size_t StringSize;

   if (pBuffer == NULL)
      return 0;

   if (pBuffer->pbData == NULL)
      return 0;

   if (szString == NULL)
      return 0;

   StringSize = wcslen(szString);
   RemoveSpecialChars(szString);

   if (StringSize == ((size_t)(-1)))
      return 0;
   else if (StringSize == 0)
      return 0;
   else
      return pBufferWriteInternal(pBuffer, szString, (DWORD)(StringSize * sizeof(WCHAR)), pdwFieldWritten, pbWriteError, szDn, szAttribute);
}

DWORD
BufferWrite (
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString
)
{
   return BufferWrite(pBuffer, szString, NULL, NULL, NULL, NULL);
}

DWORD
BufferWriteStringWithLimit (
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString,
   _In_ DWORD dwLimit,
   _Inout_opt_ PDWORD pdwFieldWritten,
   _Inout_opt_ PBOOL pbWriteError,
   _In_opt_z_ LPWSTR szDn,
   _In_opt_z_ LPWSTR szAttribute
)
{
   size_t StringSize;

   if (dwLimit == 0)
      return BufferWrite(pBuffer, szString, pdwFieldWritten, pbWriteError, szDn, szAttribute);

   if (pBuffer == NULL)
      return 0;

   if (pBuffer->pbData == NULL)
      return 0;

   if (szString == NULL)
      return 0;

   StringSize = min(wcslen(szString), dwLimit);
   RemoveSpecialChars(szString);

   if (StringSize == ((size_t)(-1)))
      return 0;
   else if (StringSize == 0)
      return 0;
   else
      return pBufferWriteInternal(pBuffer, szString, (DWORD)(StringSize * sizeof(WCHAR)), pdwFieldWritten, pbWriteError, szDn, szAttribute);
}

DWORD
BufferWriteStringWithLimit (
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString,
   _In_ DWORD dwLimit
)
{
   return BufferWriteStringWithLimit(pBuffer, szString, dwLimit, NULL, NULL, NULL, NULL);
}

DWORD
BufferWrite (
   _In_ PBUFFER_DATA pBuffer,
   _In_ const FILETIME *fileTime
)
{
   SYSTEMTIME st;
   WCHAR szDate[DATE_MAX_STR_SIZE];

   FileTimeToSystemTime(fileTime, &st);
   if (st.wYear > 9999)
      st.wYear = 9999;
   swprintf_s(
      szDate, DATE_MAX_STR_SIZE,
      DATE_FORMAT,
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
   );

   return BufferWrite(pBuffer, szDate);
}

DWORD
BufferWrite (
   _In_ PBUFFER_DATA pBuffer,
   _In_ DWORD dwValue
)
{
   wchar_t intTmp[_MAX_ULTOSTR_BASE10_COUNT];
   _ultow_s(dwValue, intTmp, _MAX_ULTOSTR_BASE10_COUNT, 10);
   return BufferWrite(pBuffer, intTmp);
}

DWORD
BufferWrite (
   _In_ PBUFFER_DATA pBuffer,
   _In_ LONGLONG dwValue
)
{
   wchar_t intTmp[_MAX_I64TOSTR_BASE10_COUNT];
   _i64tow_s(dwValue, intTmp, _MAX_I64TOSTR_BASE10_COUNT, 10);
   return BufferWrite(pBuffer, intTmp);
}

DWORD
BufferWrite (
   _In_ PBUFFER_DATA pBuffer,
   _In_ unsigned long long dwValue
)
{
   wchar_t intTmp[_MAX_U64TOSTR_BASE10_COUNT];
   _ui64tow_s(dwValue, intTmp, _MAX_U64TOSTR_BASE10_COUNT, 10);
   return BufferWrite(pBuffer, intTmp);
}

DWORD
BufferWriteFromFile (
   _In_ PBUFFER_DATA pBuffer,
   _In_ HANDLE hFile
)
{
   BOOL bResult;
   DWORD dwBytesWritten = 0;
   LARGE_INTEGER liFileSize;
   LARGE_INTEGER liFilePos;
   PBYTE pReadBuffer = NULL;

   bResult = GetFileSizeEx(hFile, &liFileSize);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot get file size%s (error %u).",
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      return 0;
   }

   pReadBuffer = (PBYTE)_HeapAlloc(READ_BUFFER_SIZE);
   if (pReadBuffer == NULL)
      return 0;

   liFilePos.QuadPart = 0;
   while (liFilePos.QuadPart < liFileSize.QuadPart)
   {
      DWORD dwReadLength = READ_BUFFER_SIZE;

      bResult = ReadFile(hFile, pReadBuffer, READ_BUFFER_SIZE, &dwReadLength, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot read file%s (error %u).",
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         break;
      }

      liFilePos.QuadPart += dwReadLength;
      dwBytesWritten = pBufferWriteInternal(pBuffer, pReadBuffer, dwReadLength, NULL, NULL, NULL, NULL);
   }

   _SafeHeapRelease(pReadBuffer);
   return dwBytesWritten;
}

DWORD
BufferWriteHex (
   _Inout_ PBUFFER_DATA pBuffer,
   _In_reads_(dwDataSize) PBYTE pbData,
   _In_ DWORD dwDataSize
)
{
   DWORD dwDataSizeSum = 0;

   for (DWORD i = 0; i < dwDataSize; i++)
   {
      WCHAR szChar[3];

      swprintf_s(szChar, 3, L"%02x", pbData[i]);
      dwDataSizeSum += pBufferWriteInternal(pBuffer, szChar, 4, NULL, NULL, NULL, NULL);
   }

   return dwDataSizeSum;
}

DWORD
BufferWriteLine (
   _In_ PBUFFER_DATA pBuffer
)
{
   return pBufferWriteInternal(pBuffer, (LPVOID)L"\r\n", 2 * sizeof(WCHAR), NULL, NULL, NULL, NULL);
}

DWORD
BufferWriteTab (
   _In_ PBUFFER_DATA pBuffer
)
{
   return pBufferWriteInternal(pBuffer, (LPVOID)L"\t", 2, NULL, NULL, NULL, NULL);
}

DWORD
BufferWriteSemicolon (
   _In_ PBUFFER_DATA pBuffer
)
{
   return pBufferWriteInternal(pBuffer, (LPVOID)L";", 2, NULL, NULL, NULL, NULL);
}

BOOL
BufferSave (
   _In_ PBUFFER_DATA pBuffer
)
{
   BOOL bReturn = TRUE;
   BOOL bResult;
   PBYTE pbOutBuffer;

   if (pBuffer == NULL)
      return FALSE;

   pbOutBuffer = pBuffer->pbData;

   if (g_GlobalConfig.bOutputFiles == TRUE)
   {
      DWORD dwBytesWritten;
      DWORD dwOutBufferLength;

      //
      // Write buffer to file
      //
      if (SIZETToDWord(pBuffer->Position, &dwOutBufferLength) != S_OK)
         return FALSE;

      bResult = WriteFile(pBuffer->hOutputFile, pbOutBuffer, dwOutBufferLength, &dwBytesWritten, NULL);
      if (bResult == TRUE)
      {
         pBuffer->ulFileSize += dwBytesWritten;
      }
      else
         bReturn = FALSE;
   }

   if (g_GlobalConfig.bOutputMLA == TRUE)
   {
      bResult = MlaBufferWrite(pBuffer->hMlaFile, pbOutBuffer, pBuffer->Position);
   }

   //
   // Reset output buffer position
   //
   if (bReturn == TRUE)
      pBuffer->Position = 0;

   return bReturn;
}

//
// Private functions
//
DWORD
pBufferWriteInternal (
   _In_ PBUFFER_DATA pBuffer,
   _In_reads_bytes_opt_(dwNumberOfBytesToWrite) LPVOID pvData,
   _In_ DWORD dwNumberOfBytesToWrite,
   _Inout_opt_ PDWORD pdwFieldWritten,
   _Inout_opt_ PBOOL pbWriteError,
   _In_opt_z_ LPWSTR szDn,
   _In_opt_z_ LPWSTR szAttribute
)
{
   if (pBuffer == NULL)
      return 0;

   if (pBuffer->pbData == NULL)
      return 0;

   if (pvData == NULL)
      return 0;

   if (dwNumberOfBytesToWrite == 0)
      return 0;

   //
   // If the data written to the field exceeds MAX_FIELD_SIZE,
   // the rest of the data is truncated to never exceed MAX_FIELD_SIZE
   //  - The size written in the field is given by pdwFieldWritten
   //  - pbWriteError allows, in case of truncation, to display
   //    an error message only once for the field
   //
   if (pdwFieldWritten != NULL)
   {
      if ((*pdwFieldWritten + dwNumberOfBytesToWrite) > MAX_FIELD_SIZE)
      {
         dwNumberOfBytesToWrite = (MAX_FIELD_SIZE - *pdwFieldWritten);
         if (pbWriteError != NULL)
         {
            if (*pbWriteError == TRUE)
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
                  "[!] %sAttribute is truncated%s (%s|%s).",
                  COLOR_YELLOW, COLOR_RESET,
                  szDn, szAttribute
               );
               *pbWriteError = FALSE;
            }
         }
      }
   }

   if (dwNumberOfBytesToWrite > pBuffer->BufferSize)
   {
      BOOL bResult;
      DWORD dwTotalBytesWritten = 0;

      // Data bigger than buffer size
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
         "[!] %sBuffer is too small to receive the data%s (data size=%u).",
         COLOR_YELLOW, COLOR_RESET,
         dwNumberOfBytesToWrite
      );

      // Save current buffer
      bResult = BufferSave(pBuffer);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to save buffer%s.",
            COLOR_RED, COLOR_RESET
         );
         return 0;
      }

      // Write chunk by chunk
      while (dwTotalBytesWritten != dwNumberOfBytesToWrite)
      {
         DWORD dwBytesWritten = 0;
         DWORD dwBytesToWrite;

         dwBytesToWrite = min((DWORD)pBuffer->BufferSize, dwNumberOfBytesToWrite - dwTotalBytesWritten);

         dwBytesWritten = pBufferWriteInternal(pBuffer, &((PBYTE)pvData)[dwTotalBytesWritten], dwBytesToWrite, pdwFieldWritten, pbWriteError, szDn, szAttribute);
         dwTotalBytesWritten += dwBytesWritten;
         if (pdwFieldWritten != NULL)
            *pdwFieldWritten += dwBytesWritten;
      }

      return dwTotalBytesWritten;
   }
   else if ((pBuffer->BufferSize - pBuffer->Position) >= dwNumberOfBytesToWrite)
   {
      // Copy data to buffer
      memcpy(pBuffer->pbData + pBuffer->Position, pvData, dwNumberOfBytesToWrite);
      pBuffer->Position += dwNumberOfBytesToWrite;
      if (pdwFieldWritten != NULL)
         *pdwFieldWritten += dwNumberOfBytesToWrite;
      return dwNumberOfBytesToWrite;
   }
   else
   {
      BOOL bResult;

      // Save buffer
      bResult = BufferSave(pBuffer);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to save buffer%s.",
            COLOR_RED, COLOR_RESET
         );
         return 0;
      }

      // Copy data to buffer
      memcpy(pBuffer->pbData + pBuffer->Position, pvData, dwNumberOfBytesToWrite);
      pBuffer->Position += dwNumberOfBytesToWrite;
      if (pdwFieldWritten != NULL)
         *pdwFieldWritten += dwNumberOfBytesToWrite;
      return dwNumberOfBytesToWrite;
   }
}
