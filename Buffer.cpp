#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <wincrypt.h>
#include <intsafe.h>
#include "ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;
extern GLOBAL_CONFIG g_GlobalConfig;

static const LZ4F_preferences_t lz4Prefs = {
   { LZ4F_max1MB, LZ4F_blockLinked, LZ4F_contentChecksumEnabled, LZ4F_frame, 0, 0, LZ4F_noBlockChecksum },
   0,       // compressionLevel
   1,       // autoFlush
   0,       //favorDecSpeed
{ 0, 0, 0}  //Reserved
};

//
// Public functions
//
BOOL
BufferInitialize (
   _Out_ PBUFFER_DATA pBuffer,
   _In_z_ LPWSTR szFilename
)
{
   BOOL bResult;
   PBUFFER_HEADER pBufferHeader;

   pBufferHeader = (PBUFFER_HEADER)_HeapAlloc(sizeof(BUFFER_HEADER));
   if (pBufferHeader == NULL)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot allocate memory%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   ZeroMemory(pBuffer, sizeof(BUFFER_DATA));

   if (g_GlobalConfig.bCompressionEnabled || g_GlobalConfig.bEncryptionEnabled)
   {
      // Add suffix for compressed / encrypted files
      swprintf_s(pBuffer->szFileName, MAX_PATH, L"%s.oradad", szFilename);
   }
   else
      _tcscpy_s(pBuffer->szFileName, MAX_PATH, szFilename);

   pBuffer->hOutputFile = CreateFile(pBuffer->szFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, NULL, 0);

   if (pBuffer->hOutputFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open outfile '%S'%s (error %u).", COLOR_RED, pBuffer->szFileName, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   pBuffer->BufferSize = 1024 * 1024;
   pBuffer->pbData = (PBYTE)_HeapAlloc(pBuffer->BufferSize);

   pBufferHeader->Magic[0] = 'O';
   pBufferHeader->Magic[1] = 'R';
   pBufferHeader->Magic[2] = 'A';
   pBufferHeader->Magic[3] = 'D';
   pBufferHeader->Magic[4] = 'A';
   pBufferHeader->Magic[5] = 'D';
   pBufferHeader->BufferVersion = BUFFER_VERSION;

   // Compression
   if (g_GlobalConfig.bCompressionEnabled)
   {
      LZ4F_errorCode_t lz4err;
      lz4err = LZ4F_createCompressionContext(&(pBuffer->lz4Ctx), LZ4F_VERSION);
      if (lz4err != 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to create compression context %s (error %u - %s).", COLOR_RED, COLOR_RESET, lz4err, LZ4F_getErrorName(lz4err)
         );
         return FALSE;
      }

      pBuffer->DataCompressSize = LZ4F_compressBound(pBuffer->BufferSize, &lz4Prefs);
      // Allocate double to allow compressUpdate and compressEnd to fit in the safe buffer
      pBuffer->pbDataCompress = (PBYTE)_HeapAlloc(pBuffer->DataCompressSize * 2);

      pBufferHeader->Flags |= BUFFER_COMPRESSED;
   }

   // Encryption
   if (g_GlobalConfig.bEncryptionEnabled)
   {
      DWORD dwRsaBufferLen = 0;
      PBYTE pbRsaBuffer = NULL;
      DWORD dwKeyBlobLen = 0;
      PBYTE pbKeyBlob = NULL;
      HCRYPTKEY hRsaKey;
      DWORD dwKeyExportLen = 0;
      PBYTE pbKeyExport = NULL;
      DWORD dwSize = sizeof(DWORD);

      //
      // Make room for encryption
      //
      bResult = CryptAcquireContext(&(pBuffer->hProv), NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to get Cryptographic Provider%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Get SHA256 provider
      //
      bResult = CryptCreateHash(pBuffer->hProv, CALG_SHA_256, 0, 0, &(pBuffer->hHash));
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to get Cryptographic Hash%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Generate a key
      //
      bResult = CryptGenKey(pBuffer->hProv, CALG_AES_256, CRYPT_EXPORTABLE, &(pBuffer->hCryptKey));
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to generate Cryptographic Key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Get Block length
      //
      bResult = CryptGetKeyParam(pBuffer->hCryptKey, KP_BLOCKLEN, (BYTE *)&(pBuffer->dwEncryptBlockLen), &dwSize, 0);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to get block size%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Allocate encryption buffer
      //
      pBuffer->DataEncryptSize = ((pBuffer->BufferSize / pBuffer->dwEncryptBlockLen) + 1) * pBuffer->dwEncryptBlockLen;
      pBuffer->pbDataEncrypt = (PBYTE)_HeapAlloc(pBuffer->DataEncryptSize);

      //
      // Convert then import RSA Public Key
      //
      bResult = CryptStringToBinary(g_GlobalConfig.szPublicKey, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwRsaBufferLen, NULL, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to parse RSA public key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      pbRsaBuffer = (PBYTE)_HeapAlloc(dwRsaBufferLen);

      bResult = CryptStringToBinary(g_GlobalConfig.szPublicKey, 0, CRYPT_STRING_BASE64HEADER, pbRsaBuffer, &dwRsaBufferLen, NULL, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to parse RSA public key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      bResult = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pbRsaBuffer, dwRsaBufferLen, 0, NULL, NULL, &dwKeyBlobLen);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to parse RSA public key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      pbKeyBlob = (PBYTE)_HeapAlloc(dwKeyBlobLen);

      bResult = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pbRsaBuffer, dwRsaBufferLen, 0, NULL, pbKeyBlob, &dwKeyBlobLen);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to parse RSA public key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      bResult = CryptImportKey(pBuffer->hProv, pbKeyBlob, dwKeyBlobLen, NULL, 0, &hRsaKey);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to import RSA public key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Export AES key
      //
      bResult = CryptExportKey(pBuffer->hCryptKey, hRsaKey, SIMPLEBLOB, 0, NULL, &dwKeyExportLen);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to export AES key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      pbKeyExport = (PBYTE)_HeapAlloc(dwKeyExportLen);

      bResult = CryptExportKey(pBuffer->hCryptKey, hRsaKey, SIMPLEBLOB, 0, pbKeyExport, &dwKeyExportLen);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to export AES key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      pBufferHeader->Flags |= BUFFER_ENCRYPTED;
      pBufferHeader->dwExtraDataLen = dwKeyExportLen;
      pBufferHeader = (PBUFFER_HEADER)HeapReAlloc(g_hHeap, HEAP_ZERO_MEMORY, pBufferHeader, sizeof(BUFFER_HEADER) + pBufferHeader->dwExtraDataLen);
      if (pBufferHeader == NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot allocate memory%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }
      memcpy_s(pBufferHeader->bExtraData, pBufferHeader->dwExtraDataLen, pbKeyExport, dwKeyExportLen);

      CryptDestroyKey(hRsaKey);
      _SafeHeapRelease(pbKeyExport);
      _SafeHeapRelease(pbKeyBlob);
   }

   if (pBufferHeader->Flags != 0)
   {
      DWORD dwBytesWritten = 0;

      bResult = WriteFile(pBuffer->hOutputFile, pBufferHeader, sizeof(BUFFER_HEADER) + pBufferHeader->dwExtraDataLen, &dwBytesWritten, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot write buffer header%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }
   }

   _SafeHeapRelease(pBufferHeader);

   // Call initialization functions
   if (g_GlobalConfig.bCompressionEnabled)
   {
      size_t compressSize;

      compressSize = LZ4F_compressBegin(pBuffer->lz4Ctx, pBuffer->pbDataCompress, pBuffer->DataCompressSize, &lz4Prefs);
      if (compressSize < 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to begin compression %s (error %u).", COLOR_RED, COLOR_RESET, compressSize
         );
         return FALSE;
      }
      pBuffer->PositionCompress += compressSize;
   }

   // FIXME: pertinent?
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
   BOOL bResult;

   bResult = BufferSave(pBuffer, TRUE);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to save buffer%s.", COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   _SafeHeapRelease(pBuffer->pbData);
   _SafeHeapRelease(pBuffer->pbDataCompress);
   _SafeHeapRelease(pBuffer->pbDataEncrypt);

   if (pBuffer->lz4Ctx != NULL)
      LZ4F_freeCompressionContext(pBuffer->lz4Ctx);
   if (pBuffer->hCryptKey != NULL)
      CryptDestroyKey(pBuffer->hCryptKey);
   if (pBuffer->hHash != NULL)
      CryptDestroyHash(pBuffer->hHash);
   if (pBuffer->hProv != NULL)
      CryptReleaseContext(pBuffer->hProv, 0);

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
      bResult = BufferSave(pBuffer, FALSE);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to save buffer%s.", COLOR_RED, COLOR_RESET
         );
         return 0;
      }

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
   _In_ PBUFFER_DATA pBuffer,
   _In_ BOOL bFinal
)
{
   BOOL bReturn = FALSE;
   BOOL bResult;
   DWORD dwBytesWritten;
   DWORD dwOutBufferLength;
   PBYTE pbOutBuffer;
   PSIZE_T pdwOutBufferPosition;

   if (pBuffer == NULL)
      return FALSE;

   if (SIZETToDWord(pBuffer->Position, &dwOutBufferLength) != S_OK)
      return FALSE;
   pbOutBuffer = pBuffer->pbData;
   pdwOutBufferPosition = &(pBuffer->Position);

   //
   // Compress data
   //
   if (g_GlobalConfig.bCompressionEnabled)
   {
      size_t bytesOut;
      int iResult;

      bytesOut = LZ4F_compressUpdate(
         pBuffer->lz4Ctx,
         pBuffer->pbDataCompress + pBuffer->PositionCompress, pBuffer->DataCompressSize,
         pBuffer->pbData, pBuffer->Position,
         NULL
      );
      iResult = LZ4F_isError(bytesOut);

      if (iResult != 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot compress data%s (error %d - %s).", COLOR_RED, COLOR_RESET, bytesOut, LZ4F_getErrorName(bytesOut)
         );
         return FALSE;
      }

      pBuffer->PositionCompress += bytesOut;

      if (bFinal)
      {
         bytesOut = LZ4F_compressEnd(
            pBuffer->lz4Ctx,
            pBuffer->pbDataCompress + pBuffer->PositionCompress, pBuffer->DataCompressSize,
            NULL
         );
         iResult = LZ4F_isError(bytesOut);

         if (iResult != 0)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot finalize compression %s (error %d - %s).", COLOR_RED, COLOR_RESET, bytesOut, LZ4F_getErrorName(bytesOut)
            );
            return FALSE;
         }

         pBuffer->PositionCompress += bytesOut;
      }

      pbOutBuffer = pBuffer->pbDataCompress;
      pdwOutBufferPosition = &(pBuffer->PositionCompress);
      if (SIZETToDWord(*pdwOutBufferPosition, &dwOutBufferLength) != S_OK)
         return FALSE;

      // Input buffer has been compressed, reset position
      pBuffer->Position = 0;
   }

   //
   // Encrypt data
   //
   if (g_GlobalConfig.bEncryptionEnabled)
   {
      DWORD dwBufferSize;
      DWORD dwRoundedOutBufferLength;

      if (SIZETToDWord(pBuffer->DataEncryptSize, &dwBufferSize) != S_OK)
         return FALSE;

      dwRoundedOutBufferLength = (dwOutBufferLength / pBuffer->dwEncryptBlockLen) * pBuffer->dwEncryptBlockLen;

      // If this is the last block, don't round
      if (bFinal)
         dwRoundedOutBufferLength = dwOutBufferLength;

      // Copy required data to encryption buffer
      memcpy_s(pBuffer->pbDataEncrypt, dwBufferSize, pbOutBuffer, dwRoundedOutBufferLength);

      // Copy remaining data to the beginning of the previous buffer, if not the last block
      if (bFinal == FALSE)
      {
         memcpy_s(pbOutBuffer, pBuffer->BufferSize, pbOutBuffer + dwRoundedOutBufferLength, dwOutBufferLength - dwRoundedOutBufferLength);
         *pdwOutBufferPosition = dwOutBufferLength - dwRoundedOutBufferLength;
      }

      bResult = CryptEncrypt(
         pBuffer->hCryptKey,
         pBuffer->hHash,
         bFinal,
         0,
         pBuffer->pbDataEncrypt,
         &dwRoundedOutBufferLength,
         dwBufferSize
      );

      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot encrypt data%s (error %u / %x).", COLOR_RED, COLOR_RESET, GetLastError(), dwOutBufferLength
         );
         return FALSE;
      }

      pbOutBuffer = pBuffer->pbDataEncrypt;
      dwOutBufferLength = dwRoundedOutBufferLength;
      pBuffer->PositionEncrypt = dwOutBufferLength;
      pdwOutBufferPosition = &(pBuffer->PositionEncrypt);
   }

   //
   // Write buffer to file
   //
   bResult = WriteFile(pBuffer->hOutputFile, pbOutBuffer, dwOutBufferLength, &dwBytesWritten, NULL);
   bReturn = bResult;

   //
   // Reset output buffer position
   //
   if (bResult)
      *pdwOutBufferPosition = 0;

   return bReturn;
}