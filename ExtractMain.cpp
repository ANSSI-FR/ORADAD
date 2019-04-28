#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <intsafe.h>
#include "Structures.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

//
// Macros
//
#define _HeapAlloc(x) HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, (x))
#define _SafeHeapRelease(x) { if (NULL != x) { HeapFree(g_hHeap, 0, x); x = NULL; } }
#define _SafeCOMRelease(x) { if (NULL != x) { x->Release(); x = NULL; } }

#define _CallWriteAndGetMax(x, y) do { DWORD dwTempSizeResult; dwTempSizeResult = x; if (dwTempSizeResult>y) y=dwTempSizeResult; } while(FALSE)

//
// Defines
//
#define MSG_MAX_SIZE       8192
#define INFO_MAX_SIZE      MSG_MAX_SIZE + 256         // 256: "%04u/%02u/%02u - %02u:%02u:%02u.%03u\t%d\t%s\t%s\t%d\t" + ... + "\r\n",
#define BUFFER_SIZE        1024 * 1024

//
// Global variables
//
HANDLE g_hHeap = NULL;
HANDLE g_hStdOut;
BOOL g_bSupportsAnsi;
HCRYPTPROV g_hProv = NULL;

//
// Functions definition
//
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
      DWORD dwDataSize;
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
   }
}

BOOL
GetRsaPrivateKey (
   LPWSTR szRsaKeyPath,
   HCRYPTKEY* phRsaKey
)
{
   BOOL bResult;

   HANDLE hFile;
   DWORD dwFileSize = 0;
   LPSTR bRsaPEMData = NULL;
   DWORD dwReadBytes = 0;
   DWORD dwRsaBufferLen = 0;
   PBYTE pbRsaBuffer = NULL;
   DWORD dwKeyBlobLen = 0;
   PBYTE pbKeyBlob = NULL;

   hFile = CreateFile(szRsaKeyPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open rsa key file '%S'%s (error %u).", COLOR_RED, szRsaKeyPath, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   dwFileSize = GetFileSize(hFile, NULL);

   bRsaPEMData = (LPSTR)_HeapAlloc(dwFileSize);
   bResult = ReadFile(hFile, bRsaPEMData, dwFileSize, &dwReadBytes, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to read rsa key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   CloseHandle(hFile);

   bResult = CryptAcquireContext(&g_hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to get Cryptographic Provider%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   // Convert then import RSA Public Key
   bResult = CryptStringToBinaryA(bRsaPEMData, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwRsaBufferLen, NULL, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to parse RSA private key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   pbRsaBuffer = (PBYTE)_HeapAlloc(dwRsaBufferLen);

   bResult = CryptStringToBinaryA(bRsaPEMData, 0, CRYPT_STRING_BASE64HEADER, pbRsaBuffer, &dwRsaBufferLen, NULL, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to parse RSA private key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   bResult = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbRsaBuffer, dwRsaBufferLen, 0, NULL, NULL, &dwKeyBlobLen);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to parse RSA private key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   pbKeyBlob = (PBYTE)_HeapAlloc(dwKeyBlobLen);

   bResult = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbRsaBuffer, dwRsaBufferLen, 0, NULL, pbKeyBlob, &dwKeyBlobLen);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to parse RSA private key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   bResult = CryptImportKey(g_hProv, pbKeyBlob, dwKeyBlobLen, NULL, 0, phRsaKey);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to import RSA private key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   return TRUE;
}

BOOL
ProcessFile (
   LPWSTR szFileName,
   HCRYPTKEY hRsaKey
)
{
   BOOL bResult;

   HANDLE hFile;
   LARGE_INTEGER liFileSize;
   LARGE_INTEGER liFilePos;
   PBUFFER_HEADER pBufferHeader = (PBUFFER_HEADER)_HeapAlloc(sizeof(BUFFER_HEADER));
   DWORD dwBytesRead = 0;
   WCHAR szDestFileName[MAX_PATH] = { 0 };
   HANDLE hDestFile;
   PBYTE bFileData = NULL;

   LZ4F_errorCode_t lz4err;
   LZ4F_dctx* lz4Ctx = NULL;
   PBYTE pbDecompress = NULL;
   DWORD dwDecompressBufLength = 1 << 20; // 1MB

   HCRYPTHASH hHash = NULL;
   HCRYPTKEY hCryptKey = NULL;
   PBYTE pbDecrypt = NULL;
   DWORD dwSize = sizeof(DWORD);
   DWORD dwBlockLen = 0;

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] Processing file '%S'.", szFileName
   );

   hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open file '%S'%s (error %u).", COLOR_RED, szFileName, COLOR_RESET, GetLastError()
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

   liFilePos.QuadPart = 0;

   if (liFileSize.QuadPart < sizeof(BUFFER_HEADER))
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sFile is corrupted (bad size)%s.", COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   if (pBufferHeader == NULL)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot allocate memory%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   bResult = ReadFile(hFile, pBufferHeader, sizeof(BUFFER_HEADER), &dwBytesRead, NULL);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot read file header%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }
   liFilePos.QuadPart += dwBytesRead;

   if (memcmp(pBufferHeader->Magic, "ORADAD", 6) != 0)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sFile is corrupted (bad magic)%s.", COLOR_RED, COLOR_RESET
      );
      return FALSE;
   }

   if (pBufferHeader->BufferVersion != BUFFER_VERSION)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnsupported file version%s (%x).", COLOR_RED ,COLOR_RESET, pBufferHeader->BufferVersion
      );
      return FALSE;
   }

   if (pBufferHeader->dwExtraDataLen > 0)
   {
      pBufferHeader = (PBUFFER_HEADER)HeapReAlloc(g_hHeap, HEAP_ZERO_MEMORY, pBufferHeader, sizeof(BUFFER_HEADER) + pBufferHeader->dwExtraDataLen);
      if (pBufferHeader == NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot allocate memory%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      bResult = ReadFile(hFile, pBufferHeader->bExtraData, pBufferHeader->dwExtraDataLen, &dwBytesRead, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot read file header extra data%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }
      liFilePos.QuadPart += dwBytesRead;
   }

   if (pBufferHeader->Flags & BUFFER_COMPRESSED)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
         "[.] File is compressed '%S'.", szFileName
      );

      lz4err = LZ4F_createDecompressionContext(&lz4Ctx, LZ4F_VERSION);
      if (lz4err != 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to create decompression context%s (error %u - %s).", COLOR_RED, COLOR_RESET, lz4err, LZ4F_getErrorName(lz4err)
         );
         return FALSE;
      }
   }

   if (pBufferHeader->Flags & BUFFER_ENCRYPTED)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
         "[.] File is encrypted '%S'.", szFileName
      );

      //
      // Import AES key
      //
      bResult = CryptImportKey(g_hProv, pBufferHeader->bExtraData, pBufferHeader->dwExtraDataLen, hRsaKey, 0, &hCryptKey);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot get AES key%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Get Block length
      //
      bResult = CryptGetKeyParam(hCryptKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwSize, 0);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to get block size%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      //
      // Get SHA256 provider
      //
      bResult = CryptCreateHash(g_hProv, CALG_SHA_256, 0, 0, &hHash);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to get Cryptographic Hash%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }
   }

   // Remove '.oradad' extension
   wcsncpy_s(szDestFileName, MAX_PATH, szFileName, wcslen(szFileName) - 7);
   hDestFile = CreateFile(szDestFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
   if (hDestFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open output file '%S'%s (error %u).", COLOR_RED, szDestFileName, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   pbDecompress = (PBYTE)_HeapAlloc(dwDecompressBufLength);
   pbDecrypt = (PBYTE)_HeapAlloc(BUFFER_SIZE);

   while (liFilePos.QuadPart < liFileSize.QuadPart)
   {
      BOOL bFinal = FALSE;
      DWORD dwDecryptBufLength = BUFFER_SIZE;
      DWORD dwWritten = 0;
      DWORD dwOutLength = 0;

      // Read data in decryption buffer
      ReadFile(hFile, pbDecrypt, BUFFER_SIZE, &dwDecryptBufLength, NULL);
      liFilePos.QuadPart += dwDecryptBufLength;

      bFinal = dwDecryptBufLength < BUFFER_SIZE;

      if (pBufferHeader->Flags & BUFFER_ENCRYPTED)
      {
         bResult = CryptDecrypt(
            hCryptKey,
            hHash,
            bFinal,
            0,
            pbDecrypt,
            &dwDecryptBufLength);

         if (bResult == FALSE)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot decrypt data%s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
            );
            return FALSE;
         }
      }

      if (pBufferHeader->Flags & BUFFER_COMPRESSED)
      {
         DWORD dwDecrypted = 0;
         size_t ret;
         int iResult;
         size_t decompressSize;
         size_t decryptSize;
         PBYTE pbDecryptTmp = pbDecrypt;

         do
         {
            decompressSize = dwDecompressBufLength;
            decryptSize = dwDecryptBufLength - (pbDecryptTmp - pbDecrypt);

            ret = LZ4F_decompress(
               lz4Ctx,
               pbDecompress, &decompressSize,
               pbDecryptTmp, &decryptSize,
               NULL
            );

            iResult = LZ4F_isError(ret);
            if (iResult != 0)
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                  "[!] %sCannot decompress data%s (error %d - %s).", COLOR_RED, COLOR_RESET, ret, LZ4F_getErrorName(ret)
               );
               return FALSE;
            }

            SIZETToDWord(decompressSize, &dwDecrypted);
            dwOutLength = dwDecrypted;
            pbDecryptTmp += decryptSize;
            WriteFile(hDestFile, pbDecompress, dwOutLength, &dwWritten, NULL);
         } while (ret != 0 && decompressSize != 0 && pbDecryptTmp < pbDecrypt + dwDecryptBufLength);
      }
      else
      {
         memcpy_s(pbDecompress, dwDecompressBufLength, pbDecrypt, dwDecryptBufLength);
         dwOutLength = dwDecryptBufLength;
         WriteFile(hDestFile, pbDecompress, dwOutLength, &dwWritten, NULL);
      }
   }

   _SafeHeapRelease(pbDecompress);
   _SafeHeapRelease(pbDecrypt);

   if (lz4Ctx != NULL)
      LZ4F_freeDecompressionContext(lz4Ctx);
   if (hCryptKey != NULL)
      CryptDestroyKey(hCryptKey);
   if (hHash != NULL)
      CryptDestroyHash(hHash);

   CloseHandle(hFile);
   CloseHandle(hDestFile);

   return TRUE;
}

VOID
ProcessFilesRecursively (
   LPWSTR szFolder,
   HCRYPTKEY hRsaKey
)
{
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
            ProcessFilesRecursively(szFullPattern, hRsaKey);
         }
      }
      while (FindNextFile(hFindFile, &FindFileData));
      FindClose(hFindFile);
   }

   // now we are going to look for the matching files
   PathCombine(szFullPattern, szFolder, L"*.oradad");
   hFindFile = FindFirstFile(szFullPattern, &FindFileData);
   if (hFindFile != INVALID_HANDLE_VALUE)
   {
      do
      {
         if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
         {
            // found a file; do something with it
            PathCombine(szFullPattern, szFolder, FindFileData.cFileName);
            ProcessFile(szFullPattern, hRsaKey);
         }
      }
      while (FindNextFile(hFindFile, &FindFileData));
      FindClose(hFindFile);
   }
}

int
wmain (
   int argc,
   wchar_t* argv[]
)
{
   BOOL bResult;
   HRESULT hr;
   LPWSTR szRsaKeyFilePath;
   LPWSTR szDirectory;
   HCRYPTKEY hRsaKey;

   //
   // Check command line parameters
   //
   if (argc < 3)
   {
      fprintf_s(stderr, "Usage: oradad_extract.exe <rsa private key file> <directory>\n");
      return EXIT_FAILURE;
   }

   szRsaKeyFilePath = argv[1];
   szDirectory = argv[2];

   //
   // Initialization
   //
   g_hHeap = HeapCreate(0, 0, 0);
   if (g_hHeap == NULL)
   {
      return EXIT_FAILURE;
   }
   hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

   //
   // Start logging
   //
   g_hStdOut = CreateFile(L"CONOUT$", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
   if (g_hStdOut == INVALID_HANDLE_VALUE)
   {
      return EXIT_FAILURE;
   }

   // Set console output to 'ISO 8859-1 Latin 1; Western European (ISO)'
   SetConsoleOutputCP(28591);

   g_bSupportsAnsi = SetConsoleMode(g_hStdOut, ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
   SetConsoleTitle(L"ORADAD_Extract");

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] %sStarting%s.", COLOR_CYAN, COLOR_RESET
   );

   bResult = GetRsaPrivateKey(szRsaKeyFilePath, &hRsaKey);
   if (bResult == FALSE)
      goto End;

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] Processing directory is '%S'.", szDirectory
   );
   ProcessFilesRecursively(szDirectory, hRsaKey);

End:
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] %sEnd.%s", COLOR_GREEN, COLOR_RESET
   );

   if (g_hProv != NULL)
      CryptReleaseContext(g_hProv, 0);

   HeapDestroy(g_hHeap);
   CoUninitialize();

   return EXIT_SUCCESS;
}