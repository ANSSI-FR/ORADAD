#include <Windows.h>
#include <intsafe.h>
#include "ORADAD.h"
#include "resource.h"

#ifdef _WIN64
#define MLA_ARCH "x86_64"
#else
#define MLA_ARCH "i686"
#endif
#ifdef _DEBUG
#define MLA_RELEASE "-debug"
#pragma comment(lib, "Ws2_32.lib")        // Required by the Rust runtime in debug mode
#pragma comment(lib, "userenv.lib")       // Required by the Rust runtime in debug mode
#else
#define MLA_RELEASE ""
#endif
#pragma comment(lib, "mla\\libmla-windows-" MLA_ARCH MLA_RELEASE "\\mla.lib")

// Compression level 5 found to be most efficient for ORADAD's CSV files and execution time constraints
//const uint32_t ulGlobalCompressionLevel = 5;

HANDLE g_hMlaOutputFile;
MLAArchiveHandle g_hMlaArchive = NULL;

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;
extern GLOBAL_CONFIG g_GlobalConfig;

#define READ_BUFFER_SIZE 1024 * 1024

//
// Mla callback functions
//
static
int32_t
mla_callback_write(
   const uint8_t* pBuffer,
   uint32_t length,
   void* context,
   uint32_t* pBytesWritten
);

static
int32_t
mla_callback_flush(
   void* context
);

//
// MLA Public functions
//
BOOL
MlaInit (
   _In_z_ LPCWSTR szMlaFilePath
)
{
   MLAStatus mlaStatus;
   MLAConfigHandle hMlaConfig = NULL;

   //
   // Open MLA file
   //
   g_hMlaOutputFile = CreateFile(szMlaFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
   if (g_hMlaOutputFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open MLA file%s '%S' (error %u).",
         COLOR_RED, COLOR_RESET, szMlaFilePath, GetLastError()
      );
      return FALSE;
   }

   //
   // Init MLA
   //
   mlaStatus = mla_config_default_new(&hMlaConfig);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sMLA config creation failed%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      return FALSE;
   }

#ifdef TRACELOGGING
   TraceLoggingWrite(
      g_hOradadLoggingProvider,
      "mla_config_default_new",
      TraceLoggingLevel(WINEVENT_LEVEL_INFO),
      TraceLoggingKeyword(ORADAD_PROVIDER_KEYWORD_MLA),
      TraceLoggingHexUInt32(mlaStatus, "mlaStatus"),
      TraceLoggingPointer(hMlaConfig, "hMlaConfig")
   );
#endif

   //
   // Add keys (integrated and from XML config file)
   //
   if (g_GlobalConfig.bBypassIntegratedMLAKey == FALSE)
   {
      HMODULE hCurrentProcess;
      HRSRC hrMLAKey;

      hCurrentProcess = GetModuleHandle(NULL);
      hrMLAKey = FindResource(hCurrentProcess, MAKEINTRESOURCE(IDR_MLAKEY), TEXT("KEY"));
      if (hrMLAKey != NULL)
      {
         HGLOBAL hResource;

         hResource = LoadResource(hCurrentProcess, hrMLAKey);
         if (hResource != NULL)
         {
            PBYTE pMLAKey;

            pMLAKey = (PBYTE)LockResource(hResource);

            mlaStatus = mla_config_add_public_keys(hMlaConfig, (char *)pMLAKey);
            if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                  "[!] %sMLA integrated public key set failed%s (error %x).",
                  COLOR_RED, COLOR_RESET, mlaStatus
               );
               return FALSE;
            }
         }
      }
   }

   if (g_GlobalConfig.szAdditionalMlaKeys != NULL)
   {
      LPSTR szAdditionalMlaKeysA;

      szAdditionalMlaKeysA = LPWSTRtoLPSTR(g_GlobalConfig.szAdditionalMlaKeys);
      if (szAdditionalMlaKeysA == NULL)
      {
         return FALSE;
      }
      else
      {
         mlaStatus = mla_config_add_public_keys(hMlaConfig, szAdditionalMlaKeysA);
         if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sMLA config public key set failed%s (error %x).",
               COLOR_RED, COLOR_RESET, mlaStatus
            );
            return FALSE;
         }
         _SafeHeapRelease(szAdditionalMlaKeysA);
      }
   }

   /*
   //
   // Compression Level
   //
   mlaStatus = mla_config_set_compression_level(hMlaConfig, ulGlobalCompressionLevel);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sMLA compression level set failed%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      return FALSE;
   }
   */

   //
   // Create file
   //
   mlaStatus = mla_archive_new(&hMlaConfig, &mla_callback_write, &mla_callback_flush, g_hMlaOutputFile, &g_hMlaArchive);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sMLA archive creation failed%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      return FALSE;
   }

#ifdef TRACELOGGING
   TraceLoggingWrite(
      g_hOradadLoggingProvider,
      "mla_archive_new",
      TraceLoggingLevel(WINEVENT_LEVEL_INFO),
      TraceLoggingKeyword(ORADAD_PROVIDER_KEYWORD_MLA),
      TraceLoggingHexUInt32(mlaStatus, "mlaStatus"),
      TraceLoggingPointer(g_hMlaArchive, "hMlaArchive")
   );
#endif

   return TRUE;
}

BOOL
MlaAddFile (
   _In_z_ LPCWSTR szFilePath,
   _Out_ MLAArchiveFileHandle *phMlaFile
)
{
   BOOL bReturn = TRUE;
   MLAStatus mlaStatus;
#ifdef TRACELOGGING
   UINT Level = WINEVENT_LEVEL_INFO;
#endif
   LPSTR szFilenameA;

   szFilenameA = LPWSTRtoLPSTR(szFilePath);
   if (szFilenameA == NULL)
   {
      *phMlaFile = NULL;
      return FALSE;
   }

   mlaStatus = mla_archive_file_new(g_hMlaArchive, szFilenameA, phMlaFile);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sMLA file creation failed%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      bReturn = FALSE;
#ifdef TRACELOGGING
      Level = WINEVENT_LEVEL_ERROR;
#endif
      *phMlaFile = NULL;
   }

#ifdef TRACELOGGING
   TraceLoggingWrite(
      g_hOradadLoggingProvider,
      "mla_archive_file_new",
      TraceLoggingLevel(Level),
      TraceLoggingKeyword(ORADAD_PROVIDER_KEYWORD_MLA),
      TraceLoggingHexUInt32(mlaStatus, "mlaStatus"),
      TraceLoggingPointer(g_hMlaArchive, "hMlaArchive"),
      TraceLoggingPointer(phMlaFile, "hMlaFile"),
      TraceLoggingString(szFilenameA, "szFilename")
   );
#endif

   _SafeHeapRelease(szFilenameA);
   return bReturn;
}

BOOL
MlaAddFileFromFile (
   _In_z_ LPCWSTR szFilePathToAdd,
   _In_z_ LPCWSTR szMLAFilePath
)
{
   BOOL bResult;
   BOOL bReturn = FALSE;

   MLAArchiveFileHandle hMlaFile;

   HANDLE hFileToAdd;
   LARGE_INTEGER liFileSize;
   LARGE_INTEGER liFilePos;
   PBYTE pReadBuffer = NULL;

   bResult = MlaAddFile(szMLAFilePath, &hMlaFile);
   if (bResult == FALSE)
      return FALSE;

   hFileToAdd = CreateFile(szFilePathToAdd, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
   if (hFileToAdd == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open file%s '%S' (error %u).",
         COLOR_RED, COLOR_RESET, szFilePathToAdd, GetLastError()
      );
      goto End;
   }

   bResult = GetFileSizeEx(hFileToAdd, &liFileSize);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sCannot get file size%s (error %u).",
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      goto End;
   }

   pReadBuffer = (PBYTE)_HeapAlloc(READ_BUFFER_SIZE);
   if (pReadBuffer == NULL)
      goto End;

   liFilePos.QuadPart = 0;
   while (liFilePos.QuadPart < liFileSize.QuadPart)
   {
      DWORD dwReadLength = READ_BUFFER_SIZE;

      bResult = ReadFile(hFileToAdd, pReadBuffer, READ_BUFFER_SIZE, &dwReadLength, NULL);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot read file %s (error %u).", COLOR_RED, COLOR_RESET, GetLastError()
         );
         break;
      }

      liFilePos.QuadPart += dwReadLength;
      bResult = MlaBufferWrite(hMlaFile, pReadBuffer, dwReadLength);
      goto End;
   }

   bReturn = TRUE;

End:
   if (hFileToAdd != INVALID_HANDLE_VALUE)
      CloseHandle(hFileToAdd);

   _SafeHeapRelease(pReadBuffer);

   MlaCloseFile(&hMlaFile);

   return bReturn;
}

BOOL
MlaCloseFile (
   _Inout_ MLAArchiveFileHandle *phMlaFile
)
{
   BOOL bReturn = TRUE;
#ifdef TRACELOGGING
   UINT Level = WINEVENT_LEVEL_INFO;
#endif
   MLAStatus mlaStatus;

   mlaStatus = mla_archive_file_close(g_hMlaArchive, phMlaFile);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to close MLA file%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      bReturn = FALSE;
#ifdef TRACELOGGING
      Level = WINEVENT_LEVEL_ERROR;
#endif
   }

#ifdef TRACELOGGING
   TraceLoggingWrite(
      g_hOradadLoggingProvider,
      "mla_archive_file_close",
      TraceLoggingLevel(Level),
      TraceLoggingKeyword(ORADAD_PROVIDER_KEYWORD_MLA),
      TraceLoggingHexUInt32(mlaStatus, "mlaStatus"),
      TraceLoggingPointer(g_hMlaArchive, "hMlaArchive"),
      TraceLoggingPointer(phMlaFile, "hMlaFile")
   );
#endif

   return bReturn;
}

BOOL
MlaBufferWrite (
   _In_ MLAArchiveFileHandle hMlaFile,
   _In_reads_(BufferSize) PBYTE pbBuffer,
   _In_ uint64_t BufferSize
)
{
   BOOL bReturn = TRUE;
#ifdef TRACELOGGING
   UINT Level = WINEVENT_LEVEL_INFO;
#endif
   MLAStatus mlaStatus;

   mlaStatus = mla_archive_file_append(g_hMlaArchive, hMlaFile, pbBuffer, BufferSize);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to append MLA file%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      bReturn = FALSE;
#ifdef TRACELOGGING
      Level = WINEVENT_LEVEL_ERROR;
#endif
   }

#ifdef TRACELOGGING
   TraceLoggingWrite(
      g_hOradadLoggingProvider,
      "mla_archive_file_append",
      TraceLoggingLevel(Level),
      TraceLoggingKeyword(ORADAD_PROVIDER_KEYWORD_MLA),
      TraceLoggingHexUInt32(mlaStatus, "mlaStatus"),
      TraceLoggingPointer(g_hMlaArchive, "hMlaArchive"),
      TraceLoggingPointer(hMlaFile, "hMlaFile"),
      TraceLoggingUInt64(BufferSize, "BufferSize")
   );
#endif

   return bReturn;
}

BOOL
MlaClose (
)
{
   BOOL bReturn = TRUE;
   MLAStatus mlaStatus;
#ifdef TRACELOGGING
   UINT Level = WINEVENT_LEVEL_INFO;
#endif

   if (g_hMlaArchive == NULL)
      return TRUE;

   mlaStatus = mla_archive_close(&g_hMlaArchive);
   if (mlaStatus != MLAStatus::MLA_STATUS_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sMLA archive close failed%s (error %x).",
         COLOR_RED, COLOR_RESET, mlaStatus
      );
      bReturn = FALSE;
#ifdef TRACELOGGING
      Level = WINEVENT_LEVEL_ERROR;
#endif
   }

#ifdef TRACELOGGING
   TraceLoggingWrite(
      g_hOradadLoggingProvider,
      "mla_archive_close",
      TraceLoggingLevel(Level),
      TraceLoggingKeyword(ORADAD_PROVIDER_KEYWORD_MLA),
      TraceLoggingHexUInt32(mlaStatus, "mlaStatus"),
      TraceLoggingPointer(g_hMlaArchive, "hMlaArchive")
   );
#endif

   CloseHandle(g_hMlaOutputFile);
   return bReturn;
}

//
// Mla callback functions
//
static
int32_t
mla_callback_write (
   const uint8_t* pBuffer,
   uint32_t length,
   void* context,
   uint32_t* pBytesWritten
)
{
   BOOL bResult;
   DWORD dwBytesWritten;

   bResult = WriteFile((HANDLE)context, pBuffer, length, &dwBytesWritten, NULL);
   if (bResult == FALSE)
   {
      DWORD dwError;

      dwError = GetLastError();
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sWriting to MLA archive failed%s (error %u).",
         COLOR_RED, COLOR_RESET, dwError
      );
      return dwError;
   }

   *pBytesWritten = dwBytesWritten;
   return ERROR_SUCCESS;
}

static
int32_t
mla_callback_flush (
   void* context
)
{
   BOOL bResult;

   bResult = FlushFileBuffers((HANDLE)context);
   if (bResult == FALSE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sFlushing MLA archive failed%s (error %u).",
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      return 1;
   }

   return 0;
}