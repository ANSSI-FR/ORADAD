#pragma once
#include <Windows.h>
#include "lz4/lz4frame.h"

//
// Log levels
//
#define LOG_LEVEL_NONE        0   // Tracing is not on
#define LOG_LEVEL_CRITICAL    1   // Abnormal exit or termination
#define LOG_LEVEL_ERROR       2   // Severe errors that need logging
#define LOG_LEVEL_WARNING     3   // Warnings such as allocation failure
#define LOG_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
#define LOG_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps
#define LOG_LEVEL_VERYVERBOSE 6

//
// Colors VT100
//
#define COLOR_RED          (g_bSupportsAnsi) ? "\x1b[1;31m" : ""
#define COLOR_GREEN        (g_bSupportsAnsi) ? "\x1b[1;32m" : ""
#define COLOR_YELLOW       (g_bSupportsAnsi) ? "\x1b[1;33m" : ""
#define COLOR_MAGENTA      (g_bSupportsAnsi) ? "\x1b[1;35m" : ""
#define COLOR_CYAN         (g_bSupportsAnsi) ? "\x1b[1;36m" : ""
#define COLOR_RESET        (g_bSupportsAnsi) ? "\x1b[0m" : ""

//
// Naming context
//
#define STR_ROOTDSE           L"rootDSE"
#define STR_DOMAIN            L"domain"
#define STR_CONFIGURATION     L"configuration"
#define STR_SCHEMA            L"schema"
#define STR_DOMAIN_DNS        L"domaindns"
#define STR_FOREST_DNS        L"forestdns"

//
// Filters
//
typedef
BOOL
(*tFilter)(
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
   );

//
// Constants
//
typedef struct _CONST_TXT {
   DWORD dwConst;       // If szTxt==NULL, dwConst indicates filter mode (Flag or Type)
   LPCWSTR szTxt;
} CONST_TXT, *PCONST_TXT;

//
// Configuration
//
typedef enum _TYPE_CONFIG
{
   ConfigTypeBool,
   ConfigTypeString,
   ConfigTypeUnsignedInterger,
   ConfigTypeCheckType
} TYPE_CONFIG;

typedef enum _BASE_TYPE
{
   BASE_ROOTDSE = 1,
   BASE_DOMAIN = 2,
   BASE_CONFIGURATION = 4,
   BASE_SCHEMA = 8,
   BASE_DOMAIN_DNS = 16,
   BASE_FOREST_DNS = 32
} BASE_TYPE;

typedef enum _ATTRIBUTE_TYPE
{
   TYPE_STR = 1,
   TYPE_STRS,
   TYPE_SID,
   TYPE_SD,
   TYPE_DACL,
   TYPE_GUID,
   TYPE_DATE,
   TYPE_DATEINT64,
   TYPE_INT,
   TYPE_INT64,
   TYPE_BOOL,
   TYPE_BIN
} ATTRIBUTE_TYPE;

typedef enum _FILTER_MODE
{
   FILTER_FLAG = 1,
   FILTER_TYPE = 2
} FILTER_MODE;

typedef struct _ATTRIBUTE_CONFIG
{
   LPWSTR szName;
   DWORD dwLevel;
   ATTRIBUTE_TYPE Type;
   tFilter fFilter;
   PVOID pvFilterData;
} ATTRIBUTE_CONFIG, *PATTRIBUTE_CONFIG;

typedef struct _CLASS_CONFIG
{
   LPWSTR szName;
   LPWSTR szAuxiliaryClass;
   LPWSTR szSystemAuxiliaryClass;

   DWORD dwAttributesCount;
   PATTRIBUTE_CONFIG *pAttributes;
} CLASS_CONFIG, *PCLASS_CONFIG;

typedef struct _ROOTDSE_CONFIG
{
   LPWSTR dnsHostName;
   LPWSTR serverName;

   LPWSTR defaultNamingContext;
   LPWSTR rootDomainNamingContext;
   LPWSTR configurationNamingContext;
   LPWSTR schemaNamingContext;
   LPWSTR domainDnsNamingContext;
   LPWSTR forestDnsNamingContext;

   LPWSTR domainControllerFunctionality;
   LPWSTR domainFunctionality;
   LPWSTR forestFunctionality;

   BOOL bIsLocalAdmin;
} ROOTDSE_CONFIG, *PROOTDSE_CONFIG;

typedef struct _CONTROL_LDAP
{
   LPWSTR szOid;
   LPWSTR szValue;
   BOOL isCritical;
} CONTROL_LDAP, *PCONTROL_LDAP;

typedef struct _REQUEST_CONFIG
{
   LPWSTR szName;
   DWORD dwBase;
   DWORD dwScope;
   LPWSTR szFilter;

   DWORD dwAttributesCount;
   PATTRIBUTE_CONFIG *pAttributes;

   DWORD dwControlsCount;
   PCONTROL_LDAP pControls;

   DWORD dwStrintMaxLengthShortName;
   DWORD dwStrintMaxLengthDn;
   DWORD dwStrintMaxLengthShortDn;

   // Per request atttribute text max size
   PDWORD pdwStrintMaxLength;

   BOOL bTableInfoWritten;
} REQUEST_CONFIG, *PREQUEST_CONFIG;

//
// Buffer
//
typedef struct _BUFFER_DATA
{
   SIZE_T BufferSize;
   SIZE_T Position;
   PBYTE pbData;
   SIZE_T PositionCompress;
   SIZE_T DataCompressSize;
   PBYTE pbDataCompress;
   SIZE_T PositionEncrypt;
   DWORD dwEncryptBlockLen;
   SIZE_T DataEncryptSize;
   PBYTE pbDataEncrypt;
   HANDLE hOutputFile;
   TCHAR szFileName[MAX_PATH];
   LZ4F_cctx* lz4Ctx;
   HCRYPTPROV hProv;
   HCRYPTHASH hHash;
   HCRYPTKEY hCryptKey;
} BUFFER_DATA, *PBUFFER_DATA;

#define BUFFER_VERSION        1
#define BUFFER_COMPRESSED     1
#define BUFFER_ENCRYPTED      2

#pragma pack(push,1)
#pragma warning(disable : 4200)
typedef struct _BUFFER_HEADER
{
   CHAR Magic[6];
   CHAR BufferVersion;
   CHAR Flags;
   DWORD dwExtraDataLen;
   BYTE bExtraData[0];
} BUFFER_HEADER, *PBUFFER_HEADER;
#pragma pack(pop)

typedef struct _GLOBAL_CONFIG
{
   WCHAR szSystemTime[17];

   LPWSTR szOutDirectory;
   WCHAR szFullOutDirectory[MAX_PATH];
   WCHAR szLogfilePath[MAX_PATH];
   HANDLE hTableFile;
   BOOL bWriteHeader;

   LPWSTR szServer;
   ULONG ulLdapPort;
   LPWSTR szUsername;
   LPWSTR szUserDomain;
   LPWSTR szUserPassword;

   DWORD dwLevel;
   BOOL bAllDomainsInForest;
   BOOL dwSleepTime;

   BOOL bCompressionEnabled;
   BOOL bEncryptionEnabled;
   BOOL bTarballEnabled;
   LPWSTR szPublicKey;

   LPWSTR szForestDomains;

   DWORD dwRequestCount;
   PREQUEST_CONFIG pRequests;

   DWORD dwRootDSEAttributesCount;
   DWORD dwAttributesCount;
   PATTRIBUTE_CONFIG pRootDSEAttributes;
   PATTRIBUTE_CONFIG pAttributes;

   BUFFER_DATA BufferMetadata;
} GLOBAL_CONFIG, *PGLOBAL_CONFIG;