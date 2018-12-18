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

typedef struct _GLOBAL_CONFIG
{
   WCHAR szSystemTime[17];

   LPWSTR szOutDirectory;
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

   DWORD dwRequestCount;
   PREQUEST_CONFIG pRequests;

   DWORD dwRootDSEAttributesCount;
   DWORD dwAttributesCount;
   PATTRIBUTE_CONFIG pRootDSEAttributes;
   PATTRIBUTE_CONFIG pAttributes;
} GLOBAL_CONFIG, *PGLOBAL_CONFIG;

//
// Buffer
//
typedef struct _BUFFER_DATA
{
   SIZE_T BufferSize;
   SIZE_T Position;
   PBYTE pbData;
   HANDLE hOutputFile;
   TCHAR szFileName[MAX_PATH];
} BUFFER_DATA, *PBUFFER_DATA;