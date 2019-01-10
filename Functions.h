//
// XML.cpp
//
PVOID
XmlReadConfigFile(
   _In_z_ LPTSTR szConfigPath,
   _In_ PGLOBAL_CONFIG pGlobalConfig
);

//
// Engine.cpp
//
BOOL
Process(
   _In_ PGLOBAL_CONFIG pGlobalConfig
);

//
// LDAP.cpp
//
BOOL
LdapGetRootDse(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szServerName,
   _Outptr_ PROOTDSE_CONFIG pRootDse
);

BOOL
LdapProcessRequest(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szServer,
   _In_ BOOL bIsLocalAdmin,
   _In_z_ LPWSTR szRootDns,
   _In_z_ LPCWSTR szPath1,
   _In_opt_z_ LPCWSTR szPath2,
   _In_z_ LPWSTR szLdapBase,
   _In_ PREQUEST_CONFIG pRequest,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo
);

//
// Util.cpp
//
VOID
Log(
   _In_z_ LPCSTR szFile,
   _In_z_ LPCSTR szFunction,
   _In_ DWORD dwLine,
   _In_ DWORD dwLevel,
   _In_z_ LPCSTR szFormat,
   ...
);

VOID
DuplicateString(
   _In_z_ LPWSTR szInput,
   _Out_ LPWSTR *szOutput
);

LPWSTR
ConvertDnToDns(
   _In_z_ LPWSTR szString
);

VOID
RemoveSpecialChars(
   _In_z_ LPWSTR szString
);

BOOL
WriteTextFile(
   _In_ HANDLE hFile,
   _In_z_ LPCSTR szFormat,
   ...
);

LPSTR
LPWSTRtoLPSTR(
   _In_opt_z_ LPWSTR szToConvert
);

BOOL
MetadataWriteFile(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPCWSTR szKey,
   _In_z_ LPWSTR szValue
);

BOOL
MetadataCreateFile(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szRootDns
);

//
// Buffer.cpp
//
BOOL
BufferInitialize
(
   _Out_ PBUFFER_DATA pBuffer,
   _In_z_ LPWSTR szFilename
);

BOOL
BufferClose(
   _Out_ PBUFFER_DATA pBuffer
);

DWORD
BufferWrite(
   _Out_ PBUFFER_DATA pBuffer,
   _In_reads_bytes_(dwNumberOfBytesToWrite) LPVOID pvData,
   _In_ DWORD dwNumberOfBytesToWrite
);

DWORD
BufferWrite(
   _Out_ PBUFFER_DATA pBuffer,
   _Inout_opt_ LPWSTR szString
);

DWORD
BufferWriteHex(
   _Out_ PBUFFER_DATA pBuffer,
   _In_reads_(dwDataSize) PBYTE pbData,
   _In_ DWORD dwDataSize
);

DWORD
BufferWriteLine(
   _Out_ PBUFFER_DATA pBuffer
);

DWORD
BufferWriteTab(
   _Out_ PBUFFER_DATA pBuffer
);

DWORD
BufferWriteSemicolon(
   _Out_ PBUFFER_DATA pBuffer
);

BOOL
BufferSave(
   _In_ PBUFFER_DATA pBuffer
);

//
// Filters.cpp
//
BOOL
GetFilter(
   _Inout_ PATTRIBUTE_CONFIG pAttributes,
   _In_z_ LPCWSTR szFilter
);

LPWSTR
ApplyFilter(
   _In_  PATTRIBUTE_CONFIG pAttributes,
   _In_z_ PVOID pvData
);