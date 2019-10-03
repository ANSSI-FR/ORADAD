#pragma once
//
// XML.cpp
//
PVOID
XmlReadConfigFile(
   _In_z_ LPTSTR szConfigPath,
   _In_ PGLOBAL_CONFIG pGlobalConfig
);

PVOID
XmlReadSchemaFile(
   _In_opt_z_ LPTSTR szConfigPath,
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ PVOID pXMLDocConfig
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
   _Out_ PROOTDSE_CONFIG pRootDse
);

BOOL
LdapProcessRequest(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_opt_z_ LPWSTR szServer,
   _In_ BOOL bIsLocalAdmin,
   _In_z_ LPWSTR szRootDns,
   _In_z_ LPCWSTR szPath1,
   _In_opt_z_ LPCWSTR szPath2,
   _In_opt_z_ LPWSTR szLdapBase,
   _In_opt_ PREQUEST_CONFIG pRequest,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo,
   _In_ BOOL bIsRootDSE
);

//
// Sysvol.cpp
//
VOID
ProcessSysvol(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szRootDns,
   _In_z_ LPCWSTR szPath1,
   _In_z_ LPCWSTR szPath2,
   _In_opt_z_ LPWSTR szServer
);

VOID
SysvolWriteTableInfo(
   _In_ HANDLE hTableFile,
   _In_z_ LPWSTR szDomainDns
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
   _In_z_ _Printf_format_string_ LPCSTR szFormat,
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

_Success_(return)
BOOL
GetFileVersion(
   _Out_ wchar_t* szVersion,
   _In_  size_t BufferCount
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

BOOL
cmdOptionExists(
   _In_ wchar_t *argv[],
   _In_ int argc,
   _In_z_ const wchar_t *szOption
);

_Success_(return)
BOOL
GetCmdOption(
   _In_ wchar_t *argv[],
   _In_ int argc,
   _In_z_ const wchar_t *szOption,
   _In_ TYPE_CONFIG ElementType,
   _Out_ PVOID pvElementValue
);

//
// Buffer.cpp
//
BOOL
BufferInitialize(
   _Out_ PBUFFER_DATA pBuffer,
   _In_z_ LPWSTR szFilename,
   _In_ BOOL bRawBuffer = FALSE
);

BOOL
BufferClose(
   _Inout_ PBUFFER_DATA pBuffer
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_reads_bytes_opt_(dwNumberOfBytesToWrite) LPVOID pvData,
   _In_ DWORD dwNumberOfBytesToWrite
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_ const FILETIME* fileTime
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_ DWORD dwValue
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_ LONGLONG dwValue
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_ unsigned long long dwValue
);

DWORD
BufferWriteFromFile(
   _In_ PBUFFER_DATA pBuffer,
   _In_ HANDLE hFile
);

DWORD
BufferWriteHex(
   _Inout_ PBUFFER_DATA pBuffer,
   _In_reads_(dwDataSize) PBYTE pbData,
   _In_ DWORD dwDataSize
);

DWORD
BufferWriteLine(
   _In_ PBUFFER_DATA pBuffer
);

DWORD
BufferWriteTab(
   _In_ PBUFFER_DATA pBuffer
);

DWORD
BufferWriteSemicolon(
   _In_ PBUFFER_DATA pBuffer
);

BOOL
BufferSave(
   _In_ PBUFFER_DATA pBuffer,
   _In_ BOOL bFinal
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

//
// tar.cpp
//
BOOL
TarInitialize(
   _Out_ PHANDLE phTarFile,
   _In_z_ LPWSTR szFilename
);

VOID
TarFilesRecursively(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szFolder,
   _In_ HANDLE hTarFile
);

BOOL
TarFile(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szFileName,
   _In_opt_z_ LPWSTR szPrefix,
   _In_ HANDLE hTarFile
);

BOOL
TarClose(
   _In_ HANDLE hTarFile
);