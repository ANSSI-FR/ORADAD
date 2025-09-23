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
   _In_ DWORD dwServerEntry,
   _In_z_ LPWSTR szServerName,
   _In_ ULONG ulLdapPort,
   _Out_ PROOTDSE_CONFIG pRootDse
);

BOOL
LdapProcessRequest(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _In_opt_z_ LPWSTR szServer,
   _In_ ULONG ulLdapPort,
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
BOOL
ProcessSysvol(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _In_z_ LPWSTR szRootDns,
   _In_z_ LPCWSTR szPath1,
   _In_z_ LPCWSTR szPath2,
   _In_opt_z_ LPWSTR szServer
);

VOID
SysvolWriteTableInfo(
   _In_ PBUFFER_OUTPUT pTableFile,
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
   _In_ PBUFFER_OUTPUT pOutput,
   _In_z_ LPCSTR szFormat,
   ...
);

LPSTR
LPWSTRtoUTF8(
   _In_opt_z_ LPCWSTR szToConvert
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
   _In_ PGLOBAL_CONFIG pGlobalConfig
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

StartStatus
GetBuildDateStatus(
);

BOOL
CheckAndCreateDirectory(
   _In_z_ LPCWSTR szDirectoryPath
);

BOOL
FormatNameAndCreateDirectory(
   _Out_writes_z_(dwPathSize) LPWSTR szOutputPath,
   _In_ DWORD dwPathSize,
   _In_z_ LPCWSTR szFormat,
   ...
);

//
// Util_Db.cpp
//
BOOL
DbAddKey(
   _Inout_ PDB_ENTRY *pBase,
   _In_opt_z_ LPWSTR szKeyName,
   _In_ DWORD dwKeyValue,
   _In_ DbCompareMode CompareMode
);

PDB_ENTRY
DbLookupKey(
   _Inout_ PDB_ENTRY pBase,
   _In_opt_z_ LPWSTR szKeyName
);

BOOL
DbFree(
   _Inout_ PDB_ENTRY *pBase
);

//
// Buffer.cpp
//
BOOL
BufferInitialize(
   _Out_ PBUFFER_DATA pBuffer,
   _In_z_ LPCWSTR szFilename,
   _In_ BOOL bWriteBomHeader,
   _In_ BOOL bSysvolOutput
);

BOOL
BufferClose(
   _Inout_ PBUFFER_DATA pBuffer
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString,
   _Inout_opt_ PDWORD pdwFieldWritten,
   _Inout_opt_ PBOOL pbWriteError,
   _In_opt_z_ LPWSTR szDn,
   _In_opt_z_ LPWSTR szAttribute
);

DWORD
BufferWriteStringWithLimit(
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString,
   _In_ DWORD dwLimit
);

DWORD
BufferWriteStringWithLimit(
   _In_ PBUFFER_DATA pBuffer,
   _In_opt_z_ LPWSTR szString,
   _In_ DWORD dwLimit,
   _Inout_opt_ PDWORD pdwFieldWritten,
   _Inout_opt_ PBOOL pbWriteError,
   _In_opt_z_ LPWSTR szDn,
   _In_opt_z_ LPWSTR szAttribute
);

DWORD
BufferWrite(
   _In_ PBUFFER_DATA pBuffer,
   _In_ const FILETIME *fileTime
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
   _In_ PBUFFER_DATA pBuffer
);

//
// MLA.cpp
//
BOOL
MlaInit(
   _In_z_ LPCWSTR szMlaFilePath
);

BOOL
MlaAddFile(
   _In_z_ LPCWSTR szFilePath,
   _Out_ MLAArchiveFileHandle *phMlaFile
);

BOOL
MlaAddFileFromFile(
   _In_z_ LPCWSTR szFilePathToAdd,
   _In_z_ LPCWSTR szMLAFilePath
);

BOOL
MlaCloseFile(
   _Inout_ MLAArchiveFileHandle *phMlaFile
);

BOOL
MlaBufferWrite(
   _In_ MLAArchiveFileHandle hMlaFile,
   _In_reads_(BufferSize) PBYTE pbBuffer,
   _In_ uint64_t BufferSize
);

BOOL
MlaClose(
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