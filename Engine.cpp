#include <Windows.h>
#include <stdio.h>
#include <DsGetDC.h>
#include <Lm.h>
#include <sddl.h>
#include "ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;
extern BOOL g_bExtendedTarForAd;

PDB_ENTRY g_pBaseNc;

_Success_(return)
BOOL
pLocateDc(
   _In_z_ LPWSTR szDomainName,
   _Out_ LPWSTR *szServer
);

BOOL
pProcessDomain(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _Inout_ PROOTDSE_CONFIG pRootDse,
   _In_opt_z_ LPWSTR szServer,
   _In_ ULONG ulLdapPort,
   _In_z_ LPWSTR szRootDns,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo
);

//
// Public functions
//
BOOL
Process (
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   BOOL bResult;
   WCHAR szDirectory[MAX_PATH];
   LPWSTR szRootDns = NULL;
   LPWSTR szServer = NULL;
   ULONG ulLdapPort = 0;

   ROOTDSE_CONFIG RootDse = { 0 };

   WCHAR szMetadata[MAX_METADATA_VALUE];
   ULONGLONG ullStartTime, ullEndTime;

   ullStartTime = GetTickCount64();

   //
   // Get server by DC Locator, if requested
   //
   if (pGlobalConfig->bAutoGetDomain == TRUE)
   {
      bResult = pLocateDc(NULL, &szServer);
      if (bResult == FALSE)
         return FALSE;

      // Add server to <domains> list (first entry)
      DuplicateString(szServer, &pGlobalConfig->DomainConfig[0].szServer);
   }
   else
   {
      // Check <domains> contains at least one entry
      if (pGlobalConfig->dwDomainCount == 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sDC Locator is disabled, but no domain specified%s.", COLOR_RED, COLOR_RESET
         );
         return FALSE;
      }

      if (pGlobalConfig->DomainConfig[0].szServer != NULL)
      {
         // Explicit server
         DuplicateString(pGlobalConfig->DomainConfig[0].szServer, &szServer);
         ulLdapPort = pGlobalConfig->DomainConfig[0].ulLdapPort;
      }
      else
      {
         // Get server by DC Locator
         bResult = pLocateDc(pGlobalConfig->DomainConfig[0].szDomainName, &szServer);
         if (bResult == FALSE)
         {
            return FALSE;
         }
      }
   }

   //
   // Get rootDSE from first server
   //
   bResult = LdapGetRootDse(pGlobalConfig, 0, szServer, ulLdapPort, &RootDse);
   if (bResult == FALSE)
      return FALSE;

   if (RootDse.rootDomainNamingContext != NULL)
   {
      szRootDns = ConvertDnToDns(RootDse.rootDomainNamingContext);
   }
   else
   {
      // Where there is no rootDomainNamingContext we are on AD-LDS.
      pGlobalConfig->bIsAdLds = TRUE;
      MetadataWriteFile(pGlobalConfig, L"ADLDS", (LPWSTR)L"1");

      // Use the server as szRootDns, disable GPO dump and process only first entry in <domains>
      DuplicateString(szServer, &szRootDns);
      pGlobalConfig->bProcessSysvol = FALSE;          // No sysvol with AD-LDS
      pGlobalConfig->dwDomainCount = min(pGlobalConfig->dwDomainCount, 1);
   }

   // Check szRootDns exists
   if (szRootDns == NULL)
      return FALSE;

   //
   // Create subdirectories (root, forest, domain, application)
   //

   // Root folder
   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns
   );
   bResult = CreateDirectory(szDirectory, NULL);
   if ((bResult == FALSE) && (GetLastError() != ERROR_ALREADY_EXISTS))
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sUnable to create directory '%S'%s (error %u).",
         COLOR_RED, szDirectory, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   // Root folder + time
   swprintf(
      pGlobalConfig->szFullOutDirectory, MAX_PATH,
      L"%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime
   );
   CreateDirectory(pGlobalConfig->szFullOutDirectory, NULL);

   // Domain folder (only on AD-DS)
   if (pGlobalConfig->bIsAdLds == FALSE)
   {
      swprintf(
         szDirectory, MAX_PATH,
         L"%s\\%s\\%s\\%s",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         STR_DOMAIN
      );
      CreateDirectory(szDirectory, NULL);
   }

   // Configuration folder
   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      STR_CONFIGURATION
   );
   CreateDirectory(szDirectory, NULL);

   // Schema folder
   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      STR_SCHEMA
   );
   CreateDirectory(szDirectory, NULL);

   // DNS folder (only on AD-DS)
   if (pGlobalConfig->bIsAdLds == FALSE)
   {
      swprintf(
         szDirectory, MAX_PATH,
         L"%s\\%s\\%s\\%s",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         STR_DOMAIN_DNS
      );
      CreateDirectory(szDirectory, NULL);

      swprintf(
         szDirectory, MAX_PATH,
         L"%s\\%s\\%s\\%s",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         STR_FOREST_DNS
      );
      CreateDirectory(szDirectory, NULL);
   }

   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      STR_APPLICATION
   );
   CreateDirectory(szDirectory, NULL);

   if (pGlobalConfig->bProcessSysvol)
   {
      swprintf(
         pGlobalConfig->szFullSysvolOutDirectory, MAX_PATH,
         L"%s\\%s\\%s_SYSVOL",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime
      );
      CreateDirectory(pGlobalConfig->szFullSysvolOutDirectory, NULL);
   }

   //
   // Open tables.tsv file
   //
   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\tables.tsv",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime
      );
   pGlobalConfig->hTableFile = CreateFile(szDirectory, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

   if (pGlobalConfig->hTableFile == INVALID_HANDLE_VALUE)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sUnable to open table file '%S'%s (error %u).",
         COLOR_RED, szDirectory, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   // Write base name (always first line)
   WriteTextFile(pGlobalConfig->hTableFile, "%S_%S\n", szRootDns, pGlobalConfig->szSystemTime);

   //
   // Open metadata.tsv file
   //
   MetadataCreateFile(pGlobalConfig, szRootDns);

   //
   // Process all forest global partition
   //
   for (DWORD i = 0; i < pGlobalConfig->dwRequestCount; i++)
   {
      if (pGlobalConfig->pRequests[i].dwBase & BASE_CONFIGURATION)
      {
         LdapProcessRequest(pGlobalConfig, 0, szServer, ulLdapPort, RootDse.bIsLocalAdmin, szRootDns, STR_CONFIGURATION, NULL, RootDse.configurationNamingContext, &pGlobalConfig->pRequests[i], TRUE, TRUE, FALSE);
      }

      if (pGlobalConfig->pRequests[i].dwBase & BASE_SCHEMA)
      {
         LdapProcessRequest(pGlobalConfig, 0, szServer, ulLdapPort, RootDse.bIsLocalAdmin, szRootDns, STR_SCHEMA, NULL, RootDse.schemaNamingContext, &pGlobalConfig->pRequests[i], TRUE, TRUE, FALSE);
      }

      // Forest DNS, but only with AD-DS
      if ((pGlobalConfig->pRequests[i].dwBase & BASE_FOREST_DNS) && (pGlobalConfig->bIsAdLds == FALSE))
      {
         LdapProcessRequest(pGlobalConfig, 0, szServer, ulLdapPort, RootDse.bIsLocalAdmin, szRootDns, STR_FOREST_DNS, NULL, RootDse.forestDnsNamingContext, &pGlobalConfig->pRequests[i], TRUE, TRUE, FALSE);
      }
   }

   //
   // Process domains (manual or automatic selection)
   //
   if (pGlobalConfig->bAutoGetTrusts == FALSE)
   {
      //
      // Process <domains> list
      //
      for (DWORD i = 0; i < pGlobalConfig->dwDomainCount; i++)
      {
         LPWSTR szDomainServer;

         if (pGlobalConfig->DomainConfig[i].szServer != NULL)
         {
            // Explicit server
            DuplicateString(pGlobalConfig->DomainConfig[i].szServer, &szDomainServer);

            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
               "[.] Processing extra domain in forest: server=%S",
               szDomainServer
            );
         }
         else
         {
            // Get server by DC Locator
            bResult = pLocateDc(pGlobalConfig->DomainConfig[i].szDomainName, &szDomainServer);
            if (bResult == FALSE)
            {
               continue;
            }

            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
               "[.] Processing extra domain in forest: domain=%S -> server=%S",
               pGlobalConfig->DomainConfig[i].szDomainName, szDomainServer
            );
         }

         pProcessDomain(pGlobalConfig, i, &pGlobalConfig->DomainConfig[i].RootDseConfig, szDomainServer, ulLdapPort, szRootDns, TRUE, FALSE);

         _SafeHeapRelease(szDomainServer);
      }
   }
   else
   {
      //
      // Automatic selection: all domains in forest get by DcLocator functions
      //
      DWORD dwResult;
      PDS_DOMAIN_TRUSTS pTrust;

      dwResult = DsEnumerateDomainTrusts(szServer, DS_DOMAIN_IN_FOREST, &pTrust, &pGlobalConfig->dwDomainCount);
      if (dwResult != ERROR_SUCCESS)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to enumerate trust (error %u).%s", COLOR_RED, dwResult, COLOR_RESET
         );
      }
      else
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "[.] Find %u domains in forest.", pGlobalConfig->dwDomainCount
         );

         pGlobalConfig->DomainConfig = (PDOMAIN_CONFIG)_HeapAlloc(sizeof(DOMAIN_CONFIG) * pGlobalConfig->dwDomainCount);
         if (pGlobalConfig->DomainConfig == NULL)
            return FALSE;

         for (ULONG i = 0; i < pGlobalConfig->dwDomainCount; i++)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
               "[.] Domain in forest: %S (Attribute: %u / Type: %u)",
               pTrust[i].DnsDomainName, pTrust[i].TrustAttributes, pTrust[i].TrustType
            );

            if (pTrust[i].DnsDomainName != NULL)
            {
               LPWSTR szDomainServer;

               bResult = pLocateDc(pTrust[i].DnsDomainName, &szDomainServer);
               if (bResult == FALSE)
                  continue;

               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
                  "[.] Processing domain in forest: %S",
                  pTrust[i].DnsDomainName
               );
               pProcessDomain(pGlobalConfig, USE_GLOBAL_CREDENTIALS, &pGlobalConfig->DomainConfig[i].RootDseConfig, szDomainServer, ulLdapPort, szRootDns, TRUE, FALSE);

               _SafeHeapRelease(szDomainServer);
            }
         }
      }
      NetApiBufferFree(pTrust);
   }

   //
   // Write table info into tables.tsv (FALSE, TRUE)
   // Done after all requests (TRUE, FALSE) to be sure to have max text size for all domains
   //
   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
      "[.] %sWrite table info.%s", COLOR_CYAN, COLOR_RESET
   );

   // Reset database
   DbFree(&g_pBaseNc);

   for (DWORD i = 0; i < pGlobalConfig->dwDomainCount; i++)
   {
      pProcessDomain(pGlobalConfig, 0, &pGlobalConfig->DomainConfig[i].RootDseConfig, NULL, 0, szRootDns, FALSE, TRUE);
   }

   //
   // Write column sizes in Metadata
   //
   {
      PDB_ENTRY pEntry;

      pEntry = pGlobalConfig->pBaseSize;
      while (pEntry != NULL)
      {
         WCHAR szMetadataValue[MAX_METADATA_VALUE];

         swprintf_s(szMetadataValue, MAX_METADATA_VALUE, L"%u", pEntry->dwKeyValue);
         MetadataWriteFile(pGlobalConfig, pEntry->szKeyName, szMetadataValue);
         pEntry = (PDB_ENTRY)pEntry->pNext;
      }
   }

   //
   // Finished
   //
   ullEndTime = GetTickCount64() - ullStartTime;

   // Metadata: Process Time and close
   swprintf_s(szMetadata, MAX_METADATA_VALUE, L"%llu", ullEndTime);
   MetadataWriteFile(pGlobalConfig, L"oradad_processtime", szMetadata);
   BufferClose(&pGlobalConfig->BufferMetadata);

   if (pGlobalConfig->hTableFile != NULL)
      CloseHandle(pGlobalConfig->hTableFile);

   //
   // Tar output files
   //
   if (pGlobalConfig->bTarballEnabled)
   {
      //
      // Create TAR
      //
      HANDLE hTarFile;
      WCHAR szTarFile[MAX_PATH];

      swprintf(
         szTarFile, MAX_PATH,
         L"%s\\%s_%s.tar",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime
      );

      bResult = TarInitialize(&hTarFile, szTarFile, g_bExtendedTarForAd);
      if (bResult == FALSE)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot create tar file '%S'%s (error %u).", COLOR_RED, szTarFile, COLOR_RESET, GetLastError()
         );
      }
      else
      {
         WCHAR szPrefix[MAX_PATH];

         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "[.] Create output file '%S'",
            szTarFile
         );

         swprintf_s(szPrefix, MAX_PATH, L"%s/%s", szRootDns, pGlobalConfig->szSystemTime);

         TarFilesRecursively(pGlobalConfig, pGlobalConfig->szFullOutDirectory, hTarFile, g_bExtendedTarForAd);
         TarFile(pGlobalConfig, pGlobalConfig->szLogfilePath, szPrefix, hTarFile, g_bExtendedTarForAd);
         TarClose(hTarFile);
      }

      if (pGlobalConfig->bProcessSysvol == TRUE)
      {
         swprintf(
            szTarFile, MAX_PATH,
            L"%s\\%s_%s_sysvol.tar",
            pGlobalConfig->szOutDirectory,
            szRootDns,
            pGlobalConfig->szSystemTime
         );

         bResult = TarInitialize(&hTarFile, szTarFile, FALSE);
         if (bResult == FALSE)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot create sysvol tar file '%S'%s (error %u).", COLOR_RED, szTarFile, COLOR_RESET, GetLastError()
            );
         }
         else
         {
            WCHAR szPrefix[MAX_PATH];

            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
               "[.] Create sysvol output file '%S'",
               szTarFile
            );

            swprintf_s(szPrefix, MAX_PATH, L"%s/%s", szRootDns, pGlobalConfig->szSystemTime);

            TarFilesRecursively(pGlobalConfig, pGlobalConfig->szFullSysvolOutDirectory, hTarFile, FALSE);
            TarClose(hTarFile);
         }
      }
   }

   //
   // Release
   //
   DbFree(&g_pBaseNc);
   DbFree(&pGlobalConfig->pBaseSize);
   _SafeHeapRelease(RootDse.pszNamingContexts);
   _SafeHeapRelease(szRootDns);
   _SafeHeapRelease(szServer);

   return TRUE;
}

//
// Private functions
//
_Success_(return)
BOOL
pLocateDc (
   _In_z_ LPWSTR szDomainName,
   _Out_ LPWSTR *szServer
)
{
   DWORD dwResult;
   PDOMAIN_CONTROLLER_INFO pDomainControllerInfo;

   dwResult = DsGetDcName(
      NULL, szDomainName, NULL, NULL,
      DS_ONLY_LDAP_NEEDED | DS_RETURN_DNS_NAME | DS_WRITABLE_REQUIRED,
      &pDomainControllerInfo
   );

   if (dwResult != ERROR_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to locate DC for domain '%S'%s (error %u).", COLOR_RED, szDomainName, COLOR_RESET, dwResult
      );
      return FALSE;
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[.] DC Locator: DC: %S (flags 0x%x), Domain: %S, Forest: %S",
      pDomainControllerInfo->DomainControllerName,
      pDomainControllerInfo->Flags,
      pDomainControllerInfo->DomainName,
      pDomainControllerInfo->DnsForestName
   );

   // +2 to remove '\\' prefix
   DuplicateString(pDomainControllerInfo->DomainControllerName + 2, szServer);

   NetApiBufferFree(pDomainControllerInfo);

   return TRUE;
}

BOOL
pProcessOtherNamingContexts (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _In_ PROOTDSE_CONFIG pRootDse,
   _In_opt_z_ LPWSTR szServer,
   _In_ ULONG ulLdapPort,
   _In_z_ LPWSTR szRootDns,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo
)
{
   for (DWORD dwIdx = 0; dwIdx < pRootDse->dwNamingContextsCount; ++dwIdx)
   {
      WCHAR szDirectory[MAX_PATH];
      LPWSTR szPartition;
      PDB_ENTRY pDbEntry;

      //
      // Bypass AD NC
      // If rootDomainNamingContext is present, this is a AD-DS. In this case,
      // defaultNamingContext indicates the domain DC.
      //
      if ((pRootDse->rootDomainNamingContext != NULL) &&
         (pRootDse->defaultNamingContext != NULL) &&
         (_wcsicmp(pRootDse->defaultNamingContext, pRootDse->pszNamingContexts[dwIdx]) == 0))
         continue;

      //
      // Be sure NC was not previously proceeded
      //
      pDbEntry = DbLookupKey(g_pBaseNc, pRootDse->pszNamingContexts[dwIdx]);
      if (pDbEntry != NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
            "[.] %sND NC '%S' already proceeded%s. Bypass.",
            COLOR_YELLOW,
            pRootDse->pszNamingContexts[dwIdx],
            COLOR_RESET
         );
         continue;
      }
      else
      {
         DbAddKey(&g_pBaseNc, pRootDse->pszNamingContexts[dwIdx], 0, DbCompareMode::Last);
      }

      szPartition = ConvertDnToDns(pRootDse->pszNamingContexts[dwIdx]);

      //
      // Create subdirectories (STR_APPLICATION)
      //
      swprintf(
         szDirectory, MAX_PATH,
         L"%s\\%s\\%s\\%s\\%s",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         STR_APPLICATION,
         szPartition
      );
      CreateDirectory(szDirectory, NULL);

      for (DWORD i = 0; i < pGlobalConfig->dwRequestCount; i++)
      {
         // Special case for NDNC or ADLS: get BASE_DOMAIN objects but prefix tables with STR_APPLICATION
         if (pGlobalConfig->pRequests[i].dwBase & BASE_DOMAIN)
         {
            LdapProcessRequest(pGlobalConfig, dwServerEntry, szServer, ulLdapPort, pRootDse->bIsLocalAdmin, szRootDns, STR_APPLICATION, szPartition, pRootDse->pszNamingContexts[dwIdx], &pGlobalConfig->pRequests[i], bRequestLdap, bWriteTableInfo, FALSE);
         }
      }
   }

   return TRUE;
}

BOOL
pProcessDomain (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _Inout_ PROOTDSE_CONFIG pRootDse,
   _In_opt_z_ LPWSTR szServer,
   _In_ ULONG ulLdapPort,
   _In_z_ LPWSTR szRootDns,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo
)
{
   BOOL bResult;
   BOOL bProcessDomain = FALSE;
   BOOL bProcessDomainDns = FALSE;

   LPTSTR szDomainDns = NULL;

   PDB_ENTRY pDbEntry;

   if ((bRequestLdap == TRUE) && (szServer != NULL))
   {
      WCHAR szDirectory[MAX_PATH];

      //
      // Get rootDSE
      //
      bResult = LdapGetRootDse(pGlobalConfig, dwServerEntry, szServer, ulLdapPort, pRootDse);
      if (bResult == FALSE)
         return FALSE;

      //
      // Is AD-DS or AD-LDS?
      // If AD-DS, create directories for AD NC
      //
      if ((pRootDse->rootDomainNamingContext != NULL) &&
         (pRootDse->defaultNamingContext != NULL))
      {
         szDomainDns = ConvertDnToDns(pRootDse->defaultNamingContext);
         if (szDomainDns == NULL)
            return FALSE;

         //
         // Create subdirectories (domain)
         //
         swprintf(
            szDirectory, MAX_PATH,
            L"%s\\%s\\%s\\%s\\%s",
            pGlobalConfig->szOutDirectory,
            szRootDns,
            pGlobalConfig->szSystemTime,
            STR_DOMAIN,
            szDomainDns
         );
         CreateDirectory(szDirectory, NULL);

         swprintf(
            szDirectory, MAX_PATH,
            L"%s\\%s\\%s\\%s\\%s",
            pGlobalConfig->szOutDirectory,
            szRootDns,
            pGlobalConfig->szSystemTime,
            STR_DOMAIN_DNS,
            szDomainDns
         );
         CreateDirectory(szDirectory, NULL);
      }
   }
   else if (pRootDse->defaultNamingContext != NULL)
   {
      szDomainDns = ConvertDnToDns(pRootDse->defaultNamingContext);
      if (szDomainDns == FALSE)
         return FALSE;
   }

   //
   // Process other NC (NDNC, AD-LDS)
   //
   bResult = pProcessOtherNamingContexts(pGlobalConfig, dwServerEntry, pRootDse, szServer, ulLdapPort, szRootDns, bRequestLdap, bWriteTableInfo);

   //
   // Be sure NC were not previously proceeded
   //
   pDbEntry = DbLookupKey(g_pBaseNc, pRootDse->defaultNamingContext);
   if (pDbEntry == NULL)
   {
      bProcessDomain = TRUE;
      DbAddKey(&g_pBaseNc, pRootDse->defaultNamingContext, 0, DbCompareMode::Last);
   }
   else
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
         "[.] %sNC '%S' already proceeded%s. Bypass.",
         COLOR_YELLOW,
         pRootDse->defaultNamingContext,
         COLOR_RESET
      );
   }

   pDbEntry = DbLookupKey(g_pBaseNc, pRootDse->domainDnsNamingContext);
   if (pDbEntry == NULL)
   {
      bProcessDomainDns = TRUE;
      DbAddKey(&g_pBaseNc, pRootDse->domainDnsNamingContext, 0, DbCompareMode::Last);
   }
   else
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
         "[.] %sDNS NC '%S' already proceeded%s. Bypass.",
         COLOR_YELLOW,
         pRootDse->domainDnsNamingContext,
         COLOR_RESET
      );
   }

   //
   // Process domain NC
   //
   for (DWORD i = 0; i < pGlobalConfig->dwRequestCount; i++)
   {
      //
      // RootDSE
      //
      if ((pGlobalConfig->pRequests[i].dwBase & BASE_ROOTDSE) && (bProcessDomain == TRUE))
      {
         LdapProcessRequest(
            pGlobalConfig,
            dwServerEntry,
            szServer, ulLdapPort,
            pRootDse->bIsLocalAdmin,
            szRootDns,
            (pRootDse->rootDomainNamingContext != NULL) ? STR_DOMAIN : STR_APPLICATION,
            (pRootDse->rootDomainNamingContext != NULL) ? szDomainDns : NULL,
            NULL,
            &pGlobalConfig->pRequests[i],
            bRequestLdap,
            bWriteTableInfo,
            TRUE
         );
      }

      //
      // Domain (defaultNamingContext) & DomainDNS (domainDnsNamingContext)
      // Only process on AD-DS (pRootDse->rootDomainNamingContext != NULL)
      //
      if ((pRootDse->rootDomainNamingContext != NULL) && (pRootDse->defaultNamingContext) && (bProcessDomain == TRUE))
      {
         if (pGlobalConfig->pRequests[i].dwBase & BASE_DOMAIN)
         {
            LdapProcessRequest(pGlobalConfig, dwServerEntry, szServer, ulLdapPort, pRootDse->bIsLocalAdmin, szRootDns, STR_DOMAIN, szDomainDns, pRootDse->defaultNamingContext, &pGlobalConfig->pRequests[i], bRequestLdap, bWriteTableInfo, FALSE);
         }

         if ((pGlobalConfig->pRequests[i].dwBase & BASE_DOMAIN_DNS) && (bProcessDomainDns == TRUE))
         {
            LdapProcessRequest(pGlobalConfig, dwServerEntry, szServer, ulLdapPort, pRootDse->bIsLocalAdmin, szRootDns, STR_DOMAIN_DNS, szDomainDns, pRootDse->domainDnsNamingContext, &pGlobalConfig->pRequests[i], bRequestLdap, bWriteTableInfo, FALSE);
         }
      }

      /*
      // DEBUG CODE
      for (DWORD j = 0; j < pGlobalConfig->dwRequestCount; j++)
      {
         if (wcscmp(pGlobalConfig->pRequests[j].szName, L"computer") == 0)
         {
            wprintf(L"%u[%s]: ", j, pGlobalConfig->pRequests[j].szName);
            for (DWORD k = 0; k < pGlobalConfig->pRequests[j].dwAttributesCount; k++)
            {
               if (wcscmp((*pGlobalConfig->pRequests[j].pAttributes[k]).szName, L"cn") == 0)
                  wprintf(L" %s:%u", (*pGlobalConfig->pRequests[j].pAttributes[k]).szName, pGlobalConfig->pRequests[j].pdwStringMaxLength[k]);
            }
            printf("\n");
         }
      }
      */
   }

   //
   // Process SYSVOL
   // Process if requested (bProcessSysvol) and only on AD-DS (pRootDse->rootDomainNamingContext != NULL)
   //
   if ((pGlobalConfig->bProcessSysvol) && (pRootDse->rootDomainNamingContext != NULL) && (bProcessDomain==TRUE))
   {
      if (bWriteTableInfo == FALSE)
      {
         ProcessSysvol(pGlobalConfig, dwServerEntry, szRootDns, STR_DOMAIN, szDomainDns, szServer);
      }
      else
      {
         SysvolWriteTableInfo(pGlobalConfig->hTableFile, szDomainDns);
      }
   }

   _SafeHeapRelease(szDomainDns);

   return TRUE;
}
