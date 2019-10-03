#include <Windows.h>
#include <stdio.h>
#include <DsGetDC.h>
#include <Lm.h>
#include <sddl.h>
#include "ORADAD.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

static LPWSTR g_ProcessedDomains[1200] = { 0 };  //1200 = max recommended domains per forest.
static DWORD g_dwProcessedDomainsIdx = 0;

_Success_(return)
BOOL
pLocateDc(
   _In_z_ LPWSTR szDomainName,
   _Out_ LPWSTR *szServer
);

BOOL
pProcessDomain(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _Inout_ PROOTDSE_CONFIG pRootDse,
   _In_opt_z_ LPWSTR szServer,
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

   ROOTDSE_CONFIG RootDse = { 0 };

   WCHAR szMetadata[MAX_METADATA_VALUE];
   ULONGLONG ullStartTime, ullEndTime;
   DWORD dwForestDomainsCount = 1;

   ullStartTime = GetTickCount64();

   //
   // Get server by DC Locator, if needed
   //
   if (pGlobalConfig->szServer == NULL)
   {
      bResult = pLocateDc(NULL, &szServer);
      if (bResult == FALSE)
         return FALSE;
   }
   else
   {
      DuplicateString(pGlobalConfig->szServer, &szServer);
   }

   //
   // Get rootDSE
   //
   bResult = LdapGetRootDse(pGlobalConfig, szServer, &RootDse);
   if (bResult == FALSE)
      return FALSE;

   szRootDns = ConvertDnToDns(RootDse.rootDomainNamingContext);
   if (szRootDns == NULL)
      return FALSE;

   //
   // Create subdirectories (root and forest)
   //
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

   swprintf(
      pGlobalConfig->szFullOutDirectory, MAX_PATH,
      L"%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime
   );
   CreateDirectory(pGlobalConfig->szFullOutDirectory, NULL);

   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      STR_DOMAIN
   );
   CreateDirectory(szDirectory, NULL);

   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      STR_CONFIGURATION
   );
   CreateDirectory(szDirectory, NULL);

   swprintf(
      szDirectory, MAX_PATH,
      L"%s\\%s\\%s\\%s",
      pGlobalConfig->szOutDirectory,
      szRootDns,
      pGlobalConfig->szSystemTime,
      STR_SCHEMA
   );
   CreateDirectory(szDirectory, NULL);

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
   pGlobalConfig->bWriteMetadataSize = TRUE;

   //
   // Process all forest global partition
   //
   for (DWORD i = 0; i < pGlobalConfig->dwRequestCount; i++)
   {
      if (pGlobalConfig->pRequests[i].dwBase & BASE_CONFIGURATION)
      {
         LdapProcessRequest(pGlobalConfig, szServer, RootDse.bIsLocalAdmin, szRootDns, STR_CONFIGURATION, NULL, RootDse.configurationNamingContext, &pGlobalConfig->pRequests[i], TRUE, TRUE, FALSE);
      }

      if (pGlobalConfig->pRequests[i].dwBase & BASE_SCHEMA)
      {
         LdapProcessRequest(pGlobalConfig, szServer, RootDse.bIsLocalAdmin, szRootDns, STR_SCHEMA, NULL, RootDse.schemaNamingContext, &pGlobalConfig->pRequests[i], TRUE, TRUE, FALSE);
      }

      if (pGlobalConfig->pRequests[i].dwBase & BASE_FOREST_DNS)
      {
         LdapProcessRequest(pGlobalConfig, szServer, RootDse.bIsLocalAdmin, szRootDns, STR_FOREST_DNS, NULL, RootDse.forestDnsNamingContext, &pGlobalConfig->pRequests[i], TRUE, TRUE, FALSE);
      }
   }

   //
   // Domains (only our domain and <forestDomains> list or all domains in forest)
   //
   if (pGlobalConfig->bAllDomainsInForest == FALSE)
   {
      PROOTDSE_CONFIG pRootDseForestDomains = NULL;

      //
      // Process our domain
      //
      pProcessDomain(pGlobalConfig, &RootDse, szServer, szRootDns, TRUE, FALSE);
      g_ProcessedDomains[g_dwProcessedDomainsIdx++] = szServer;

      //
      // Process <forestDomains> list
      //
      if (pGlobalConfig->szForestDomains != NULL)
      {
         DWORD dwDomainIndex = 0;
         LPWSTR szContext = NULL;
         LPWSTR szForestDomainsCopy;
         LPWSTR szOtherDomain;

         //
         // Count how many domains in list
         //
         for (size_t i = 0; i < wcslen(pGlobalConfig->szForestDomains); i++)
         {
            if (pGlobalConfig->szForestDomains[i] == ',')
               dwForestDomainsCount++;
         }

         //
         // Allocate rootDse entries
         //
         pRootDseForestDomains = (PROOTDSE_CONFIG)_HeapAlloc(sizeof(ROOTDSE_CONFIG) * dwForestDomainsCount);
         if (pRootDseForestDomains == NULL)
            return FALSE;

         //
         // Process domains list
         //
         DuplicateString(pGlobalConfig->szForestDomains, &szForestDomainsCopy);
         szOtherDomain = wcstok_s(szForestDomainsCopy, L",", &szContext);

         while (szOtherDomain != NULL)
         {
            LPWSTR szDomainServer;

            // Skip domain of we have already processed it
            for (DWORD dwIdx = 0; dwIdx < g_dwProcessedDomainsIdx; ++dwIdx)
            {
               if (_wcsicmp(szOtherDomain, g_ProcessedDomains[dwIdx]) == 0)
               {
                  goto NextOtherDomain;
               }
            }

            bResult = pLocateDc(szOtherDomain, &szDomainServer);
            if (bResult == FALSE)
            {
               goto NextOtherDomain;
            }

            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
               "[.] Processing extra domain in forest: %S",
               szOtherDomain
            );
            pProcessDomain(pGlobalConfig, &pRootDseForestDomains[dwDomainIndex], szDomainServer, szRootDns, TRUE, FALSE);

            g_ProcessedDomains[g_dwProcessedDomainsIdx++] = szOtherDomain;

            _SafeHeapRelease(szDomainServer);

         NextOtherDomain:
            // Move to next token
            szOtherDomain = wcstok_s(NULL, L",", &szContext);
            dwDomainIndex++;
         }

         _SafeHeapRelease(szForestDomainsCopy);
      }

      //
      // Write table infos into tables.tsv (FALSE, TRUE)
      // Done after all requests (TRUE, FALSE) to be sure to have max text size for all domains
      //
      pProcessDomain(pGlobalConfig, &RootDse, NULL, szRootDns, FALSE, TRUE);

      // Be sure to write only once data size in metadata.tsv
      pGlobalConfig->bWriteMetadataSize = FALSE;

      if (pGlobalConfig->szForestDomains != NULL)
      {
         DWORD dwDomainIndex = 0;
         LPWSTR szContext = NULL;
         LPWSTR szForestDomainsCopy;
         LPWSTR szOtherDomain;

         DuplicateString(pGlobalConfig->szForestDomains, &szForestDomainsCopy);
         szOtherDomain = wcstok_s(szForestDomainsCopy, L",", &szContext);

         while (szOtherDomain != NULL)
         {
            pProcessDomain(pGlobalConfig, &pRootDseForestDomains[dwDomainIndex], NULL, szRootDns, FALSE, TRUE);

            // Move to next token
            szOtherDomain = wcstok_s(NULL, L",", &szContext);
            dwDomainIndex++;
         }

         _SafeHeapRelease(szForestDomainsCopy);
      }

      _SafeHeapRelease(pRootDseForestDomains);
   }
   else
   {
      DWORD dwResult;
      PDS_DOMAIN_TRUSTS pTrust;
      ULONG ulDomainCount;

      dwResult = DsEnumerateDomainTrusts(szServer, DS_DOMAIN_IN_FOREST, &pTrust, &ulDomainCount);
      if (dwResult != ERROR_SUCCESS)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sUnable to enumerate trust (error %u).%s", COLOR_RED, dwResult, COLOR_RESET
         );
      }
      else
      {
         PROOTDSE_CONFIG pRootDse;

         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "[.] Find %u domains in forest.", ulDomainCount
         );

         pRootDse = (PROOTDSE_CONFIG)_HeapAlloc(sizeof(ROOTDSE_CONFIG) * ulDomainCount);
         if (pRootDse == NULL)
            return FALSE;

         for (ULONG i = 0; i < ulDomainCount; i++)
         {
            // Skip domain of we have already processed it
            for (DWORD dwIdx = 0; dwIdx < g_dwProcessedDomainsIdx; ++dwIdx)
            {
               if (_wcsicmp(pTrust[i].DnsDomainName, g_ProcessedDomains[dwIdx]) == 0)
               {
                  continue;
               }
            }

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
               pProcessDomain(pGlobalConfig, &pRootDse[i], szDomainServer, szRootDns, TRUE, FALSE);

               g_ProcessedDomains[g_dwProcessedDomainsIdx++] = pTrust[i].DnsDomainName;

               _SafeHeapRelease(szDomainServer);
            }
         }

         //
         // Write table infos into tables.tsv (FALSE, TRUE)
         // Done after all requests (TRUE, FALSE) to be sure to have max text size for all domains
         //
         for (ULONG i = 0; i < ulDomainCount; i++)
         {
            if (pTrust[i].DnsDomainName != NULL)
               pProcessDomain(pGlobalConfig, &pRootDse[i], NULL, szRootDns, FALSE, TRUE);

            // Be sure to write only once data size in metadata.tsv
            if (pGlobalConfig->bWriteMetadataSize == TRUE)
               pGlobalConfig->bWriteMetadataSize = FALSE;
         }

         _SafeHeapRelease(pRootDse);
      }
      NetApiBufferFree(pTrust);
   }

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

      bResult = TarInitialize(&hTarFile, szTarFile);
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

         TarFilesRecursively(pGlobalConfig, pGlobalConfig->szFullOutDirectory, hTarFile);
         TarFile(pGlobalConfig, pGlobalConfig->szLogfilePath, szPrefix, hTarFile);
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

         bResult = TarInitialize(&hTarFile, szTarFile);
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

            TarFilesRecursively(pGlobalConfig, pGlobalConfig->szFullSysvolOutDirectory, hTarFile);
            TarClose(hTarFile);
         }
      }
   }

   //
   // Release
   //
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
pProcessDomain (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _Inout_ PROOTDSE_CONFIG pRootDse,
   _In_opt_z_ LPWSTR szServer,
   _In_z_ LPWSTR szRootDns,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo
)
{
   BOOL bResult;

   LPTSTR szDomainDns;

   if ((bRequestLdap == TRUE) && (szServer != NULL))
   {
      WCHAR szDirectory[MAX_PATH];

      //
      // Get rootDSE
      //
      bResult = LdapGetRootDse(pGlobalConfig, szServer, pRootDse);
      if (bResult == FALSE)
         return FALSE;

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
   else if (pRootDse->defaultNamingContext != NULL)
   {
      szDomainDns = ConvertDnToDns(pRootDse->defaultNamingContext);
      if (szDomainDns == FALSE)
         return FALSE;
   }
   else
   {
      return FALSE;
   }

   //
   // PROCRESS LDAP
   //
   for (DWORD i = 0; i < pGlobalConfig->dwRequestCount; i++)
   {
      if (pGlobalConfig->pRequests[i].dwBase & BASE_ROOTDSE)
      {
         LdapProcessRequest(pGlobalConfig, szServer, pRootDse->bIsLocalAdmin, szRootDns, STR_DOMAIN, szDomainDns, NULL, &pGlobalConfig->pRequests[i], bRequestLdap, bWriteTableInfo, TRUE);
      }

      if (pGlobalConfig->pRequests[i].dwBase & BASE_DOMAIN)
      {
         LdapProcessRequest(pGlobalConfig, szServer, pRootDse->bIsLocalAdmin, szRootDns, STR_DOMAIN, szDomainDns, pRootDse->defaultNamingContext, &pGlobalConfig->pRequests[i], bRequestLdap, bWriteTableInfo, FALSE);
      }

      if (pGlobalConfig->pRequests[i].dwBase & BASE_DOMAIN_DNS)
      {
         LdapProcessRequest(pGlobalConfig, szServer, pRootDse->bIsLocalAdmin, szRootDns, STR_DOMAIN_DNS, szDomainDns, pRootDse->domainDnsNamingContext, &pGlobalConfig->pRequests[i], bRequestLdap, bWriteTableInfo, FALSE);
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
   // PROCESS SYSVOL
   //
   if (pGlobalConfig->bProcessSysvol)
   {
      if (bWriteTableInfo == FALSE)
      {
         ProcessSysvol(pGlobalConfig, szRootDns, STR_DOMAIN, szDomainDns, szServer);
      }
      else
      {
         SysvolWriteTableInfo(pGlobalConfig->hTableFile, szDomainDns);
      }
   }

   _SafeHeapRelease(szDomainDns);

   return TRUE;
}
