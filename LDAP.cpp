#include <Windows.h>
#include <Winldap.h>
#include <NtLdap.h>           // For LDAP Extended Controls
#include <Winber.h>
#include <stdio.h>
#include <Winber.h>
#include <sddl.h>
#include <intsafe.h>
#include "ORADAD.h"

#define MAX_ATTRIBUTE_NAME       64

extern GLOBAL_CONFIG g_GlobalConfig;
extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

//
// Private functions
//
LDAP*
pLdapOpenConnection(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _In_z_ LPWSTR szServerName,
   _In_ ULONG ulLdapPort
);

BOOL
pWriteTableInfo(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ PREQUEST_CONFIG pRequest,
   _In_ BOOL bIsTop,
   _In_ BOOL bIsRootDSE,
   _In_z_ LPWSTR szRelativePath,
   _In_z_ LPWSTR szTableName,
   _In_z_ LPWSTR szTableNameNoDomain,
   _In_ DWORD dwAttributesCount,
   _In_ PATTRIBUTE_CONFIG *pAttributes
);

BOOL
pHasAttributeWithRange(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPWSTR szDn
);

_Success_(return)
BOOL
pParseRange(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPWSTR szAttribute,
   _Out_ LPWSTR *pszAttrName,
   _Out_ PDWORD pdwEnd
);

LPWSTR*
pGetRangedAttribute(
   _In_ LDAP* pLdapHandle,
   _In_ LPWSTR szDn,
   _In_ LPWSTR szAttribute,
   _In_ PDWORD pdwRangeStart
);

//
// Public functions
//
BOOL
LdapGetRootDse (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _In_z_ LPWSTR szServerName,
   _In_ ULONG ulLdapPort,
   _Out_ PROOTDSE_CONFIG pRootDse
)
{
   ULONG ulResult;

   LDAP* pLdapHandle;
   LDAPMessage *pLdapMessage = NULL;
   LDAPMessage* pEntry = NULL;
   PWCHAR pAttribute = NULL;
   BerElement* pBer = NULL;

   LPCWSTR szAttrsSearch[] = {
      L"dnsHostName" , L"serverName" ,
      L"defaultNamingContext", L"rootDomainNamingContext", L"configurationNamingContext", L"schemaNamingContext", L"namingContexts",
      L"domainControllerFunctionality", L"domainFunctionality", L"forestFunctionality",
      L"tokenGroups",         // Constructed rootDse attribute. Must be explicitly requested.
      NULL
   };

   pLdapHandle = pLdapOpenConnection(pGlobalConfig, dwServerEntry, szServerName, ulLdapPort);
   if (pLdapHandle == NULL)
      return FALSE;

#pragma warning(suppress : 6387) /* for rootDSE, filter=NULL is required */
   ulResult = ldap_search_s(pLdapHandle, NULL, LDAP_SCOPE_BASE, NULL, (PZPWSTR)szAttrsSearch, FALSE, &pLdapMessage);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sError in ldap_search_s(rootdse)%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
      );
      return FALSE;
   }

   pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
   pAttribute = ldap_first_attribute(pLdapHandle, pEntry, &pBer);

   pRootDse->bIsLocalAdmin = FALSE;
   pRootDse->dwNamingContextsCount = 0;

   if (pGlobalConfig->bBypassLdapProcess == TRUE)
      goto End;

   while (pAttribute != NULL)
   {
      PWCHAR *ppValue = NULL;

      ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

      if (ppValue != NULL)
      {
         ULONG ulValues;

         if ((wcscmp(pAttribute, L"dnsHostName") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->dnsHostName);
         else if ((wcscmp(pAttribute, L"serverName") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->serverName);
         else if ((wcscmp(pAttribute, L"defaultNamingContext") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->defaultNamingContext);
         else if ((wcscmp(pAttribute, L"rootDomainNamingContext") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->rootDomainNamingContext);
         else if ((wcscmp(pAttribute, L"configurationNamingContext") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->configurationNamingContext);
         else if ((wcscmp(pAttribute, L"schemaNamingContext") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->schemaNamingContext);
         else if ((wcscmp(pAttribute, L"domainControllerFunctionality") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->domainControllerFunctionality);
         else if ((wcscmp(pAttribute, L"domainFunctionality") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->domainFunctionality);
         else if ((wcscmp(pAttribute, L"forestFunctionality") == 0) && (wcslen(pAttribute) > 0))
            DuplicateString(ppValue[0], &pRootDse->forestFunctionality);
         else if ((wcscmp(pAttribute, L"namingContexts") == 0) && (wcslen(pAttribute) > 0))
         {
            ulValues = ldap_count_values(ppValue);

            pRootDse->pszNamingContexts = (LPWSTR*)_HeapAlloc(ulValues * sizeof(LPWSTR));

            for (ULONG i = 0; i < ulValues; i++)
            {
               if (wcsstr(ppValue[i], L"DC=ForestDnsZones,") == ppValue[i])
                  DuplicateString(ppValue[i], &pRootDse->forestDnsNamingContext);
               else if (wcsstr(ppValue[i], L"DC=DomainDnsZones,") == ppValue[i])
                  DuplicateString(ppValue[i], &pRootDse->domainDnsNamingContext);
               else if (wcsstr(ppValue[i], L"CN=Configuration,") == ppValue[i] || wcsstr(ppValue[i], L"CN=Schema,CN=Configuration,") == ppValue[i])
                  continue;
               else
               {
                  // Get all Naming Context, except DNS, Configuration and Schema
                  DuplicateString(ppValue[i], &pRootDse->pszNamingContexts[pRootDse->dwNamingContextsCount]);
                  pRootDse->dwNamingContextsCount += 1;
               }
            }
         }
         else if ((wcscmp(pAttribute, L"tokenGroups") == 0) && (wcslen(pAttribute) > 0))
         {
            berval **ppval = NULL;

            ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

            if (ppval != NULL)
            {
               ulValues = ldap_count_values_len(ppval);

               for (ULONG j = 0; j < ulValues; j++)
               {
                  BOOL bResult;
                  LPTSTR szSid;

                  bResult = ConvertSidToStringSid(ppval[j]->bv_val, &szSid);

                  if (bResult == TRUE)
                  {
                     if (wcscmp(szSid, L"S-1-5-32-544") == 0)         // Administrators
                     {
                        pRootDse->bIsLocalAdmin = TRUE;
                     }
                     LocalFree(szSid);
                  }
               }
            }
            ldap_value_free_len(ppval);
         }
         ldap_value_free(ppValue);
      }

      ldap_memfree(pAttribute);
      pAttribute = ldap_next_attribute(pLdapHandle, pEntry, pBer);
   }

End:
   if (pBer != NULL)
   {
      ber_free(pBer, 0);
      pBer = NULL;
   }

   ulResult = ldap_msgfree(pLdapMessage);
   ulResult = ldap_unbind(pLdapHandle);

   return TRUE;
}

BOOL
LdapProcessRequest (
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
)
{
   BOOL bResult;
   BOOL bBufferOpen = FALSE;
   WCHAR szRelativePath[MAX_PATH];
   WCHAR szTableName[MAX_PATH];
   WCHAR szTableNameNoDomain[MAX_PATH];

   DWORD dwAttributesCount;
   PATTRIBUTE_CONFIG *pAttributes;

   BOOL bIsTop = FALSE;

   ULONG ulResult;
   ULONG ulReturnCode;
   ULONG ulEntriesCount;
   ULONG ulTotalEntriesCount = 0;

   if (bIsRootDSE == TRUE)
   {
      DWORD dwIdx = 0;

      dwAttributesCount = pGlobalConfig->dwRootDSEAttributesCount;

      // pRootDSEAttributes is array of attributes
      // pAttributes is array of pointers to attributes. Create temporary array.
      pAttributes = (PATTRIBUTE_CONFIG*)_HeapAlloc(dwAttributesCount * sizeof(PATTRIBUTE_CONFIG));
      if (pAttributes == NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot allocate memory%s (error %u).",
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      for (DWORD i = 0; i < dwAttributesCount; i++)
      {
         if (pGlobalConfig->pRootDSEAttributes[i].dwLevel <= pGlobalConfig->dwLevel)
         {
            pAttributes[dwIdx] = &(pGlobalConfig->pRootDSEAttributes[i]);
            dwIdx++;
         }
      }
      dwAttributesCount = dwIdx;
   }
   else
   {
      DWORD dwIdx = 0;

      dwAttributesCount = pRequest->dwAttributesCount;
      pAttributes = (PATTRIBUTE_CONFIG*)_HeapAlloc(dwAttributesCount * sizeof(PATTRIBUTE_CONFIG));
      if (pAttributes == NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot allocate memory%s (error %u).",
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      for (DWORD i = 0; i < dwAttributesCount; i++)
      {
         if (pRequest->pAttributes[i]->dwLevel <= pGlobalConfig->dwLevel)
         {
            pAttributes[dwIdx] = pRequest->pAttributes[i];
            dwIdx++;
         }
      }
      dwAttributesCount = dwIdx;
   }

   if (_wcsicmp(pRequest->szName, L"top") == 0)
      bIsTop = TRUE;

   //
   // Initialize names
   //
   // szRelativePath:      filename where to write buffer data and write in tables.tsv
   // szTableName:         write in tables.tsv (not used anymore) and metadata.tsv
   // szTableNameNoDomain: write in tables.tsv (not used anymore), metadata.tsv and metadata.tsv
   //
   if ((szPath1 != NULL) && (szPath2 != NULL))
   {
      swprintf_s(
         szRelativePath, MAX_PATH,
         L"%s\\%s\\%s.tsv",
         szPath1,
         szPath2,
         pRequest->szName
      );

      swprintf_s(
         szTableName, MAX_PATH,
         L"%s_%s_%s",
         szPath1,
         szPath2,
         pRequest->szName
      );

      swprintf_s(
         szTableNameNoDomain, MAX_PATH,
         L"%s_%s",
         szPath1,
         pRequest->szName
      );
   }
   else if ((szPath1 != NULL) && (szPath2 == NULL))
   {
      swprintf_s(
         szRelativePath, MAX_PATH,
         L"%s\\%s.tsv",
         szPath1,
         pRequest->szName
      );

      swprintf_s(
         szTableName, MAX_PATH,
         L"%s_%s",
         szPath1,
         pRequest->szName
      );

      swprintf_s(
         szTableNameNoDomain, MAX_PATH,
         L"%s_%s",
         szPath1,
         pRequest->szName
      );
   }
   else
   {
      return FALSE;
   }

   //
   // Special case for rootDSE
   //
   if (bIsRootDSE == TRUE)
   {
      swprintf_s(
         szTableName, MAX_PATH,
         L"%s",
         pRequest->szName
      );

      swprintf_s(
         szTableNameNoDomain, MAX_PATH,
         L"%s",
         pRequest->szName
      );
   }

   if ((bRequestLdap == TRUE) && (szServer != NULL))
   {
      BUFFER_DATA Buffer;
      PBUFFER_DATA pBuffer;

      LDAP* pLdapHandle;
      LDAPMessage *pLdapMessage = NULL;

      LPWSTR *pszAttributes = NULL;

      PLDAPControl pLdapControl = NULL;
      PLDAPControl *controlArray = NULL;

      LDAPMessage* pEntry = NULL;

      LDAP_BERVAL LdapCookie = { 0, NULL };
      PLDAP_BERVAL pLdapNewCookie = NULL;
      PLDAPControl *currControls = NULL;

      DWORD dwObjectCount = 0;
      ULONGLONG ullStartTime, ullEndTime;

      // Allocate controls
      // 0: paging, 1..n:controls, <last>: NULL
      controlArray = (PLDAPControl*)_HeapAlloc(((size_t)pRequest->dwControlsCount + 2) * sizeof(LDAPControl*));
      if (controlArray == NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
            "[!] %sCannot allocate memory%s (error %u).",
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         return FALSE;
      }

      ullStartTime = GetTickCount64();

      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "[.] Dumping '%S/%S/%S/%S'.", szRootDns, szPath1, szPath2, pRequest->szName
      );

      //
      // Create output buffer
      //
      bResult = BufferInitialize(&Buffer, szRelativePath, TRUE, FALSE);
      if (bResult == FALSE)
         return FALSE;
      else
         bBufferOpen = TRUE;

      pBuffer = &Buffer;

      //
      // Write header into output file if requested by configuration
      //
      if (pGlobalConfig->bWriteHeader == TRUE)
      {
         if (bIsRootDSE == TRUE)
            BufferWrite(pBuffer, (LPWSTR)L"server");
         else
            BufferWrite(pBuffer, (LPWSTR)L"dn");

         if (bIsTop == TRUE)
         {
            BufferWriteTab(pBuffer);
            BufferWrite(pBuffer, (LPWSTR)L"shortname");
            BufferWriteTab(pBuffer);
            BufferWrite(pBuffer, (LPWSTR)L"shortdn");
         }

         for (DWORD i = 0; i < dwAttributesCount; i++)
         {
            if (((*pAttributes[i]).Type == TYPE_INT) || ((*pAttributes[i]).Type == TYPE_INT64))
            {
               if ((*pAttributes[i]).fFilter == NULL)
               {
                  // No filter: int only
                  BufferWriteTab(pBuffer);
                  BufferWrite(pBuffer, (*pAttributes[i]).szName);
               }
               else
               {
                  // Filter: text + int
                  BufferWriteTab(pBuffer);
                  BufferWrite(pBuffer, (*pAttributes[i]).szName);

                  BufferWriteTab(pBuffer);
                  BufferWrite(pBuffer, (*pAttributes[i]).szName);
                  BufferWrite(pBuffer, (LPWSTR)L"_int");
               }
            }
            else
            {
               BufferWriteTab(pBuffer);
               BufferWrite(pBuffer, (*pAttributes[i]).szName);
            }
         }

         BufferWriteLine(pBuffer);
      }

      // If NC doesn't exist (ie DomainDNS), bypass LDAP request
      // For rootDSE, no NC is provided
      if ((szLdapBase != NULL) || (bIsRootDSE == TRUE))
      {
         //
         // Process
         //
         pLdapHandle = pLdapOpenConnection(pGlobalConfig, dwServerEntry, szServer, ulLdapPort);
         if (pLdapHandle == NULL)
         {
            if (bBufferOpen == TRUE)
               BufferClose(&Buffer);

            return FALSE;
         }

         // Add page control in controlArray[0]
         ulResult = ldap_create_page_control(
            pLdapHandle,
            900,
            &LdapCookie,
            TRUE,
            &pLdapControl
         );

         controlArray[0] = pLdapControl;

         for (DWORD dwControlIt = 0; dwControlIt < pRequest->dwControlsCount; ++dwControlIt)
         {
            LDAPControl* LdapControl;
            BerElement* pBerElmt = NULL;
            berval* pBerVal = NULL;

            LdapControl = (LDAPControl*)_HeapAlloc(sizeof(LDAPControl));
            if (LdapControl == NULL)
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                  "[!] %sCannot allocate memory%s (error %u).",
                  COLOR_RED, COLOR_RESET, GetLastError()
               );

               if (bBufferOpen == TRUE)
                  BufferClose(&Buffer);

               return FALSE;
            }

            pBerElmt = ber_alloc_t(LBER_USE_DER);

            if (pRequest->pControls[dwControlIt].szValue == NULL)
            {
               // Do nothing here, flatten will produce pBerVal with bv_len = 0
            }
            else if (_wcsicmp(pRequest->pControls[dwControlIt].szValueType, L"int") == 0)
            {
               ULONG ulValue = wcstoul(pRequest->pControls[dwControlIt].szValue, NULL, 0);

               // Special case for OID LDAP_SERVER_SD_FLAGS_OID: Mask SACL_SECURITY_INFORMATION if not admin
               if (_wcsicmp(pRequest->pControls[dwControlIt].szOid, L"1.2.840.113556.1.4.801") == 0 &&
                  bIsLocalAdmin == FALSE)
               {
                  ulValue &= ~SACL_SECURITY_INFORMATION;
               }

               ber_printf(pBerElmt, (PSTR)"{i}", ulValue);
            }

            ber_flatten(pBerElmt, &pBerVal);

            LdapControl->ldctl_iscritical = pRequest->pControls[dwControlIt].isCritical;
            LdapControl->ldctl_oid = pRequest->pControls[dwControlIt].szOid;
            LdapControl->ldctl_value.bv_val = pBerVal->bv_val;
            LdapControl->ldctl_value.bv_len = pBerVal->bv_len;

            controlArray[dwControlIt + 1] = LdapControl;

            ber_free(pBerElmt, 1);
         }

         //
         // Format pszAttributes list
         // Note: dn can't be requested in attribute list. We get it by ldap_get_dn().
         //
         pszAttributes = (LPWSTR*)_HeapAlloc(((size_t)dwAttributesCount + 1) * sizeof(LPWSTR));   // +1 for NULL (list terminator)
         for (DWORD i = 0; i < dwAttributesCount; i++)
            pszAttributes[i] = (*pAttributes[i]).szName;

         //
         // Process searches
         //
      Loop:
         ulResult = ldap_search_ext_s(
            pLdapHandle,
            szLdapBase,
            pRequest->dwScope,
            pRequest->szFilter,
            pszAttributes,       // attrs
            0,                   // attrsonly
            controlArray,        // ServerControls
            NULL,                // ClientControls
            0,                   // timeout
            0,                   // SizeLimit
            &pLdapMessage
         );
         if (ulResult != LDAP_SUCCESS)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sError in ldap_search_ext_s('%S', '%S')%s (error %u: %s).",
               COLOR_RED, szLdapBase, pRequest->szFilter, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
            );
            return FALSE;
            //goto End;
         }

         ulEntriesCount = ldap_count_entries(
            pLdapHandle,
            pLdapMessage
         );

         ulTotalEntriesCount += ulEntriesCount;
         if (pGlobalConfig->bDisplayProgress == TRUE)
            fwprintf(stdout, L"\r   Processed %lu entries", ulTotalEntriesCount);

         for (ULONG i = 0; i < ulEntriesCount; i++)
         {
            LPWSTR szDn;
            BOOL bHasRange;
            BOOL bIsRoot = FALSE;

            if (i == 0)
               pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
            else
               pEntry = ldap_next_entry(pLdapHandle, pEntry);

            szDn = ldap_get_dn(pLdapHandle, pEntry);

            if (bIsRootDSE == TRUE)
            {
               // For RootDSE, dwStringMaxLengthShortName is used for 'server' max size
               _CallWriteAndGetMax(BufferWrite(pBuffer, szServer), pRequest->dwStringMaxLengthShortName);
               BufferWriteTab(pBuffer);
            }
            else
            {
               //
               // For all files, 'dn' is first column
               //
               if (szDn != NULL)
               {
                  LPWSTR szDnDns;

                  _CallWriteAndGetMax(BufferWrite(pBuffer, szDn), pRequest->dwStringMaxLengthDn);

                  szDnDns = ConvertDnToDns(szDn);

                  if (_wcsicmp(szDnDns, szRootDns) == 0)
                     bIsRoot = TRUE;

                  _SafeHeapRelease(szDnDns);
               }
               BufferWriteTab(pBuffer);
            }

            //
            // Two more columns for 'top'
            //
            if (bIsTop == TRUE)
            {
               WCHAR szShortName[MAX_PATH];

               //
               // Short name
               //
               if (szPath2 != NULL)
                  swprintf_s(szShortName, MAX_PATH, L"%s/%s", szPath1, szPath2);
               else
                  swprintf_s(szShortName, MAX_PATH, L"%s/%s", szPath1, szRootDns);
               _CallWriteAndGetMax(BufferWrite(pBuffer, szShortName), pRequest->dwStringMaxLengthShortName);
               BufferWriteTab(pBuffer);

               //
               // Short DN
               //
               if (szDn != NULL)
               {
                  LPWSTR szBasePosition;

                  // Compute short DN
                  szBasePosition = wcsstr(szDn, szLdapBase);
                  if ((szBasePosition != NULL) && (szBasePosition != szDn))
                  {
                     *(szBasePosition - 1) = 0;       // -1 to remove ','
                     _CallWriteAndGetMax(BufferWrite(pBuffer, szDn), pRequest->dwStringMaxLengthShortDn);
                  }
                  BufferWriteTab(pBuffer);
               }
               else
               {
                  BufferWriteTab(pBuffer);
               }
            }

            //
            // Check range
            //
            bHasRange = pHasAttributeWithRange(pLdapHandle, pEntry, szDn);

            //
            // Other attributes
            //
            for (DWORD j = 0; j < dwAttributesCount; j++)
            {
               LPWSTR pAttribute = NULL;
               LPWSTR* ppValue = NULL;
               berval** ppval = NULL;

               ppval = NULL;
               pAttribute = pszAttributes[j];

               switch ((*pAttributes[j]).Type)
               {
               case TYPE_STR:
               case TYPE_INT:
               case TYPE_INT64:
               {
                  ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

                  if (ppValue != NULL)
                  {
                     if (((*pAttributes[j]).Type == TYPE_INT) && ((*pAttributes[j]).fFilter != NULL))
                     {
                        // INT + filter
                        LPWSTR szText;
                        LONG lValue = 0;

                        swscanf_s(ppValue[0], L"%li", &lValue);

                        szText = ApplyFilter(&(*pAttributes[j]), &lValue);
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szText), pRequest->pdwStringMaxLength[j]);
                        _SafeHeapRelease(szText);

                        BufferWriteTab(pBuffer);
                        BufferWrite(pBuffer, ppValue[0]);
                     }
                     else if (((*pAttributes[j]).Type == TYPE_INT64) && ((*pAttributes[j]).fFilter != NULL))
                     {
                        // INT64 + filter
                        LPWSTR szText;
                        LONGLONG llValue = 0;

                        swscanf_s(ppValue[0], L"%lli", &llValue);

                        szText = ApplyFilter(&(*pAttributes[j]), &llValue);
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szText), pRequest->pdwStringMaxLength[j]);
                        _SafeHeapRelease(szText);

                        BufferWriteTab(pBuffer);
                        BufferWrite(pBuffer, ppValue[0]);
                     }
                     else
                     {
                        // STR
                        _CallWriteAndGetMax(BufferWrite(pBuffer, ppValue[0]), pRequest->pdwStringMaxLength[j]);
                     }
                  }
                  else if ((((*pAttributes[j]).Type == TYPE_INT) || ((*pAttributes[j]).Type == TYPE_INT64)) && ((*pAttributes[j]).fFilter != NULL))
                  {
                     _CallWriteAndGetMax(BufferWriteTab(pBuffer), pRequest->pdwStringMaxLength[j]);
                  }
               }
               break;

               case TYPE_STRS:
               {
                  ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

                  if (ppValue != NULL)
                  {
                     if (*ppValue != NULL)
                     {
                        DWORD dwTotalSize = 0;
                        ULONG ulValues;

                        ulValues = ldap_count_values(ppValue);

                        for (ULONG k = 0; k < ulValues; k++)
                        {
                           if (k == 0)
                           {
                              dwTotalSize += BufferWrite(pBuffer, ppValue[k]);
                           }
                           else
                           {
                              dwTotalSize += BufferWriteSemicolon(pBuffer);
                              dwTotalSize += BufferWrite(pBuffer, ppValue[k]);
                           }
                        }

                        pRequest->pdwStringMaxLength[j] = __max(pRequest->pdwStringMaxLength[j], dwTotalSize);
                     }
                     else if (bHasRange == TRUE)
                     {
                        //
                        // Error: attribute is present but with no value. This may be a value with range.
                        //
                        DWORD dwTotalSize = 0;
                        DWORD dwRangeEnd;
                        LPWSTR szRangeAttrName;

                        bResult = pParseRange(pLdapHandle, pEntry, pAttribute, &szRangeAttrName, &dwRangeEnd);

                        if ((bResult == TRUE) && (szRangeAttrName != NULL))
                        {
                           LPWSTR szDnEntry;                   // We can't reuse szDn which was modified
                           LPWSTR *ppValueRange = NULL;

                           szDnEntry = ldap_get_dn(pLdapHandle, pEntry);

                           Log(
                              __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
                              "[.] '%S' has attribute '%S' with range.",
                              szDnEntry, szRangeAttrName
                              );

                           //
                           // This is an attribute with range. Write current request.
                           //
                           ppValueRange = ldap_get_values(pLdapHandle, pEntry, szRangeAttrName);
                           if (ppValueRange != NULL)
                           {
                              ULONG ulValues;

                              ulValues = ldap_count_values(ppValueRange);

                              for (ULONG k = 0; k < ulValues; k++)
                              {
                                 if (k == 0)
                                 {
                                    dwTotalSize += BufferWrite(pBuffer, ppValueRange[k]);
                                 }
                                 else
                                 {
                                    dwTotalSize += BufferWriteSemicolon(pBuffer);
                                    dwTotalSize += BufferWrite(pBuffer, ppValueRange[k]);
                                 }
                              }

                              ldap_value_free(ppValueRange);
                           }

                           //
                           // Ask remaining parts
                           //
                           do
                           {
                              ULONG ulValues;

                              dwRangeEnd++;
                              ppValueRange = pGetRangedAttribute(pLdapHandle, szDnEntry, pAttribute, &dwRangeEnd);

                              if (ppValueRange != NULL)
                              {
                                 ulValues = ldap_count_values(ppValueRange);

                                 for (ULONG k = 0; k < ulValues; k++)
                                 {
                                    dwTotalSize += BufferWriteSemicolon(pBuffer);
                                    dwTotalSize += BufferWrite(pBuffer, ppValueRange[k]);
                                 }

                                 ldap_value_free(ppValueRange);
                              }
                              else
                                 break;

                              if (dwRangeEnd == 0)             // This was the final part of the range
                                 break;
                           } while (TRUE);

                           ldap_memfree(szDnEntry);
                        }

                        pRequest->pdwStringMaxLength[j] = __max(pRequest->pdwStringMaxLength[j], dwTotalSize);
                     }
                     else
                     {
                        // We exclude 'msDS-RevealedList' and 'msDS-RevealedDSAs' attributes which can be
                        // returned even null
                        if (wcscmp(pAttribute, L"msDS-RevealedList") != 0 && wcscmp(pAttribute, L"msDS-RevealedDSAs") != 0)
                        {
                           Log(
                              __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
                              "[x] %sldap_get_values(%S, %S) has no value but is not with range.%s",
                              COLOR_YELLOW, szDn, pAttribute, COLOR_RESET
                           );
                        }
                     }
                  }
               }
               break;

               case TYPE_SID:
               {
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval != NULL)
                  {
                     DWORD dwTotalSize = 0;
                     ULONG ulValues;

                     ulValues = ldap_count_values_len(ppval);

                     for (ULONG k = 0; k < ulValues; k++)
                     {
                        LPWSTR szSid;

                        if (k != 0)
                           dwTotalSize += BufferWriteSemicolon(pBuffer);

                        bResult = ConvertSidToStringSid(ppval[k]->bv_val, &szSid);
                        if (bResult == TRUE)
                        {
                           dwTotalSize += BufferWrite(pBuffer, szSid);
                           LocalFree(szSid);
                        }
                        else
                        {
                           Log(
                              __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                              "[!] %sUnable to convert SID.%s",
                              COLOR_RED, COLOR_RESET
                           );
                        }
                     }
                     pRequest->pdwStringMaxLength[j] = __max(pRequest->pdwStringMaxLength[j], dwTotalSize);
                  }
               }
               break;

               case TYPE_SD:
               {
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval)
                  {
                     DWORD dwSize;

                     dwSize = BufferWriteHex(pBuffer, (PBYTE)ppval[0]->bv_val, ppval[0]->bv_len);
                     pRequest->pdwStringMaxLength[j] = __max(pRequest->pdwStringMaxLength[j], dwSize);
                  }
               }
               break;

               case TYPE_DACL:
               {
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval)
                  {
                     LPWSTR szSddl;

                     //
                     // DACL_SECURITY_INFORMATION
                     //
                     bResult = ConvertSecurityDescriptorToStringSecurityDescriptor(
                        ppval[0]->bv_val,
                        SDDL_REVISION_1,
                        DACL_SECURITY_INFORMATION,
                        &szSddl,
                        NULL
                     );

                     if (bResult == TRUE)
                     {
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szSddl), pRequest->pdwStringMaxLength[j]);
                        LocalFree(szSddl);
                     }
                     else
                     {
                        Log(
                           __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                           "[!] %sUnable to convert SDDL.%s",
                           COLOR_RED, COLOR_RESET
                        );
                     }
                  }
               }
               break;

               case TYPE_GUID:
               {
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval)
                  {
                     LPWSTR szGuid = NULL;

                     (void)UuidToString((UUID*)ppval[0]->bv_val, (RPC_WSTR*)&szGuid);

                     if (szGuid != NULL)
                     {
                        BufferWrite(pBuffer, szGuid);;

                        if ((bIsTop == TRUE) && (bIsRoot == TRUE))
                        {
                           if (_wcsicmp(pAttribute, L"objectGUID") == 0)
                           {
                              MetadataWriteFile(pGlobalConfig, L"forest|rootguid", szGuid);
                           }
                        }

                        RpcStringFree((RPC_WSTR*)&szGuid);
                     }
                  }
               }
               break;

               case TYPE_DATE:
               {
                  ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

                  if (ppValue != NULL)
                  {
                     WCHAR szDate[20];

                     szDate[0] = ppValue[0][0];
                     szDate[1] = ppValue[0][1];
                     szDate[2] = ppValue[0][2];
                     szDate[3] = ppValue[0][3];
                     szDate[4] = 0x2d;                // L"-";
                     szDate[5] = ppValue[0][4];
                     szDate[6] = ppValue[0][5];
                     szDate[7] = 0x2d;                // L"-";
                     szDate[8] = ppValue[0][6];
                     szDate[9] = ppValue[0][7];
                     szDate[10] = 0x20;                // L" ";
                     szDate[11] = ppValue[0][8];
                     szDate[12] = ppValue[0][9];
                     szDate[13] = 0x3a;                // L":";
                     szDate[14] = ppValue[0][10];
                     szDate[15] = ppValue[0][11];
                     szDate[16] = 0x3a;                // L":";
                     szDate[17] = ppValue[0][12];
                     szDate[18] = ppValue[0][13];
                     szDate[19] = 0;

                     BufferWrite(pBuffer, szDate);
                  }
               }
               break;

               case TYPE_DATEINT64:
               {
                  ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

                  if (ppValue != NULL)
                  {
                     LONG64 llTimeStamp;

                     swscanf_s(ppValue[0], L"%lli", &llTimeStamp);
                     if (llTimeStamp == 0x7fffffffffffffff)
                     {
                        BufferWrite(pBuffer, (LPWSTR)L"2999-12-12 23:59:59");
                     }
                     else if (llTimeStamp != 0)
                     {
                        SYSTEMTIME st;
                        WCHAR szDate[DATE_MAX_STR_SIZE];

                        FileTimeToSystemTime((FILETIME *)&llTimeStamp, &st);
                        if (st.wYear > 9999)
                           st.wYear = 9999;
                        swprintf_s(
                           szDate, DATE_MAX_STR_SIZE,
                           DATE_FORMAT,
                           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
                        );
                        BufferWrite(pBuffer, szDate);
                     }
                  }
               }
               break;

               case TYPE_BOOL:
               {
                  ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

                  if (ppValue != NULL)
                  {
                     if (_wcsicmp(ppValue[0], L"TRUE") == 0)
                        BufferWrite(pBuffer, (LPWSTR)L"1");
                     else if (_wcsicmp(ppValue[0], L"FALSE") == 0)
                        BufferWrite(pBuffer, (LPWSTR)L"0");
                     else
                        Log(
                           __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                           "[!] %sUnknwon boolean value%s ('%S').",
                           COLOR_RED, COLOR_RESET, ppValue[0]
                        );
                  }
               }
               break;

               case TYPE_BIN:
               {
                  // TODO: Range
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval != NULL)
                  {
                     DWORD dwTotalSize = 0;
                     ULONG ulValues;

                     ulValues = ldap_count_values_len(ppval);

                     for (ULONG k = 0; k < ulValues; k++)
                     {
                        if (k != 0)
                           dwTotalSize += BufferWriteSemicolon(pBuffer);

                        if ((*pAttributes[j]).fFilter != NULL)
                        {
                           LPWSTR szText;

                           szText = ApplyFilter(&(*pAttributes[j]), (PBYTE)ppval[k]->bv_val);
                           dwTotalSize += BufferWrite(pBuffer, szText);
                           _SafeHeapRelease(szText);
                        }
                        else
                        {
                           dwTotalSize += BufferWriteHex(pBuffer, (PBYTE)ppval[k]->bv_val, ppval[k]->bv_len);
                        }
                     }
                     pRequest->pdwStringMaxLength[j] = __max(pRequest->pdwStringMaxLength[j], dwTotalSize);
                  }
               }
               break;
               }

               if ((j + 1) < dwAttributesCount)
                  BufferWriteTab(pBuffer);

               if (ppValue != NULL)
               {
                  ldap_value_free(ppValue);
               }
               if (ppval != NULL)
               {
                  ldap_value_free_len(ppval);
               }
            }

            BufferWriteLine(pBuffer);
            dwObjectCount++;
            ldap_memfree(szDn);
         }

         // RootDSA has always 1 entry
         if (bIsRootDSE == TRUE)
            goto End;

         ulResult = ldap_parse_result(
            pLdapHandle,
            pLdapMessage,
            &ulReturnCode,
            NULL,
            NULL,
            NULL,
            &currControls,
            FALSE
         );
         if (ulResult != LDAP_SUCCESS)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sError in ldap_parse_result()%s (error %u: %s).",
               COLOR_RED, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
            );
            return FALSE;
            //goto End;
         }

         ulResult = ldap_parse_page_control(pLdapHandle, currControls, NULL, (berval * *)& pLdapNewCookie);
         if (ulResult != LDAP_SUCCESS)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sError in ldap_parse_page_control()%s (error %u: %s).",
               COLOR_RED, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
            );
            return FALSE;
            //goto End;
         }

         if ((pLdapNewCookie->bv_len == 0) || (pLdapNewCookie->bv_val == 0))
            goto End;

         controlArray[0] = NULL;

         ulResult = ldap_create_page_control(
            pLdapHandle,
            900,
            pLdapNewCookie,
            TRUE,
            &controlArray[0]
         );
         if (ulResult != LDAP_SUCCESS)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sError in ldap_create_page_control()%s (error %u: %s).",
               COLOR_RED, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
            );
            return FALSE;
            //goto End;
         }

         ldap_msgfree(pLdapMessage);

         //
         // Wait if requested by config
         //
         if (g_GlobalConfig.dwSleepTime > 0)
            Sleep(g_GlobalConfig.dwSleepTime);

         goto Loop;

      End:
         ber_bvfree(pLdapNewCookie);

         // Free all HeapAlloc'ed controls (1..dwControlCount+1)
         for (DWORD dwControlIt = 0; dwControlIt < pRequest->dwControlsCount; ++dwControlIt)
         {
            _SafeHeapRelease(controlArray[dwControlIt + 1]);
         }
         _SafeHeapRelease(controlArray);

         ulResult = ldap_control_free(pLdapControl);
         ulResult = ldap_msgfree(pLdapMessage);
         ulResult = ldap_unbind(pLdapHandle);

         if (pGlobalConfig->bDisplayProgress == TRUE)
            fwprintf(stdout, L".\n");
      }

      BufferClose(&Buffer);

      _SafeHeapRelease(pszAttributes);

      ullEndTime = GetTickCount64();
      ullEndTime = (ullEndTime - ullStartTime) / 1000;

      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "   [+] %sFinished%s: elapsed time: %llu second%s, %u object%s.",
         COLOR_GREEN, COLOR_RESET,
         ullEndTime,
         ullEndTime > 1 ? "s" : "",
         dwObjectCount,
         dwObjectCount > 1 ? "s" : ""
      );
   }

   if (bWriteTableInfo == TRUE)
   {
      pWriteTableInfo(pGlobalConfig, pRequest, bIsTop, bIsRootDSE, szRelativePath, szTableName, szTableNameNoDomain, dwAttributesCount, pAttributes);
   }

   _SafeHeapRelease(pAttributes);

   return TRUE;
}

//
// Private functions
//
LDAP*
pLdapOpenConnection (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ DWORD dwServerEntry,
   _In_z_ LPWSTR szServerName,
   _In_ ULONG ulLdapPort
)
{
   ULONG ulResult;
   ULONG ulVersion = LDAP_VERSION3;
   void *pvValue = NULL;

   LDAP* pLdapHandle = NULL;

   pLdapHandle = ldap_open(szServerName, (ulLdapPort == 0) ? LDAP_PORT : ulLdapPort);
   if (pLdapHandle == NULL)
   {
      ulResult = LdapGetLastError();
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to open LDAP connection%s to '%S' (error %u: %s).",
         COLOR_RED, COLOR_RESET, szServerName,  ulResult, ldap_err2stringA(ulResult)
      );
      return NULL;
   }

   ulResult = ldap_connect(pLdapHandle, NULL);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to connect to LDAP server%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
      );
      ldap_unbind(pLdapHandle);
      return NULL;
   }

   ulResult = ldap_set_option(pLdapHandle, LDAP_OPT_PROTOCOL_VERSION, (void*)&ulVersion);
   pvValue = LDAP_OPT_OFF;
   ulResult = ldap_set_option(pLdapHandle, LDAP_OPT_REFERRALS, &pvValue);

   if ((dwServerEntry == USE_GLOBAL_CREDENTIALS) || (pGlobalConfig->DomainConfig[dwServerEntry].szUsername == NULL))
   {
      if (pGlobalConfig->szUsername == NULL)
      {
         ulResult = ldap_bind_s(pLdapHandle, NULL, NULL, LDAP_AUTH_NEGOTIATE);

         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERYVERBOSE,
            "[.] LDAP bind with implicit credentials (global credentials)."
         );
      }
      else
      {
         SEC_WINNT_AUTH_IDENTITY Auth = { 0 };

         Auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
         Auth.User = (USHORT*)pGlobalConfig->szUsername;
         Auth.Domain = (USHORT*)pGlobalConfig->szUserDomain;
         Auth.Password = (USHORT*)pGlobalConfig->szUserPassword;
         (void)SIZETToULong(wcslen(pGlobalConfig->szUsername), &(Auth.UserLength));
         (void)SIZETToULong(wcslen(pGlobalConfig->szUserDomain), &(Auth.DomainLength));
         (void)SIZETToULong(wcslen(pGlobalConfig->szUserPassword), &(Auth.PasswordLength));

         ulResult = ldap_bind_s(pLdapHandle, NULL, (PWCHAR)&Auth, LDAP_AUTH_NEGOTIATE);

         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERYVERBOSE,
            "[.] LDAP bind with explicit credentials (global credentials, username='%S').",
            pGlobalConfig->szUsername
         );
      }
   }
   else
   {
      if (wcslen(pGlobalConfig->DomainConfig[dwServerEntry].szUsername) == 0)
      {
         ulResult = ldap_bind_s(pLdapHandle, NULL, NULL, LDAP_AUTH_NEGOTIATE);

         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERYVERBOSE,
            "[.] LDAP bind with implicit credentials (domain %u).", dwServerEntry
         );
      }
      else
      {
         SEC_WINNT_AUTH_IDENTITY Auth = { 0 };

         Auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
         Auth.User = (USHORT*)pGlobalConfig->DomainConfig[dwServerEntry].szUsername;
         Auth.Domain = (USHORT*)pGlobalConfig->DomainConfig[dwServerEntry].szUserDomain;
         Auth.Password = (USHORT*)pGlobalConfig->DomainConfig[dwServerEntry].szUserPassword;
         (void)SIZETToULong(wcslen(pGlobalConfig->DomainConfig[dwServerEntry].szUsername), &(Auth.UserLength));
         (void)SIZETToULong(wcslen(pGlobalConfig->DomainConfig[dwServerEntry].szUserDomain), &(Auth.DomainLength));
         (void)SIZETToULong(wcslen(pGlobalConfig->DomainConfig[dwServerEntry].szUserPassword), &(Auth.PasswordLength));

         ulResult = ldap_bind_s(pLdapHandle, NULL, (PWCHAR)&Auth, LDAP_AUTH_NEGOTIATE);

         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERYVERBOSE,
            "[.] LDAP bind with explicit credentials (domain %u, username='%S').",
            dwServerEntry, pGlobalConfig->DomainConfig[dwServerEntry].szUsername
         );
      }
   }

   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sUnable to bind to LDAP server%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
      );
      ldap_unbind(pLdapHandle);
      return NULL;
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[+] %sSuccessfully bind to %S%s.", COLOR_GREEN, szServerName, COLOR_RESET
   );

   return pLdapHandle;
}

BOOL
pWriteTableInfo (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ PREQUEST_CONFIG pRequest,
   _In_ BOOL bIsTop,
   _In_ BOOL bIsRootDSE,
   _In_z_ LPWSTR szRelativePath,
   _In_z_ LPWSTR szTableName,
   _In_z_ LPWSTR szTableNameNoDomain,
   _In_ DWORD dwAttributesCount,
   _In_ PATTRIBUTE_CONFIG *pAttributes
)
{
   DWORD dwColumsCount;

   //
   // Count columns
   //
   if (bIsTop == TRUE)
      dwColumsCount = dwAttributesCount + 3;       // dn/server + shortname + shortdn
   else
      dwColumsCount = dwAttributesCount + 1;       // dn/server

   for (DWORD i = 0; i < dwAttributesCount; i++)
   {
      if ((((*pAttributes[i]).Type == TYPE_INT) || ((*pAttributes[i]).Type == TYPE_INT64)) && ((*pAttributes[i]).fFilter != NULL))
      {
         dwColumsCount++;                       // text + int
      }
   }

   //
   // Write columns infos
   //
   // Relative path
   WriteTextFile(&pGlobalConfig->TableFile, "%S\t", szRelativePath);

   // Table names
   WriteTextFile(&pGlobalConfig->TableFile, "%S\t", szTableName);
   WriteTextFile(&pGlobalConfig->TableFile, "%S\t", szTableNameNoDomain);

   WriteTextFile(&pGlobalConfig->TableFile, "%u\t", dwColumsCount);

   // Columns
   if (bIsRootDSE == TRUE)
   {
      // For RootDSE, dwStringMaxLengthShortName is used for 'server' max size
      WriteTextFile(&pGlobalConfig->TableFile, "server\tnvarchar(%u)", (pRequest->dwStringMaxLengthShortName / 2) + 1);
   }
   else
   {
      WriteTextFile(&pGlobalConfig->TableFile, "dn\tnvarchar(%u)", (pRequest->dwStringMaxLengthDn / 2) + 1);
   }

   if (bIsTop == TRUE)
   {
      // +1 to be sure to round to upper value (even) and avoid nvarchar(0)
      WriteTextFile(&pGlobalConfig->TableFile, "\tshortname\tnvarchar(%u)", (pRequest->dwStringMaxLengthShortName / 2) + 1);
      WriteTextFile(&pGlobalConfig->TableFile, "\tshortdn\tnvarchar(%u)", (pRequest->dwStringMaxLengthShortDn / 2) + 1);
   }

   //
   // Other columns
   //
   for (DWORD i = 0; i < dwAttributesCount; i++)
   {
      DWORD dwStringMaxLength;

      // +1 to be sure to round to upper value (even) and avoid nvarchar(0)
      dwStringMaxLength = (pRequest->pdwStringMaxLength[i] / 2) + 1;

      if ((*pAttributes[i]).Type == TYPE_INT)
      {
         if ((*pAttributes[i]).fFilter == NULL)
         {
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tint", (*pAttributes[i]).szName);
         }
         else
         {
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tnvarchar(%u)", (*pAttributes[i]).szName, dwStringMaxLength);
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S_int\tint", (*pAttributes[i]).szName);
         }
      }
      else if ((*pAttributes[i]).Type == TYPE_INT64)
      {
         if ((*pAttributes[i]).fFilter == NULL)
         {
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tbigint", (*pAttributes[i]).szName);
         }
         else
         {
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tnvarchar(%u)", (*pAttributes[i]).szName, dwStringMaxLength);
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S_int\tbigint", (*pAttributes[i]).szName);
         }
      }
      else
      {
         switch ((*pAttributes[i]).Type)
         {
         case TYPE_STR:
         case TYPE_STRS:
         {
            // nvarchar(n) n must be from 1 through 4000
            if (dwStringMaxLength < 4000)
               WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tnvarchar(%u)", (*pAttributes[i]).szName, dwStringMaxLength);
            else
            {
               WCHAR szMetadataKey[MAX_METADATA_KEY];

               WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tnvarchar(max)", (*pAttributes[i]).szName);

               swprintf_s(szMetadataKey, MAX_METADATA_KEY, L"size|%s|%s", szTableNameNoDomain, (*pAttributes[i]).szName);
               DbAddKey(&pGlobalConfig->pBaseSize, szMetadataKey, dwStringMaxLength, DbCompareMode::Max);
            }
            break;
         }

         case TYPE_SID:
         case TYPE_SD:
         case TYPE_DACL:
         case TYPE_BIN:
         {
            // varchar(n) n must be from 1 through 8000
            if (dwStringMaxLength < 8000)
               WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tvarchar(%u)", (*pAttributes[i]).szName, dwStringMaxLength);
            else
            {
               WCHAR szMetadataKey[MAX_METADATA_KEY];

               WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tvarchar(max)", (*pAttributes[i]).szName);

               swprintf_s(szMetadataKey, MAX_METADATA_KEY, L"size|%s|%s", szTableNameNoDomain, (*pAttributes[i]).szName);
               DbAddKey(&pGlobalConfig->pBaseSize, szMetadataKey, dwStringMaxLength, DbCompareMode::Max);
            }
            break;
         }

         case TYPE_GUID:
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tuniqueidentifier", (*pAttributes[i]).szName);
            break;

         case TYPE_DATE:
         case TYPE_DATEINT64:
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\tdatetime2", (*pAttributes[i]).szName);
            break;

         case TYPE_BOOL:
            WriteTextFile(&pGlobalConfig->TableFile, "\t%S\ttinyint", (*pAttributes[i]).szName);
            break;

         default:
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sData type unknown%s.",
               COLOR_RED, COLOR_RESET
            );
            return FALSE;
         }
         }
      }
   }
   WriteTextFile(&pGlobalConfig->TableFile, "\n");

   return TRUE;
}

BOOL
pHasAttributeWithRange (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPWSTR szDn
)
{
   BOOL bReturn = FALSE;
   LPWSTR szAttrName;
   BerElement *berElt = NULL;

   // Search for attributes with range
   szAttrName = ldap_first_attribute(pLdapHandle, pEntry, &berElt);
   while (szAttrName != NULL)
   {
      if (wcsstr(szAttrName, L";range=") != 0)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
            "[.] '%S' has at least one attribute with range ('%S').",
            szDn, szAttrName
         );
         bReturn = TRUE;
         break;
      }
      szAttrName = ldap_next_attribute(pLdapHandle, pEntry, berElt);
   }

   ber_free(berElt, 0);

   return bReturn;
}

_Success_(return)
BOOL
pParseRange (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPWSTR szAttribute,
   _Out_ LPWSTR *pszAttrName,
   _Out_ PDWORD pdwEnd
)
{
   BOOL bFound = FALSE;
   BerElement *berElt = NULL;
   LPWSTR szAttrName;
   WCHAR szRangeAttrName[MAX_ATTRIBUTE_NAME] = { 0 };
   DWORD dwStart;

   // Search for attributes with range
   szAttrName = ldap_first_attribute(pLdapHandle, pEntry, &berElt);
   while (szAttrName != NULL)
   {
      if (_wcsicmp(szAttrName, L";range=") != 0)
      {
         int r;

         r = swscanf_s(szAttrName, L"%[a-zA-z0-9_-];range=%u-%u", szRangeAttrName, MAX_ATTRIBUTE_NAME - 1, &dwStart, pdwEnd);

         if (r == 3)
         {
            if (_wcsicmp(szAttribute, szRangeAttrName) == 0)
            {
               // This is our attribute with range
               *pszAttrName = szAttrName;
               bFound = TRUE;
               break;
            }
         }
      }
      szAttrName = ldap_next_attribute(pLdapHandle, pEntry, berElt);
   }

   ber_free(berElt, 0);

   return bFound;
}

LPWSTR*
pGetRangedAttribute (
   _In_ LDAP* pLdapHandle,
   _In_ LPWSTR szDn,
   _In_ LPWSTR szAttribute,
   _In_ PDWORD pdwRangeStart
)
{
   BOOL bResult;
   ULONG ulResult;

   LDAPMessage *pLdapMessage = NULL;
   LDAPMessage *pEntry = NULL;

   LPWSTR ptRangeAttributes[2] = { NULL };
   WCHAR szRangeAttrName[MAX_ATTRIBUTE_NAME + 20] = { 0 };        // 20: ';range=%d-*'
   PWCHAR* ppValue = NULL;
   LPWSTR szNewAttributeName = NULL;

   swprintf_s(szRangeAttrName, MAX_ATTRIBUTE_NAME + 20, L"%s;range=%d-*", szAttribute, *pdwRangeStart);

   ptRangeAttributes[0] = szRangeAttrName;

   ulResult = ldap_search_s(
      pLdapHandle,
      szDn,
      LDAP_SCOPE_BASE,
      (PWSTR)L"(objectClass=*)",
      ptRangeAttributes,   // attrs
      0,                   // attrsonly
      &pLdapMessage
   );

   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "[!] %sError in ldap_search_s(%S)%s (error %u: %s).",
         COLOR_RED, szRangeAttrName, COLOR_RESET, ulResult, ldap_err2stringA(ulResult)
      );

      if (ulResult != LDAP_NO_SUCH_OBJECT)
      {
         // LDAP_NO_SUCH_OBJECT is a common error.
         g_GlobalConfig.bProcessHasError = TRUE;
      }

      goto End;
   }

   pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
   if (pEntry == NULL)
      goto End;

   ppValue = ldap_get_values(pLdapHandle, pEntry, szRangeAttrName);
   if (ppValue == NULL)
   {
      bResult = pParseRange(pLdapHandle, pEntry, szAttribute, &szNewAttributeName, pdwRangeStart);
      if ((bResult == TRUE) && (szNewAttributeName != NULL))
      {
         ppValue = ldap_get_values(pLdapHandle, pEntry, szNewAttributeName);
      }
      else
      {
         ldap_value_free(ppValue);
         ppValue = NULL;
      }
   }
   else
   {
      *pdwRangeStart = 0;
   }

End:
   ldap_msgfree(pLdapMessage);

   return ppValue;
}

/*
   BerElement* pBer = NULL;

   pAttribute = ldap_first_attribute(
      pLdapHandle,      // Session handle
      pEntry,           // Current entry
      &pBer);           // [out] Current BerElement

   while (pAttribute != NULL)
   {
      ldap_memfree(pAttribute);

      pAttribute = ldap_next_attribute(
         pLdapHandle,   // Session Handle
         pEntry,            // Current entry
         pBer);             // Current BerElement
         }
   }

   if (pBer != NULL)
   {
      ber_free(pBer, 0);
      pBer = NULL;
   }
*/