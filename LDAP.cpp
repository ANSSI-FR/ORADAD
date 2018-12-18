#include <Windows.h>
#include <Winldap.h>
#include <NtLdap.h>           // For LDAP Extended Controls
#include <Winber.h>
#include <stdio.h>
#include <Winber.h>
#include <sddl.h>
#include "ORADAD.h"

#define MAX_ATTRIBUTE_NAME       64

extern GLOBAL_CONFIG g_GlobalConfig;
extern HANDLE g_hHeap;

//
// Private functions
//
LDAP*
pLdapOpenConnection(
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szServerName
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
   _In_z_ LPWSTR szServerName,
   _Outptr_ PROOTDSE_CONFIG pRootDse
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

   pLdapHandle = pLdapOpenConnection(pGlobalConfig, szServerName);
   if (pLdapHandle == NULL)
      return FALSE;

   ulResult = ldap_search_s(pLdapHandle, NULL, LDAP_SCOPE_BASE, NULL, (PZPWSTR)szAttrsSearch, FALSE, &pLdapMessage);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "Error in ldap_search_s() (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
      );
      return FALSE;
   }

   pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
   pAttribute = ldap_first_attribute(pLdapHandle, pEntry, &pBer);

   pRootDse->bIsLocalAdmin = FALSE;

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

            for (ULONG i = 0; i < ulValues; i++)
            {
               if (wcsstr(ppValue[i], L"DC=ForestDnsZones,") == ppValue[i])
                  DuplicateString(ppValue[i], &pRootDse->forestDnsNamingContext);
               else if(wcsstr(ppValue[i], L"DC=DomainDnsZones,") == ppValue[i])
                  DuplicateString(ppValue[i], &pRootDse->domainDnsNamingContext);
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
   _In_z_ LPWSTR szServer,
   _In_ BOOL bIsLocalAdmin,
   _In_z_ LPWSTR szRootDns,
   _In_opt_z_ LPCWSTR szPath1,
   _In_opt_z_ LPCWSTR szPath2,
   _In_opt_z_ LPWSTR szLdapBase,
   _In_ PREQUEST_CONFIG pRequest,
   _In_ BOOL bRequestLdap,
   _In_ BOOL bWriteTableInfo
)
{
   BOOL bResult;
   WCHAR szFilename[MAX_PATH];
   WCHAR szRelativePath[MAX_PATH];
   WCHAR szTableName[MAX_PATH];
   WCHAR szTableNameNoDomain[MAX_PATH];

   DWORD dwAttributesCount;
   PATTRIBUTE_CONFIG *pAttributes;

   BOOL bIsRootDSE;
   BOOL bIsTop = FALSE;

   ULONG ulResult;
   ULONG ulReturnCode;
   ULONG ulEntriesCount;

   if (szLdapBase == NULL)
   {
      bIsRootDSE = TRUE;
      dwAttributesCount = pGlobalConfig->dwRootDSEAttributesCount;

      // pRootDSEAttributes is array of attributes
      // pAttributes is array of pointers to attributes. Create temporary array.
      pAttributes = (PATTRIBUTE_CONFIG*)_HeapAlloc(dwAttributesCount * sizeof(PATTRIBUTE_CONFIG));
      for (DWORD i = 0; i < dwAttributesCount; i++)
      {
         pAttributes[i] = &(pGlobalConfig->pRootDSEAttributes[i]);
      }
   }
   else
   {
      bIsRootDSE = FALSE;
      dwAttributesCount = pRequest->dwAttributesCount;
      pAttributes = pRequest->pAttributes;
   }

   if (_wcsicmp(pRequest->szName, L"top") == 0)
      bIsTop = TRUE;

   //
   // Initialize names
   //
   if ((szPath1 != NULL) && (szPath2 != NULL))
   {
      swprintf_s(
         szFilename, MAX_PATH,
         L"%s\\%s\\%s\\%s\\%s\\%s.tsv",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         szPath1,
         szPath2,
         pRequest->szName
      );

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
         szFilename, MAX_PATH,
         L"%s\\%s\\%s\\%s\\%s.tsv",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         szPath1,
         pRequest->szName
      );

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
   else if ((szPath1 == NULL) && (szPath2 == NULL))
   {
      swprintf_s(
         szFilename, MAX_PATH,
         L"%s\\%s\\%s\\%s.tsv",
         pGlobalConfig->szOutDirectory,
         szRootDns,
         pGlobalConfig->szSystemTime,
         pRequest->szName
      );

      swprintf_s(
         szRelativePath, MAX_PATH,
         L"%s.tsv",
         pRequest->szName
      );

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
   else
   {
      return FALSE;
   }

   if (bRequestLdap == TRUE)
   {
      BUFFER_DATA Buffer;
      PBUFFER_DATA pBuffer;

      LDAP* pLdapHandle;
      LDAPMessage *pLdapMessage = NULL;

      LPWSTR *pszAttributes;

      PLDAPControl pLdapControl = NULL;
      PLDAPControl controlArray[3] = { 0 };     // 0: paging, 1:LDAP_SERVER_SD_FLAGS_OID, 2: NULL

      LDAPMessage* pEntry = NULL;

      LDAP_BERVAL LdapCookie = { 0, NULL };
      PLDAP_BERVAL pLdapNewCookie = NULL;
      PLDAPControl *currControls = NULL;

      berval *pBerVal = NULL;

      DWORD dwStartTime, dwEndTime;

      dwStartTime = GetTickCount();

      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
         "Start dump '%S/%S/%S/%S'.", szRootDns, szPath1, szPath2, pRequest->szName
      );

      //
      // Create output buffer
      //
      bResult = BufferInitialize(&Buffer, szFilename);
      if (bResult == FALSE)
      {
         return FALSE;
      }

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

      //
      // Process
      //
      pLdapHandle = pLdapOpenConnection(pGlobalConfig, szServer);
      if (pLdapHandle == NULL)
         return FALSE;

      ulResult = ldap_create_page_control(
         pLdapHandle,
         900,
         &LdapCookie,
         TRUE,
         &pLdapControl
      );

      controlArray[0] = pLdapControl;

      if (bIsTop == TRUE)
      {
         // For 'top' requests, we ask for Security Descriptor (nTSecurityDescriptor). By default, all parts are requested, including SACL.
         // We request SACL only if we are local administrator. Overwise, nothing is return.
         LDAPControl LdapControlSdFlag;
         BerElement *pBerElmt = NULL;

         pBerElmt = ber_alloc_t(LBER_USE_DER);
         if (bIsLocalAdmin == TRUE)
            ber_printf(pBerElmt, (PSTR)"{i}", (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION));
         else
            ber_printf(pBerElmt, (PSTR)"{i}", (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION));
         ber_flatten(pBerElmt, &pBerVal);

         LdapControlSdFlag.ldctl_iscritical = TRUE;
         LdapControlSdFlag.ldctl_oid = (LPWSTR)LDAP_SERVER_SD_FLAGS_OID_W;
         LdapControlSdFlag.ldctl_value.bv_val = pBerVal->bv_val;
         LdapControlSdFlag.ldctl_value.bv_len = pBerVal->bv_len;

         controlArray[1] = &LdapControlSdFlag;

         ber_free(pBerElmt, 1);
      }

      //
      // Format pszAttributes list
      // Note: dn can't be requested in attribute list. We get it by ldap_get_dn().
      //
      pszAttributes = (LPWSTR*)_HeapAlloc((dwAttributesCount + 1) * sizeof(LPWSTR));   // +1 for NULL (list terminator)
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
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "Error in ldap_search_ext_s() (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
         );
         goto End;
      }

      ulEntriesCount = ldap_count_entries(
         pLdapHandle,
         pLdapMessage
      );

      for (ULONG i = 0; i < ulEntriesCount; i++)
      {
         LPWSTR szDn;
         BOOL bHasRange;

         if (i == 0)
            pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
         else
            pEntry = ldap_next_entry(pLdapHandle, pEntry);

         szDn = ldap_get_dn(pLdapHandle, pEntry);

         if (bIsRootDSE == TRUE)
         {
            // For RootDSE, dwStrintMaxLengthShortName is used for 'server' max size
            _CallWriteAndGetMax(BufferWrite(pBuffer, szServer), pRequest->dwStrintMaxLengthShortName);
            BufferWriteTab(pBuffer);
         }
         else
         {
            LPWSTR *ppValue = NULL;

            //
            // For all files, 'dn' is first column
            //
            if (szDn != NULL)
            {
               _CallWriteAndGetMax(BufferWrite(pBuffer, szDn), pRequest->dwStrintMaxLengthDn);
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
            _CallWriteAndGetMax(BufferWrite(pBuffer, szShortName), pRequest->dwStrintMaxLengthShortName);
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
                  _CallWriteAndGetMax(BufferWrite(pBuffer, szDn), pRequest->dwStrintMaxLengthShortDn);
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
            LPWSTR *ppValue = NULL;
            berval **ppval = NULL;

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
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szText), pRequest->pdwStrintMaxLength[j]);
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
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szText), pRequest->pdwStrintMaxLength[j]);
                        _SafeHeapRelease(szText);

                        BufferWriteTab(pBuffer);
                        BufferWrite(pBuffer, ppValue[0]);
                     }
                     else
                     {
                        // STR
                        _CallWriteAndGetMax(BufferWrite(pBuffer, ppValue[0]), pRequest->pdwStrintMaxLength[j]);
                     }
                  }
                  else if ((((*pAttributes[j]).Type == TYPE_INT) || ((*pAttributes[j]).Type == TYPE_INT64)) && ((*pAttributes[j]).fFilter != NULL))
                  {
                     _CallWriteAndGetMax(BufferWriteTab(pBuffer), pRequest->pdwStrintMaxLength[j]);
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

                        pRequest->pdwStrintMaxLength[j] = __max(pRequest->pdwStrintMaxLength[j], dwTotalSize);
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
                           LPWSTR *ppValueRange = NULL;

                           Log(
                              __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
                              "'%S' has attribute '%S' with range.",
                              szDn, szRangeAttrName
                              );

                           //
                           // This is an attribute with range. Write current request.
                           //
                           ppValueRange = ldap_get_values(pLdapHandle, pEntry, szRangeAttrName);
                           if (ppValueRange != NULL)
                           {
                              DWORD dwTotalSize = 0;
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
                              LPWSTR *ppValueRange = NULL;
                              ULONG ulValues;

                              dwRangeEnd++;
                              ppValueRange = pGetRangedAttribute(pLdapHandle, szDn, pAttribute, &dwRangeEnd);

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
                        }

                        pRequest->pdwStrintMaxLength[j] = __max(pRequest->pdwStrintMaxLength[j], dwTotalSize);
                     }
                     else
                     {
                        Log(
                           __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_WARNING,
                           "ldap_get_values(%S, %s) has no value but is not with range.", szDn, pAttribute
                        );
                     }
                  }
               }
               break;

               case TYPE_SID:
               {
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval)
                  {
                     BOOL bResult;
                     LPWSTR szSid;

                     bResult = ConvertSidToStringSid(ppval[0]->bv_val, &szSid);
                     if (bResult == TRUE)
                     {
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szSid), pRequest->pdwStrintMaxLength[j]);
                        LocalFree(szSid);
                     }
                     else
                     {
                        Log(
                           __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                           "Unable to convert SID."
                        );
                     }
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
                     pRequest->pdwStrintMaxLength[j] = __max(pRequest->pdwStrintMaxLength[j], dwSize);
                  }
               }
               break;

               case TYPE_DACL:
               {
                  ppval = ldap_get_values_len(pLdapHandle, pEntry, pAttribute);

                  if (ppval)
                  {
                     BOOL bResult;
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
                        _CallWriteAndGetMax(BufferWrite(pBuffer, szSddl), pRequest->pdwStrintMaxLength[j]);
                        LocalFree(szSddl);
                     }
                     else
                     {
                        Log(
                           __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                           "Unable to convert SDDL."
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

                     UuidToString((UUID*)ppval[0]->bv_val, (RPC_WSTR*)&szGuid);

                     if (szGuid != NULL)
                     {
                        BufferWrite(pBuffer, szGuid);;
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
                        WCHAR szDate[20];

                        FileTimeToSystemTime((FILETIME *)&llTimeStamp, &st);
                        swprintf_s(
                           szDate, 20,
                           L"%04u-%02u-%02u %02u:%02u:%02u",
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
                           "Unknwon boolean value ('%S').", ppValue[0]
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
                     pRequest->pdwStrintMaxLength[j] = __max(pRequest->pdwStrintMaxLength[j], dwTotalSize);
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
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "Error in ldap_parse_result() (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
         );
         goto End;
      }

      ulResult = ldap_parse_page_control(pLdapHandle, currControls, NULL, (berval**)&pLdapNewCookie);
      if (ulResult != LDAP_SUCCESS)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "Error in ldap_parse_page_control() (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
         );
         goto End;
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
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
            "Error in ldap_create_page_control() (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
         );
         goto End;
      }

      ldap_msgfree(pLdapMessage);

      //
      // Wait if requested by config
      //
      if (g_GlobalConfig.dwSleepTime > 0)
         Sleep(g_GlobalConfig.dwSleepTime);

      goto Loop;

   End:
      if (bIsTop == TRUE)
         ber_bvfree(pBerVal);

      ber_bvfree(pLdapNewCookie);

      ulResult = ldap_control_free(pLdapControl);
      ulResult = ldap_msgfree(pLdapMessage);
      ulResult = ldap_unbind(pLdapHandle);

      BufferClose(&Buffer);

      dwEndTime = GetTickCount();

      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "Dump '%S/%S/%S/%S' finished (elapsed time: %u seconds).",
         szRootDns, szPath1, szPath2, pRequest->szName,
         (dwEndTime - dwStartTime) / 1000
      );
   }

   if (bWriteTableInfo == TRUE)
   {
      pWriteTableInfo(pGlobalConfig, pRequest, bIsTop, bIsRootDSE, szRelativePath, szTableName, szTableNameNoDomain, dwAttributesCount, pAttributes);
   }

   if (bIsRootDSE == TRUE)
      _SafeHeapRelease(pAttributes);

   return TRUE;
}

//
// Private functions
//
LDAP*
pLdapOpenConnection (
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_z_ LPWSTR szServerName
)
{
   ULONG ulResult;
   ULONG ulVersion = LDAP_VERSION3;
   void *pvValue = NULL;

   LDAP* pLdapHandle = NULL;

   if (pGlobalConfig->ulLdapPort == 0)
      pGlobalConfig->ulLdapPort = LDAP_PORT;

   pLdapHandle = ldap_open(szServerName, (pGlobalConfig->ulLdapPort == 0) ? LDAP_PORT : pGlobalConfig->ulLdapPort);
   if (pLdapHandle == NULL)
   {
      ulResult = LdapGetLastError();
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "Unable to open LDAP connection to %S (error %u: %s).", szServerName, ulResult, ldap_err2stringA(ulResult)
      );
      return NULL;
   }

   ulResult = ldap_connect(pLdapHandle, NULL);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "Unable to connect to LDAP server (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
      );
      ldap_unbind(pLdapHandle);
      return NULL;
   }

   ulResult = ldap_set_option(pLdapHandle, LDAP_OPT_PROTOCOL_VERSION, (void*)&ulVersion);
   pvValue = LDAP_OPT_OFF;
   ulResult = ldap_set_option(pLdapHandle, LDAP_OPT_REFERRALS, &pvValue);

   if (pGlobalConfig->szUsername == NULL)
   {
      ulResult = ldap_bind_s(pLdapHandle, NULL, NULL, LDAP_AUTH_NEGOTIATE);
   }
   else
   {
      SEC_WINNT_AUTH_IDENTITY Auth = { 0 };

      Auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
      Auth.User = (USHORT*)pGlobalConfig->szUsername;
      Auth.Domain = (USHORT*)pGlobalConfig->szUserDomain;
      Auth.Password = (USHORT*)pGlobalConfig->szUserPassword;
      Auth.UserLength = wcslen(pGlobalConfig->szUsername);
      Auth.DomainLength = wcslen(pGlobalConfig->szUserDomain);
      Auth.PasswordLength = wcslen(pGlobalConfig->szUserPassword);

      ulResult = ldap_bind_s(pLdapHandle, NULL, (PWCHAR)&Auth, LDAP_AUTH_NEGOTIATE);
   }

   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "Unable to bind to LDAP server (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
      );
      ldap_unbind(pLdapHandle);
      return NULL;
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "Successfully bind to %S.", szServerName
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

   // Results of RootDSE are merged in the same file.
   // Be sure to write table info only once
   if ((bIsRootDSE == TRUE) && (pRequest->bTableInfoWritten == TRUE))
      return TRUE;
   else
      pRequest->bTableInfoWritten = TRUE;

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
   WriteTextFile(pGlobalConfig->hTableFile, "%S\t", szRelativePath);

   // Table names
   WriteTextFile(pGlobalConfig->hTableFile, "%S\t", szTableName);
   WriteTextFile(pGlobalConfig->hTableFile, "%S\t", szTableNameNoDomain);

   WriteTextFile(pGlobalConfig->hTableFile, "%u\t", dwColumsCount);

   // Columns
   if (bIsRootDSE == TRUE)
   {
      // For RootDSE, dwStrintMaxLengthShortName is used for 'server' max size
      WriteTextFile(pGlobalConfig->hTableFile, "server\tnvarchar(%u)", (pRequest->dwStrintMaxLengthShortName / 2) + 1);
   }
   else
   {
      WriteTextFile(pGlobalConfig->hTableFile, "dn\tnvarchar(%u)", (pRequest->dwStrintMaxLengthDn / 2) + 1);
   }

   if (bIsTop == TRUE)
   {
      // +1 to be sure to round to upper value (even) and avoid nvarchar(0)
      WriteTextFile(pGlobalConfig->hTableFile, "\tshortname\tnvarchar(%u)", (pRequest->dwStrintMaxLengthShortName / 2) + 1);
      WriteTextFile(pGlobalConfig->hTableFile, "\tshortdn\tnvarchar(%u)", (pRequest->dwStrintMaxLengthShortDn / 2) + 1);
   }

   //
   // Other columns
   //
   for (DWORD i = 0; i < dwAttributesCount; i++)
   {
      DWORD dwStrintMaxLength;

      // +1 to be sure to round to upper value (even) and avoid nvarchar(0)
      dwStrintMaxLength = (pRequest->pdwStrintMaxLength[i] / 2) + 1;

      if ((*pAttributes[i]).Type == TYPE_INT)
      {
         if ((*pAttributes[i]).fFilter == NULL)
         {
            WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tint", (*pAttributes[i]).szName);
         }
         else
         {
            WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tnvarchar(%u)", (*pAttributes[i]).szName, dwStrintMaxLength);
            WriteTextFile(pGlobalConfig->hTableFile, "\t%S_int\tint", (*pAttributes[i]).szName);
         }
      }
      else if ((*pAttributes[i]).Type == TYPE_INT64)
      {
         if ((*pAttributes[i]).fFilter == NULL)
         {
            WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tbigint", (*pAttributes[i]).szName);
         }
         else
         {
            WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tnvarchar(%u)", (*pAttributes[i]).szName, dwStrintMaxLength);
            WriteTextFile(pGlobalConfig->hTableFile, "\t%S_int\tbigint", (*pAttributes[i]).szName);
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
               if (dwStrintMaxLength < 4000)
                  WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tnvarchar(%u)", (*pAttributes[i]).szName, dwStrintMaxLength);
               else
                  WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tnvarchar(max)", (*pAttributes[i]).szName);
               break;
            }

            case TYPE_SID:
            case TYPE_SD:
            case TYPE_DACL:
            case TYPE_BIN:
            {
               // varchar(n) n must be from 1 through 8000
               if (dwStrintMaxLength < 8000)
                  WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tvarchar(%u)", (*pAttributes[i]).szName, dwStrintMaxLength);
               else
                  WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tvarchar(max)", (*pAttributes[i]).szName);
               break;
            }

            case TYPE_GUID:
               WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tuniqueidentifier", (*pAttributes[i]).szName);
               break;

            case TYPE_DATE:
            case TYPE_DATEINT64:
               WriteTextFile(pGlobalConfig->hTableFile, "\t%S\tdatetime2", (*pAttributes[i]).szName);
               break;

            case TYPE_BOOL:
               WriteTextFile(pGlobalConfig->hTableFile, "\t%S\ttinyint", (*pAttributes[i]).szName);
               break;

            default:
            {
               Log(
                  __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
                  "Data type unknown."
               );
               return FALSE;
            }
         }
      }
   }
   WriteTextFile(pGlobalConfig->hTableFile, "\n");

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
            "'%S' has attribute '%S' with range.",
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
   WCHAR szRangeAttrName[MAX_ATTRIBUTE_NAME];
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
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_INFORMATION,
         "Error in ldap_search_s() (error %u: %s).", ulResult, ldap_err2stringA(ulResult)
      );
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