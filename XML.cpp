#include <Windows.h>
#include <msxml6.h>
#include <atlcomcli.h>
#include "ORADAD.h"
#include "resource.h"

extern HANDLE g_hHeap;
extern BOOL g_bSupportsAnsi;

//
// Private functions
//
BOOL
pReadAttributes(
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPCWSTR szXPath,
   _Out_ PDWORD dwAttributesCount,
   _Out_ PATTRIBUTE_CONFIG *pAttributes
);

BOOL
pReadAttributeString(
   _In_ IXMLDOMNamedNodeMap *pXmlAttributeMap,
   _In_z_ LPWSTR szAttributeName,
   _Out_ LPWSTR *szValue
);

BOOL
pReadAttributeInterger(
   _In_ IXMLDOMNamedNodeMap *pXmlAttributeMap,
   _In_z_ LPWSTR szAttributeName,
   _Out_ PDWORD pdwValue
);

BOOL
pAddClassAttributes(
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPWSTR szClassName,
   _In_ PCLASS_CONFIG pClass,
   _In_ DWORD dwAttributesCount,
   _In_ PATTRIBUTE_CONFIG pAttributes
);

BOOL
pAddClassesToRequest(
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPWSTR szClassName,
   PREQUEST_CONFIG pRequest,
   _In_ PGLOBAL_CONFIG pGlobalConfig
);

PATTRIBUTE_CONFIG
pFindAttribute(
   _In_ DWORD dwAttributesCount,
   _In_ PATTRIBUTE_CONFIG pAttributes,
   _In_z_ LPWSTR szName
);

BOOL
pXmlParseRequest(
   _In_ IXMLDOMDocument2 *pXMLDoc,
   IXMLDOMNode *pXmlNodeRequest,
   PREQUEST_CONFIG pRequests,
   _In_ PGLOBAL_CONFIG pGlobalConfig
);

DWORD
pReadUInteger(
   _In_opt_z_ LPCWSTR szValue
);

BOOL
pReadBoolean(
   _In_opt_z_ LPCWSTR szValue
);

//
// Public functions
//
// Note: we return PVOID to avoid include msxml.h in all files.
PVOID
XmlReadConfigFile (
   _In_z_ LPTSTR szConfigPath,
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   HRESULT hr;
   VARIANT_BOOL bSuccess = false;

   IXMLDOMDocument2 *pXMLDoc = NULL;
   IXMLDOMNode *pXMLNode = NULL;
   IXMLDOMNode *pXMLNodeDomains = NULL;
   IXMLDOMNodeList *pXMLNodeList = NULL;
   IXMLDOMNodeList *pXMLNodeDomainsList = NULL;

   long lLength, lDomainLength;
   ULONG ulCurrentDomain = 0;

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[.] Read config file."
   );

   hr = CoCreateInstance(CLSID_FreeThreadedDOMDocument60, NULL, CLSCTX_INPROC_SERVER, IID_IXMLDOMDocument2, (void**)&pXMLDoc);
   if ((hr != S_OK) || (pXMLDoc == NULL))
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sUnable to create config XML object (error 0x%08x).%s", COLOR_RED, hr, COLOR_RESET
      );
      return NULL;
   }

   hr = pXMLDoc->put_async(VARIANT_FALSE);
   //hr = pXMLDoc->setProperty(L"SelectionLanguage", L"XPath");

   //
   // Load file
   //
   hr = pXMLDoc->load(CComVariant(szConfigPath), &bSuccess);

   if ((hr != S_OK) || (bSuccess == FALSE))
   {
      IXMLDOMParseError *pXmlParseError = NULL;
      BSTR strError;
      LPSTR szError;

      hr = pXMLDoc->get_parseError(&pXmlParseError);
      hr = pXmlParseError->get_reason(&strError);

      RemoveSpecialChars(strError);
      szError = LPWSTRtoUTF8(strError);

      if (szError != NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
            "[!] %sUnable to parse config XML (%s).%s", COLOR_RED, szError, COLOR_RESET
         );
         _SafeHeapRelease(szError);
      }

      _SafeCOMRelease(pXmlParseError);
      _SafeCOMRelease(pXMLDoc);
      return NULL;
   }

   //
   // Read Main Config
   //
   hr = pXMLDoc->selectSingleNode((BSTR)TEXT("/config"), &pXMLNode);
   hr = pXMLNode->get_childNodes(&pXMLNodeList);
   hr = pXMLNodeList->get_length(&lLength);

   for (long i = 0; i < lLength; i++)
   {
      IXMLDOMNode *pXmlNodeConfig = NULL;
      BSTR strNodeName;
      BSTR strNodeText;

      hr = pXMLNodeList->get_item(i, &pXmlNodeConfig);
      hr = pXmlNodeConfig->get_nodeName(&strNodeName);
      hr = pXmlNodeConfig->get_text(&strNodeText);

      if ((wcscmp(strNodeName, L"autoGetDomain") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bAutoGetDomain = pReadBoolean(strNodeText);
      else if ((wcscmp(strNodeName, L"autoGetTrusts") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bAutoGetTrusts = pReadBoolean(strNodeText);
      else if ((wcscmp(strNodeName, L"username") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->szUsername = strNodeText;
      else if ((wcscmp(strNodeName, L"userdomain") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->szUserDomain = strNodeText;
      else if ((wcscmp(strNodeName, L"userpassword") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->szUserPassword = strNodeText;
      else if ((wcscmp(strNodeName, L"level") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->dwLevel = pReadUInteger(strNodeText);
      else if ((wcscmp(strNodeName, L"confidential") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->dwConfidential = pReadUInteger(strNodeText);
      else if ((wcscmp(strNodeName, L"sleepTime") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->dwSleepTime = pReadUInteger(strNodeText);
      else if ((wcscmp(strNodeName, L"writeHeader") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bWriteHeader = pReadBoolean(strNodeText);

      else if ((wcscmp(strNodeName, L"outputFiles") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bOutputFiles = pReadBoolean(strNodeText);
      else if ((wcscmp(strNodeName, L"outputMLA") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bOutputMLA = pReadBoolean(strNodeText);
      else if ((wcscmp(strNodeName, L"additionalMLAKeys") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->szAdditionalMlaKeys = strNodeText;

      else if ((wcscmp(strNodeName, L"process_sysvol") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bProcessSysvol = pReadBoolean(strNodeText);
      else if ((wcscmp(strNodeName, L"sysvol_filter") == 0) && (wcslen(strNodeText) > 0))
      {
         pGlobalConfig->szSysvolFilter = strNodeText;
         _wcslwr_s(pGlobalConfig->szSysvolFilter, wcslen(pGlobalConfig->szSysvolFilter) + 1);
      }

      else if ((wcscmp(strNodeName, L"displayProgress") == 0) && (wcslen(strNodeText) > 0))
         pGlobalConfig->bDisplayProgress = pReadBoolean(strNodeText);

      _SafeCOMRelease(pXmlNodeConfig);
   }

   _SafeCOMRelease(pXMLNodeList);
   _SafeCOMRelease(pXMLNode);

   //
   // Check values
   //
   if (pGlobalConfig->bAutoGetDomain == FALSE)
      (pGlobalConfig->bAutoGetTrusts = FALSE);

   // Reserve space in <domains> for current domain if bAutoGetDomain is enabled
   if (pGlobalConfig->bAutoGetDomain == TRUE)
   {
      pGlobalConfig->dwDomainCount = 1;
      ulCurrentDomain++;
   }

   if (pGlobalConfig->bAutoGetTrusts == TRUE)
   {
      pGlobalConfig->DomainConfig = (PDOMAIN_CONFIG)_HeapAlloc(sizeof(DOMAIN_CONFIG) * pGlobalConfig->dwDomainCount);
   }
   else
   {
      //
      // Read Domains Config
      //
      hr = pXMLDoc->selectSingleNode((BSTR)TEXT("/config/domains"), &pXMLNodeDomains);
      hr = pXMLNodeDomains->get_childNodes(&pXMLNodeDomainsList);
      hr = pXMLNodeDomainsList->get_length(&lDomainLength);

      pGlobalConfig->DomainConfig = (PDOMAIN_CONFIG)_HeapAlloc(sizeof(DOMAIN_CONFIG) * (pGlobalConfig->dwDomainCount + lDomainLength));

      for (long i = 0; i < lDomainLength; i++)
      {
         IXMLDOMNode* pXmlNodeDomain = NULL;

         hr = pXMLNodeDomainsList->get_item(i, &pXmlNodeDomain);
         hr = pXmlNodeDomain->get_childNodes(&pXMLNodeList);
         hr = pXMLNodeList->get_length(&lLength);

         for (long j = 0; j < lLength; j++)
         {
            IXMLDOMNode* pXmlNodeConfig = NULL;
            BSTR strNodeName;
            BSTR strNodeText;

            hr = pXMLNodeList->get_item(j, &pXmlNodeConfig);
            hr = pXmlNodeConfig->get_nodeName(&strNodeName);
            hr = pXmlNodeConfig->get_text(&strNodeText);

            if ((wcscmp(strNodeName, L"server") == 0) && (wcslen(strNodeText) > 0))
               pGlobalConfig->DomainConfig[ulCurrentDomain].szServer = strNodeText;
            if ((wcscmp(strNodeName, L"port") == 0) && (wcslen(strNodeText) > 0))
               pGlobalConfig->DomainConfig[ulCurrentDomain].ulLdapPort = pReadUInteger(strNodeText);
            else if ((wcscmp(strNodeName, L"domainName") == 0) && (wcslen(strNodeText) > 0))
               pGlobalConfig->DomainConfig[ulCurrentDomain].szDomainName = strNodeText;
            else if ((wcscmp(strNodeName, L"username") == 0))     // Special case here, username can be '' (use implicit). If NULL, use global credentials
               pGlobalConfig->DomainConfig[ulCurrentDomain].szUsername = strNodeText;
            else if ((wcscmp(strNodeName, L"userdomain") == 0) && (wcslen(strNodeText) > 0))
               pGlobalConfig->DomainConfig[ulCurrentDomain].szUserDomain = strNodeText;
            else if ((wcscmp(strNodeName, L"userpassword") == 0) && (wcslen(strNodeText) > 0))
               pGlobalConfig->DomainConfig[ulCurrentDomain].szUserPassword = strNodeText;

            _SafeCOMRelease(pXmlNodeConfig);
         }

         _SafeCOMRelease(pXMLNodeList);
         _SafeCOMRelease(pXmlNodeDomain);

         if (lLength > 0)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
               "[i] %sConfig%s Add domain %u (server='%S', domainName='%S', username='%S')",
               COLOR_BLUE, COLOR_RESET,
               ulCurrentDomain,
               pGlobalConfig->DomainConfig[ulCurrentDomain].szServer,
               pGlobalConfig->DomainConfig[ulCurrentDomain].szDomainName,
               pGlobalConfig->DomainConfig[ulCurrentDomain].szUsername
            );

            // Be sure <domain> is valid (avoid #comment)
            pGlobalConfig->dwDomainCount++;
            ulCurrentDomain++;
         }
      }

      _SafeCOMRelease(pXMLNodeDomainsList);
      _SafeCOMRelease(pXMLNodeDomains);
   }

   if ((pGlobalConfig->bOutputFiles == FALSE) && (pGlobalConfig->bOutputMLA == FALSE))
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sAt least one output (file or MLA) must be enabled.%s", COLOR_RED, COLOR_RESET
      );
      return NULL;
   }

   return pXMLDoc;
}

PVOID
XmlReadSchemaFile (
   _In_opt_z_ LPTSTR szConfigPath,
   _In_ PGLOBAL_CONFIG pGlobalConfig,
   _In_ PVOID pXMLDocConfig
)
{
   UNREFERENCED_PARAMETER(pXMLDocConfig);

   BOOL bResult;
   HRESULT hr;
   VARIANT_BOOL bSuccess = false;

   IXMLDOMDocument2 *pXMLDoc = NULL;
   IXMLDOMNodeList *pXMLNodeList = NULL;

   SAFEARRAY* psaSchema;

   long lLength;

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_VERBOSE,
      "[.] Read schema file."
   );

   hr = CoCreateInstance(CLSID_FreeThreadedDOMDocument60, NULL, CLSCTX_INPROC_SERVER, IID_IXMLDOMDocument2, (void**)&pXMLDoc);
   if ((hr != S_OK) || (pXMLDoc == NULL))
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sUnable to create XML object (error 0x%08x).%s", COLOR_RED, hr, COLOR_RESET
      );
      return NULL;
   }

   hr = pXMLDoc->put_async(VARIANT_FALSE);

   //
   // Load file
   //
   if (szConfigPath != NULL)
   {
      hr = pXMLDoc->load(CComVariant(szConfigPath), &bSuccess);
   }
   else
   {
      SAFEARRAYBOUND rgsabound[1];
      VARIANT v;

      HMODULE hCurrentProcess;
      HRSRC hrSchema;
      DWORD dwSchemaSize = 0;
      PBYTE pSchema = NULL;

      //
      // Load config from resource
      //
      hCurrentProcess = GetModuleHandle(NULL);
      hrSchema = FindResource(hCurrentProcess, MAKEINTRESOURCE(IDR_SCHEMA), TEXT("SCHEMA"));
      if (hrSchema != NULL)
      {
         HGLOBAL hResource;

         hResource = LoadResource(hCurrentProcess, hrSchema);
         if (hResource != NULL)
         {
            dwSchemaSize = SizeofResource(hCurrentProcess, hrSchema);
            pSchema = (PBYTE)LockResource(hResource);
         }
      }

      if (pSchema == NULL)
      {
         _SafeCOMRelease(pXMLDoc);
         return NULL;
      }

      rgsabound[0].lLbound = 0;
      rgsabound[0].cElements = dwSchemaSize;
      psaSchema = SafeArrayCreate(VT_UI1, 1, rgsabound);
      memcpy(psaSchema->pvData, pSchema, dwSchemaSize);

      VariantInit(&v);
      V_VT(&v) = VT_ARRAY | VT_UI1;
      V_ARRAY(&v) = psaSchema;

      hr = pXMLDoc->load(v, &bSuccess);
   }

   if ((hr != S_OK) || (bSuccess == FALSE))
   {
      IXMLDOMParseError *pXmlParseError = NULL;
      BSTR strError;
      LPSTR szError;

      hr = pXMLDoc->get_parseError(&pXmlParseError);
      hr = pXmlParseError->get_reason(&strError);

      RemoveSpecialChars(strError);
      szError = LPWSTRtoUTF8(strError);

      if (szError != NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
            "[!] %sUnable to parse schema XML (%s).%s", COLOR_RED, szError, COLOR_RESET
         );
         _SafeHeapRelease(szError);
      }

      _SafeCOMRelease(pXmlParseError);
      _SafeCOMRelease(pXMLDoc);
      return NULL;
   }

   //
   // Read Attributes
   //
   bResult = pReadAttributes(pXMLDoc, L"/schema/rootDSEAttributes/attribute", &pGlobalConfig->dwRootDSEAttributesCount, &pGlobalConfig->pRootDSEAttributes);
   if (bResult == FALSE)
      return NULL;

   bResult = pReadAttributes(pXMLDoc, L"/schema/attributes/attribute", &pGlobalConfig->dwAttributesCount, &pGlobalConfig->pAttributes);
   if (bResult == FALSE)
      return NULL;

   //
   // Read Requests
   //
   hr = pXMLDoc->selectNodes((BSTR)TEXT("/schema/requests/request"), &pXMLNodeList);
   hr = pXMLNodeList->get_length(&lLength);

   pGlobalConfig->dwRequestCount = lLength;
   pGlobalConfig->pRequests = (PREQUEST_CONFIG)_HeapAlloc(lLength * sizeof(REQUEST_CONFIG));

   for (long i = 0; i < lLength; i++)
   {
      IXMLDOMNode *pXmlNodeRequest = NULL;
      IXMLDOMNodeList *pXmlNodeListRequest = NULL;

      hr = pXMLNodeList->get_item(i, &pXmlNodeRequest);

      bResult = pXmlParseRequest(pXMLDoc, pXmlNodeRequest, &pGlobalConfig->pRequests[i], pGlobalConfig);
      if (bResult == FALSE)
         return NULL;

      if (pGlobalConfig->pRequests[i].dwBase & BASE_ROOTDSE)
      {
         // RootDSE can only be RootDSE. Disable other types
         pGlobalConfig->pRequests[i].dwBase = BASE_ROOTDSE;

         // Allocate per request max attribute text size
         pGlobalConfig->pRequests[i].pdwStringMaxLength = (PDWORD)_HeapAlloc(sizeof(DWORD) * pGlobalConfig->dwRootDSEAttributesCount);
      }
      else
      {
         // Allocate per request max attribute text size
         pGlobalConfig->pRequests[i].pdwStringMaxLength = (PDWORD)_HeapAlloc(sizeof(DWORD) * pGlobalConfig->pRequests[i].dwAttributesCount);
      }

      // Free COM
      _SafeCOMRelease(pXmlNodeListRequest);
      _SafeCOMRelease(pXmlNodeRequest);
   }

   _SafeCOMRelease(pXMLNodeList);

   //
   // DEBUG CODE: display requests and attributes
   //
   /*
   for (DWORD i = 0; i < pGlobalConfig->dwRequestCount; i++)
   {
      wprintf_s(L"%s\n", pGlobalConfig->pRequests[i].szName);
      for (DWORD j = 0; j < pGlobalConfig->pRequests[i].dwAttributesCount; j++)
      {
         wprintf_s(L"   %s\n", pGlobalConfig->pRequests[i].pAttributes[j]->szName);
      }
      wprintf_s(L"\n");
   }
   */

   return pXMLDoc;
}

//
// Private functions
//
BOOL
pReadAttributes (
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPCWSTR szXPath,
   _Out_ PDWORD dwAttributesCount,
   _Out_ PATTRIBUTE_CONFIG *pAttributes
)
{
   HRESULT hr;

   IXMLDOMNodeList *pXMLNodeList = NULL;

   long lLength;

   hr = pXMLDoc->selectNodes((BSTR)szXPath, &pXMLNodeList);

   hr = pXMLNodeList->get_length(&lLength);

   *dwAttributesCount = lLength;
   *pAttributes = (PATTRIBUTE_CONFIG)_HeapAlloc(lLength * sizeof(ATTRIBUTE_CONFIG));
   if (*pAttributes == NULL)
   {
      *dwAttributesCount = 0;
      return FALSE;
   }

   for (long i = 0; i < lLength; i++)
   {
      BOOL bResult;

      LPWSTR szType;
      LPWSTR szFilter;
      LPWSTR szFlags;

      IXMLDOMNode *pXmlNodeAttribute = NULL;
      IXMLDOMNamedNodeMap *pXmlAttributeMap = NULL;

      hr = pXMLNodeList->get_item(i, &pXmlNodeAttribute);
      hr = pXmlNodeAttribute->get_attributes(&pXmlAttributeMap);

      pReadAttributeString(pXmlAttributeMap, (LPWSTR)L"name", &(*pAttributes)[i].szName);
      pReadAttributeInterger(pXmlAttributeMap, (LPWSTR)L"level", &(*pAttributes)[i].dwLevel);
      pReadAttributeString(pXmlAttributeMap, (LPWSTR)L"type", &szType);
      pReadAttributeString(pXmlAttributeMap, (LPWSTR)L"filter", &szFilter);
      pReadAttributeString(pXmlAttributeMap, (LPWSTR)L"flags", &szFlags);
      pReadAttributeInterger(pXmlAttributeMap, (LPWSTR)L"limit", &(*pAttributes)[i].dwLimit);

      if (szFilter != NULL)
      {
         bResult = GetFilter(&(*pAttributes)[i], szFilter);
         if (bResult == FALSE)
            return FALSE;
      }

      if (_wcsicmp(szType, L"STR") == 0)
         (*pAttributes)[i].Type = TYPE_STR;
      else if (_wcsicmp(szType, L"STRS") == 0)
         (*pAttributes)[i].Type = TYPE_STRS;
      else if (_wcsicmp(szType, L"SID") == 0)
         (*pAttributes)[i].Type = TYPE_SID;
      else if (_wcsicmp(szType, L"SD") == 0)
         (*pAttributes)[i].Type = TYPE_SD;
      else if (_wcsicmp(szType, L"DACL") == 0)
         (*pAttributes)[i].Type = TYPE_DACL;
      else if (_wcsicmp(szType, L"GUID") == 0)
         (*pAttributes)[i].Type = TYPE_GUID;
      else if (_wcsicmp(szType, L"DATE") == 0)
         (*pAttributes)[i].Type = TYPE_DATE;
      else if (_wcsicmp(szType, L"DATEINT64") == 0)
         (*pAttributes)[i].Type = TYPE_DATEINT64;
      else if (_wcsicmp(szType, L"INT") == 0)
         (*pAttributes)[i].Type = TYPE_INT;
      else if (_wcsicmp(szType, L"INT64") == 0)
         (*pAttributes)[i].Type = TYPE_INT64;
      else if (_wcsicmp(szType, L"BOOL") == 0)
         (*pAttributes)[i].Type = TYPE_BOOL;
      else if (_wcsicmp(szType, L"BIN") == 0)
         (*pAttributes)[i].Type = TYPE_BIN;
      else
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
            "[!] %sUnknown type (%S).%s", COLOR_RED, szType, COLOR_RESET
         );
         return FALSE;
      }

      if (szFlags != NULL)
      {
         if (wcsstr(szFlags, L"confidential") != NULL)
         {
            if ((*pAttributes)[i].dwLimit < 99999)
               (*pAttributes)[i].bConfidential = TRUE;
         }
      }

      _SafeCOMRelease(pXmlAttributeMap);
      _SafeCOMRelease(pXmlNodeAttribute);
   }

   _SafeCOMRelease(pXMLNodeList);

   return TRUE;
}

BOOL
pReadAttributeString (
   _In_ IXMLDOMNamedNodeMap *pXmlAttributeMap,
   _In_z_ LPWSTR szAttributeName,
   _Out_ LPWSTR *szValue
)
{
   HRESULT hr;
   IXMLDOMNode *pXmlNodeAttribute = NULL;
   BSTR strName;

   hr = pXmlAttributeMap->getNamedItem((BSTR)szAttributeName, &pXmlNodeAttribute);
   if (hr == S_OK)
   {
      hr = pXmlNodeAttribute->get_text(&strName);
      *szValue = (LPTSTR)strName;

      _SafeCOMRelease(pXmlNodeAttribute);
   }
   else
      *szValue = NULL;

   return TRUE;
}

BOOL
pReadAttributeInterger (
   _In_ IXMLDOMNamedNodeMap *pXmlAttributeMap,
   _In_z_ LPWSTR szAttributeName,
   _Out_ PDWORD pdwValue
)
{
   HRESULT hr;
   int r;
   IXMLDOMNode *pXmlNodeAttribute = NULL;
   BSTR strName;
   DWORD dwValue = 0;

   hr = pXmlAttributeMap->getNamedItem((BSTR)szAttributeName, &pXmlNodeAttribute);
   if (hr == S_OK)
   {
      hr = pXmlNodeAttribute->get_text(&strName);
      r = swscanf_s(strName, L"%u", &dwValue);

      _SafeCOMRelease(pXmlNodeAttribute);
   }
   *pdwValue = dwValue;



   return TRUE;
}

BOOL
pAddClassAttributes (
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPWSTR szClassName,
   _In_ PCLASS_CONFIG pClass,
   _In_ DWORD dwAttributesCount,
   _In_ PATTRIBUTE_CONFIG pAttributes
)
{
   HRESULT hr;
   WCHAR szXPath[MAX_PATH];
   IXMLDOMNodeList *pXMLNodeList = NULL;

   DWORD dwInitialLength;
   long lLength;

   BOOL bAttributeNotFound = FALSE;

   swprintf_s(szXPath, MAX_PATH, L"/schema/classes/class[@name=\"%s\"]/attribute", szClassName);

   hr = pXMLDoc->selectNodes(szXPath, &pXMLNodeList);
   hr = pXMLNodeList->get_length(&lLength);
   if (lLength == 0)
   {
      return TRUE;
   }

   dwInitialLength = pClass->dwAttributesCount;
   pClass->dwAttributesCount += lLength;

   if (dwInitialLength == 0)
   {
      pClass->pAttributes = (PATTRIBUTE_CONFIG*)_HeapAlloc(pClass->dwAttributesCount * sizeof(ATTRIBUTE_CONFIG));
   }
   else
   {
      pClass->pAttributes = (PATTRIBUTE_CONFIG*)HeapReAlloc(g_hHeap, HEAP_ZERO_MEMORY, pClass->pAttributes, pClass->dwAttributesCount * sizeof(ATTRIBUTE_CONFIG));
   }

   for (long i = 0; i < lLength; i++)
   {
      LPWSTR szAttributeName;
      PATTRIBUTE_CONFIG pAttribute;

      IXMLDOMNode *pXmlNode = NULL;
      IXMLDOMNamedNodeMap *pXmlClassMap = NULL;

      hr = pXMLNodeList->get_item(i, &pXmlNode);
      hr = pXmlNode->get_attributes(&pXmlClassMap);

      pReadAttributeString(pXmlClassMap, (LPWSTR)L"name", &szAttributeName);

      pAttribute = pFindAttribute(dwAttributesCount, pAttributes, szAttributeName);
      if (pAttribute == NULL)
      {
         Log(
            __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
            "[!] %sAttribute not found (%S).%s", COLOR_RED, szAttributeName, COLOR_RESET
         );
         bAttributeNotFound = TRUE;
      }

      pClass->pAttributes[dwInitialLength + i] = pAttribute;

      _SafeCOMRelease(pXmlClassMap);
      _SafeCOMRelease(pXmlNode);
   }

   _SafeCOMRelease(pXMLNodeList);

   if (bAttributeNotFound == TRUE)
      return FALSE;
   else
      return TRUE;
}

PATTRIBUTE_CONFIG
pFindAttribute (
   _In_ DWORD dwAttributesCount,
   _In_ PATTRIBUTE_CONFIG pAttributes,
   _In_z_ LPWSTR szName
)
{
   for (DWORD i = 0; i < dwAttributesCount; i++)
   {
      if (_wcsicmp(pAttributes[i].szName, szName) == 0)
         return &pAttributes[i];
   }

   return NULL;
}

_Success_(return)
BOOL
pGetAttributeByNameForRequest (
   _In_z_ LPWSTR szAttributeName,
   _Out_ PATTRIBUTE_CONFIG *pAttributes,
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   for (DWORD i = 0; i < pGlobalConfig->dwAttributesCount; i++)
   {
      if (_wcsicmp(szAttributeName, pGlobalConfig->pAttributes[i].szName) == 0)
      {
         *pAttributes = &pGlobalConfig->pAttributes[i];
         return TRUE;
      }
   }

   Log(
      __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
      "[!] %sAttribute '%S' not found.%s", COLOR_RED, szAttributeName, COLOR_RESET
   );
   return FALSE;
}

BOOL
pAddClassToRequest (
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPWSTR szClassName,
   PREQUEST_CONFIG pRequest,
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   HRESULT hr;
   BOOL bReturn = TRUE;

   WCHAR szXPath[MAX_PATH];
   long lLength;

   IXMLDOMNodeList *pXMLNodeListClass = NULL;
   IXMLDOMNodeList *pXMLNodeListAttributes = NULL;
   IXMLDOMNode *pXmlNode = NULL;
   IXMLDOMNamedNodeMap *pXmlClassMap = NULL;

   DWORD dwAttributesCount = 0;
   DWORD dwNewAttributes = 0;
   LPWSTR *szAttributes;
   LPWSTR szSubClasses;

   PATTRIBUTE_CONFIG *pNewAttributes;

   //
   // Find class
   //
   swprintf_s(szXPath, MAX_PATH, L"/schema/classes/class[@name=\"%s\"]", szClassName);

   hr = pXMLDoc->selectNodes(szXPath, &pXMLNodeListClass);
   hr = pXMLNodeListClass->get_length(&lLength);
   if (lLength != 1)
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_CRITICAL,
         "[!] %sClass '%S' not found for request '%S'.%s", COLOR_RED, szClassName, pRequest->szName, COLOR_RESET
      );
      return FALSE;
   }

   hr = pXMLNodeListClass->get_item(0, &pXmlNode);
   hr = pXmlNode->get_attributes(&pXmlClassMap);

   pReadAttributeString(pXmlClassMap, (LPWSTR)L"auxiliaryClass", &szSubClasses);
   if (szSubClasses != NULL)
      pAddClassesToRequest(pXMLDoc, szSubClasses, pRequest, pGlobalConfig);

   pReadAttributeString(pXmlClassMap, (LPWSTR)L"systemAuxiliaryClass", &szSubClasses);
   if (szSubClasses != NULL)
      pAddClassesToRequest(pXMLDoc, szSubClasses, pRequest, pGlobalConfig);

   hr = pXmlNode->get_childNodes(&pXMLNodeListAttributes);
   pXMLNodeListAttributes->get_length(&lLength);

   szAttributes = (LPWSTR*)_HeapAlloc(lLength * sizeof(LPWSTR));
   if (szAttributes == NULL)
   {
      return FALSE;
   }

   for (long i = 0; i < lLength; i++)
   {
      BSTR AttributeName;
      IXMLDOMNode *pXmlSubNode = NULL;

      hr = pXMLNodeListAttributes->get_item(i, &pXmlSubNode);
      hr = pXmlSubNode->get_nodeName(&AttributeName);

      if (_wcsicmp(AttributeName, L"attribute") == 0)
      {
         IXMLDOMNamedNodeMap *pXmlNodeAttributeAttributes = NULL;
         IXMLDOMNode *pXmlNodeAttributeName = NULL;
         BSTR szName;

         hr = pXmlSubNode->get_attributes(&pXmlNodeAttributeAttributes);
         hr = pXmlNodeAttributeAttributes->getNamedItem((BSTR)L"name", &pXmlNodeAttributeName);
         hr = pXmlNodeAttributeName->get_text(&szName);
         szAttributes[i] = (LPWSTR)szName;
         dwAttributesCount++;

         _SafeCOMRelease(pXmlNodeAttributeName);
         _SafeCOMRelease(pXmlNodeAttributeAttributes);
      }

      _SafeCOMRelease(pXmlSubNode);
   }

   _SafeCOMRelease(pXmlClassMap);
   _SafeCOMRelease(pXmlNode);
   _SafeCOMRelease(pXMLNodeListAttributes);
   _SafeCOMRelease(pXMLNodeListClass);

   //
   // First pass: count new attributes
   //
   DWORD dwClassNewAttributes;

   dwClassNewAttributes = dwAttributesCount;

   for (DWORD j = 0; j < dwAttributesCount; j++)
   {
      for (DWORD k = 0; k < pRequest->dwAttributesCount; k++)
      {
         if (_wcsicmp(szAttributes[j], (*pRequest->pAttributes[k]).szName) == 0)
            dwClassNewAttributes--;
      }
   }

   dwNewAttributes += dwClassNewAttributes;

   //
   // Second pass: add new attributes
   //
   if (dwNewAttributes > 0)
   {
      if (pRequest->pAttributes == NULL)
      {
         pNewAttributes = (PATTRIBUTE_CONFIG*)HeapAlloc(
            g_hHeap,
            HEAP_ZERO_MEMORY,
            dwNewAttributes * sizeof(PATTRIBUTE_CONFIG)
         );
      }
      else
      {
         pNewAttributes = (PATTRIBUTE_CONFIG*)HeapReAlloc(
            g_hHeap,
            HEAP_ZERO_MEMORY,
            pRequest->pAttributes,
            (pRequest->dwAttributesCount + dwNewAttributes) * sizeof(PATTRIBUTE_CONFIG)
         );
      }
      if (pNewAttributes == NULL)
      {
         return FALSE;
      }

      pRequest->pAttributes = pNewAttributes;

      for (DWORD j = 0; j < dwAttributesCount; j++)
      {
         BOOL bAddAttribute = TRUE;

         for (DWORD k = 0; k < pRequest->dwAttributesCount; k++)
         {
            if (_wcsicmp(szAttributes[j], (*pRequest->pAttributes[k]).szName) == 0)
            {
               bAddAttribute = FALSE;
            }
         }

         if (bAddAttribute == TRUE)
         {
            BOOL bResult;

            bResult = pGetAttributeByNameForRequest(szAttributes[j], &pRequest->pAttributes[pRequest->dwAttributesCount], pGlobalConfig);
            if (bResult == FALSE)
               bReturn = FALSE;
            else
               pRequest->dwAttributesCount++;
         }
      }
   }

   return bReturn;
}

BOOL
pAddClassesToRequest (
   _In_ IXMLDOMDocument2 *pXMLDoc,
   _In_z_ LPWSTR szClassName,
   PREQUEST_CONFIG pRequest,
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   LPWSTR szToken;
   LPWSTR szTokenContext = NULL;

   if (szClassName == NULL)
      return TRUE;

   szToken = wcstok_s(szClassName, L",", &szTokenContext);
   while (szToken != NULL)
   {
      BOOL bResult;

      bResult = pAddClassToRequest(pXMLDoc, szToken, pRequest, pGlobalConfig);
      if (bResult == FALSE)
         return FALSE;

      szToken = wcstok_s(NULL, L",", &szTokenContext);
   }

   return TRUE;
}

BOOL
pXmlParseRequest (
   _In_ IXMLDOMDocument2 *pXMLDoc,
   IXMLDOMNode *pXmlNodeRequest,
   PREQUEST_CONFIG pRequest,
   _In_ PGLOBAL_CONFIG pGlobalConfig
)
{
   HRESULT hr;
   IXMLDOMNodeList *pXmlNodeListRequest = NULL;

   long lLength;

   hr = pXmlNodeRequest->get_childNodes(&pXmlNodeListRequest);

   hr = pXmlNodeListRequest->get_length(&lLength);

   for (long i = 0; i < lLength; i++)
   {
      IXMLDOMNode *pXmlNode = NULL;

      BSTR strNodeName;
      BSTR strNodeText;

      hr = pXmlNodeListRequest->get_item(i, &pXmlNode);
      hr = pXmlNode->get_nodeName(&strNodeName);
      hr = pXmlNode->get_text(&strNodeText);

      if ((_wcsicmp(strNodeName, L"name") == 0) && (wcslen(strNodeText) > 0))
         pRequest->szName = strNodeText;
      else if ((_wcsicmp(strNodeName, L"filter") == 0) && (wcslen(strNodeText) > 0))
         pRequest->szFilter = strNodeText;
      else if ((_wcsicmp(strNodeName, L"scope") == 0) && (wcslen(strNodeText) > 0))
      {
         if (_wcsicmp(strNodeText, L"base") == 0)
            pRequest->dwScope = 0;        // LDAP_SCOPE_BASE;
         else if (_wcsicmp(strNodeText, L"onelevel") == 0)
            pRequest->dwScope = 1;        // LDAP_SCOPE_ONELEVEL;
         else if (_wcsicmp(strNodeText, L"subtree") == 0)
            pRequest->dwScope = 2;        // LDAP_SCOPE_SUBTREE;
      }
      else if ((_wcsicmp(strNodeName, L"base") == 0) && (wcslen(strNodeText) > 0))
      {
         LPWSTR szToken;
         LPWSTR szTokenContext = NULL;

         szToken = wcstok_s(strNodeText, L",", &szTokenContext);
         while (szToken != NULL)
         {
            if (_wcsicmp(szToken, STR_ROOTDSE) == 0)
               pRequest->dwBase |= BASE_ROOTDSE;
            else if (_wcsicmp(szToken, STR_DOMAIN) == 0)
               pRequest->dwBase |= BASE_DOMAIN;
            else if (_wcsicmp(szToken, STR_CONFIGURATION) == 0)
               pRequest->dwBase |= BASE_CONFIGURATION;
            else if (_wcsicmp(szToken, STR_SCHEMA) == 0)
               pRequest->dwBase |= BASE_SCHEMA;
            else if (_wcsicmp(szToken, STR_DOMAIN_DNS) == 0)
               pRequest->dwBase |= BASE_DOMAIN_DNS;
            else if (_wcsicmp(szToken, STR_FOREST_DNS) == 0)
               pRequest->dwBase |= BASE_FOREST_DNS;
            //else if (_wcsicmp(szToken, STR_APPLICATION) == 0)
            //   pRequest->dwBase |= BASE_APPLICATION;

            szToken = wcstok_s(NULL, L",", &szTokenContext);
         }
      }
      else if ((_wcsicmp(strNodeName, L"classes") == 0) && (wcslen(strNodeText) > 0))
      {
         BOOL bResult;

         bResult = pAddClassesToRequest(pXMLDoc, strNodeText, pRequest, pGlobalConfig);

         if (bResult == FALSE)
            return FALSE;
      }
      else if (_wcsicmp(strNodeName, L"controls") == 0)
      {
         IXMLDOMNodeList* pXmlNodeListControls = NULL;
         long lControlLength;

         hr = pXmlNode->get_childNodes(&pXmlNodeListControls);
         hr = pXmlNodeListControls->get_length(&lControlLength);
         pRequest->pControls = (PCONTROL_LDAP)_HeapAlloc(lControlLength * sizeof(CONTROL_LDAP));
         if (pRequest->pControls == NULL)
         {
            Log(
               __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
               "[!] %sCannot allocate memory%s (error %u).",
               COLOR_RED, COLOR_RESET, GetLastError()
            );
            break;
         }
         pRequest->dwControlsCount = lControlLength;

         for (long lControlIt = 0; lControlIt < lControlLength; ++lControlIt)
         {
            IXMLDOMNode* pXmlControlNode = NULL;
            IXMLDOMNamedNodeMap* pXmlAttributes = NULL;
            long lAttrLength;

            hr = pXmlNodeListControls->get_item(lControlIt, &pXmlControlNode);
            hr = pXmlControlNode->get_attributes(&pXmlAttributes);
            if (hr != S_OK)
               continue;

            hr = pXmlAttributes->get_length(&lAttrLength);

            for (long lAttrIt = 0; lAttrIt < lAttrLength; ++lAttrIt)
            {
               IXMLDOMNode* pXmlAttribute = NULL;
               BSTR strAttrName;
               BSTR strAttrText;

               hr = pXmlAttributes->get_item(lAttrIt, &pXmlAttribute);
               hr = pXmlAttribute->get_nodeName(&strAttrName);
               hr = pXmlAttribute->get_text(&strAttrText);

               if (_wcsicmp(strAttrName, L"oid") == 0)
               {
                  pRequest->pControls[lControlIt].szOid = strAttrText;
               }
               else if (_wcsicmp(strAttrName, L"valueType") == 0)
               {
                  pRequest->pControls[lControlIt].szValueType = strAttrText;
               }
               else if (_wcsicmp(strAttrName, L"value") == 0)
               {
                  pRequest->pControls[lControlIt].szValue = strAttrText;
               }
               else if (_wcsicmp(strAttrName, L"critical") == 0)
               {
                  pRequest->pControls[lControlIt].isCritical = (_wcsicmp(strAttrText, L"true") == 0);
               }

               _SafeCOMRelease(pXmlAttribute);
            }

            _SafeCOMRelease(pXmlAttributes);
            _SafeCOMRelease(pXmlControlNode);
         }

         _SafeCOMRelease(pXmlNodeListControls);
      }

      _SafeCOMRelease(pXmlNode);
   }

   _SafeCOMRelease(pXmlNodeListRequest);

   return TRUE;
}

DWORD
pReadUInteger (
   _In_opt_z_ LPCWSTR szValue
)
{
   DWORD dwResult;

   if (szValue == NULL)
      return 0;

   if (wcslen(szValue) == 0)
      return 0;

   if (swscanf_s(szValue, L"%u", &dwResult) == 1)
      return dwResult;
   else
      return 0;
}

BOOL
pReadBoolean (
   _In_opt_z_ LPCWSTR szValue
)
{
   if (szValue == NULL)
      return FALSE;

   if (_wcsicmp(szValue, L"true") == 0)
      return TRUE;
   else if (wcscmp(szValue, L"1") == 0)
      return TRUE;
   else
      return FALSE;
}