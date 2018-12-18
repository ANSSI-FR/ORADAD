#include <Windows.h>
#include <Sddl.h>
#include <stdio.h>
#include "ORADAD.h"
#include "Constants.h"

extern HANDLE g_hHeap;

#define NEVER_VALUE                 9223372036854775808
#define STR_UNABLE_CONVERT_SID      L"Unable to convert SID"
#define STR_NEVER                   L"Never"

//
// Filter functions
//
BOOL
pFilterFlagsType(
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
);

BOOL
pFilterSid(
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
);

BOOL
pFilterFiletime(
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
);

BOOL
pFilterNegFiletime(
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
);

//
// Private functions
//
LPWSTR
pHeapAllocAndCopyString(
   _In_z_ LPCWSTR szString
);

BOOL
GetFilter (
   _Inout_ PATTRIBUTE_CONFIG pAttributes,
   _In_z_ LPCWSTR szFilter
)
{
   if (_wcsicmp(szFilter, L"userAccountControl") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cUserAccountControl;
   }
   else if (_wcsicmp(szFilter, L"supportedEncryptionTypes") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cSupportedEncryptionTypes;
   }
   else if (_wcsicmp(szFilter, L"groupType") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cGroupType;
   }
   else if (_wcsicmp(szFilter, L"trustAttributes") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cTrustAttributes;
   }
   else if (_wcsicmp(szFilter, L"trustDirection") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cTrustDirection;
   }
   else if (_wcsicmp(szFilter, L"trustType") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cTrustType;
   }
   else if (_wcsicmp(szFilter, L"systemFlags") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cSystemFlags;
   }
   else if (_wcsicmp(szFilter, L"searchFlags") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cSearchFlags;
   }
   else if (_wcsicmp(szFilter, L"schemaFlagsEx") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFlagsType;
      pAttributes->pvFilterData = cSchemaFlagsEx;
   }
   else if (_wcsicmp(szFilter, L"sid") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterSid;
      pAttributes->pvFilterData = NULL;
   }
   else if (_wcsicmp(szFilter, L"Filetime") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterFiletime;
      pAttributes->pvFilterData = NULL;
   }
   else if (_wcsicmp(szFilter, L"NegFiletime") == 0)
   {
      pAttributes->fFilter = (tFilter)pFilterNegFiletime;
      pAttributes->pvFilterData = NULL;
   }
   else
   {
      Log(
         __FILE__, __FUNCTION__, __LINE__, LOG_LEVEL_ERROR,
         "Unknown filter '%S'.", szFilter
      );
      return FALSE;
   }

   return TRUE;
}

LPWSTR
ApplyFilter (
   _In_ PATTRIBUTE_CONFIG pAttributes,
   _In_z_ PVOID pvData
)
{
   BOOL bResult;
   LPWSTR szResult = NULL;

   if (pvData == NULL)
      return NULL;

   if (pAttributes->fFilter == NULL)
      return NULL;

   bResult = pAttributes->fFilter(pvData, pAttributes->pvFilterData, &szResult);
   if (bResult == FALSE)
   {
      _SafeHeapRelease(szResult);
      return NULL;
   }
   else
      return szResult;
}

//
// Filter functions
//
BOOL
pFilterFlagsType (
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
)
{
   BOOL bFirst = TRUE;
   DWORD dwValue;
   DWORD dwRest;
   LPWSTR szOut;

   PCONST_TXT pFlagsList;
   DWORD dwFilterMode;

   szOut = (LPWSTR)_HeapAlloc(CONST_MAX_SIZE * sizeof(WCHAR));
   if (szOut == NULL)
      return FALSE;

   dwValue = *(PDWORD)pvData;
   dwRest = dwValue;
   pFlagsList = (PCONST_TXT)pvParam;

   //
   // Pass 1: Get filter Mode
   //
   pFlagsList = (PCONST_TXT)pvParam;
   while (pFlagsList->szTxt)
   {
      pFlagsList++;
   }
   dwFilterMode = pFlagsList->dwConst;

   //
   // Pass 2: Apply filter
   //
   pFlagsList = (PCONST_TXT)pvParam;
   switch (dwFilterMode)
   {
      case FILTER_FLAG:
      {
         while (pFlagsList->szTxt)
         {
            if (pFlagsList->dwConst & dwValue)
            {
               if (bFirst)
                  bFirst = FALSE;
               else
                  wcscat_s(szOut, CONST_MAX_SIZE, L" | ");
               wcscat_s(szOut, CONST_MAX_SIZE, pFlagsList->szTxt);
               dwRest &= ~pFlagsList->dwConst;
            }
            pFlagsList++;
         }

         //
         // Add remaining flags
         //
         if (dwRest)
         {
            WCHAR szRest[SIZE_NUMBER_TXT];
            swprintf_s(szRest, SIZE_NUMBER_TXT, L"%lu", dwRest);

            if (!bFirst)
               wcscat_s(szOut, CONST_MAX_SIZE, L" | ");

            wcscat_s(szOut, CONST_MAX_SIZE, szRest);
         }
      }
      break;

      case FILTER_TYPE:
      {
         while (pFlagsList->szTxt)
         {
            if (pFlagsList->dwConst == dwValue)
            {
               wcscpy_s(szOut, CONST_MAX_SIZE, pFlagsList->szTxt);
               break;
            }
            pFlagsList++;
         }
      }
      break;
   }

   *szResult = szOut;
   return TRUE;
}

BOOL
pFilterSid (
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
)
{
   BOOL bResult;
   LPWSTR szSid;

   bResult = ConvertSidToStringSid(pvData, &szSid);
   if (bResult == TRUE)
   {
      *szResult = pHeapAllocAndCopyString(szSid);
      LocalFree(szSid);
   }
   else
   {
      *szResult = pHeapAllocAndCopyString(STR_UNABLE_CONVERT_SID);
   }

   return TRUE;
}

BOOL
pFilterFiletime (
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
)
{
   LONGLONG llValue;

   *szResult = NULL;

   llValue = *(PLONGLONG)pvData;

   if (llValue == 0)
      *szResult = NULL;
   else
   {
      LONGLONG llDay;
      LONG lHour;
      LONG lMinute;
      LONG lSeconde;

      llValue = llValue / 10000000;

      llDay = llValue / 86400;
      llValue = llValue - (llDay * 86400);

      lHour = (LONG)(llValue / 3600);
      llValue = llValue - (lHour * 3600);

      lMinute = (LONG)(llValue / 60);
      llValue = llValue - (lMinute * 60);

      lSeconde = (LONG)(llValue / 60);
      llValue = llValue - (lSeconde * 60);

      *szResult = (LPWSTR)_HeapAlloc(15 * sizeof(WCHAR));
      swprintf_s(*szResult, 15, L"%llu:%02u:%02u:%02u", llDay, lHour, lMinute, lSeconde);
   }

   return TRUE;
}

BOOL
pFilterNegFiletime (
   _In_ PVOID pvData,
   _In_ PVOID pvParam,
   _Outptr_ LPWSTR *szResult
)
{
   LONGLONG llValue;

   *szResult = NULL;

   llValue = -(*(PLONGLONG)pvData);

   if (llValue == 0)
      *szResult = NULL;
   else if (llValue == NEVER_VALUE)
      *szResult = pHeapAllocAndCopyString(STR_NEVER);
   else
   {
      LONGLONG llDay;
      LONG lHour;
      LONG lMinute;
      LONG lSeconde;

      llValue = llValue / 10000000;

      llDay = llValue / 86400;
      llValue = llValue - (llDay * 86400);

      lHour = (LONG)(llValue / 3600);
      llValue = llValue - (lHour * 3600);

      lMinute = (LONG)(llValue / 60);
      llValue = llValue - (lMinute * 60);

      lSeconde = (LONG)(llValue / 60);
      llValue = llValue - (lSeconde * 60);

      *szResult = (LPWSTR)_HeapAlloc(15 * sizeof(WCHAR));
      swprintf_s(*szResult, 15, L"%llu:%02u:%02u:%02u", llDay, lHour, lMinute, lSeconde);
   }

   return TRUE;
}

//
// Private functions
//
LPWSTR
pHeapAllocAndCopyString (
   _In_z_ LPCWSTR szString
)
{
   LPWSTR szReturn;
   size_t SizeString;

   SizeString = wcslen(szString);
   SizeString++;           // NULL char
   szReturn = (LPWSTR)_HeapAlloc(SizeString * sizeof(WCHAR));
   if (szReturn != NULL)
   {
      wcscpy_s(szReturn, SizeString, szString);
   }

   return szReturn;
}