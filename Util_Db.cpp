#include <Windows.h>
#include "ORADAD.h"

extern HANDLE g_hHeap;
extern HANDLE g_hLogFile;
extern BOOL g_bSupportsAnsi;

//
// Public functions
//
BOOL
DbAddKey (
   _Inout_ PDB_ENTRY *pBase,
   _In_opt_z_ LPWSTR szKeyName,
   _In_ DWORD dwKeyValue,
   _In_ DbCompareMode CompareMode
)
{
   PDB_ENTRY pCurrent;

   if (szKeyName == NULL)
      return NULL;

   pCurrent = DbLookupKey(*pBase, szKeyName);
   if (pCurrent == NULL)
   {
      pCurrent = (PDB_ENTRY)_HeapAlloc(sizeof(DB_ENTRY));
      if (pCurrent == NULL)
         return FALSE;
      DuplicateString(szKeyName, &pCurrent->szKeyName);
      pCurrent->dwKeyValue = dwKeyValue;

      if (*pBase == NULL)
      {
         *pBase = pCurrent;
      }
      else
      {
         PDB_ENTRY pLast = *pBase;

         while (pLast->pNext != NULL)
            pLast = (PDB_ENTRY)pLast->pNext;

         pLast->pNext = pCurrent;
      }
   }
   else
   {
      BOOL bUpdateValue = FALSE;

      if (CompareMode == DbCompareMode::Max)
      {
         if (dwKeyValue > pCurrent->dwKeyValue)
         {
            bUpdateValue = TRUE;
         }
      }
      else if (CompareMode == DbCompareMode::Last)
      {
         bUpdateValue = TRUE;
      }

      if (bUpdateValue == TRUE)
      {
         pCurrent->dwKeyValue = dwKeyValue;
      }
   }

   return TRUE;
}

PDB_ENTRY
DbLookupKey (
   _Inout_ PDB_ENTRY pBase,
   _In_opt_z_ LPWSTR szKeyName
)
{
   PDB_ENTRY pCurrent;

   if ((pBase == NULL) || (szKeyName==NULL))
      return NULL;

   pCurrent = pBase;
   while (pCurrent != NULL)
   {
      if (_wcsicmp(pCurrent->szKeyName, szKeyName) == 0)
         return pCurrent;

      pCurrent = (PDB_ENTRY)((PDB_ENTRY)pCurrent)->pNext;
   }

   // pCurrent should be null here
   return pCurrent;
}

BOOL
DbFree (
   _Inout_ PDB_ENTRY *pBase
)
{
   PDB_ENTRY pCurrent;

   if (*pBase == NULL)
      return TRUE;

   pCurrent = *pBase;
   while (pCurrent != NULL)
   {
      PDB_ENTRY pBackup;

      _SafeHeapRelease(pCurrent->szKeyName);
      pBackup = (PDB_ENTRY)pCurrent->pNext;
      _SafeHeapRelease(pCurrent);
      pCurrent = pBackup;
   }

   *pBase = NULL;

   return TRUE;
}
