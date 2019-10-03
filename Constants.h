#include <Iads.h>                   // cUserAccountControl
#include <ntsecapi.h>               // cTrustAttributes

#define CONST_MAX_SIZE        1024
#define SIZE_NUMBER_TXT       12

#define ADS_UF_NO_AUTH_DATA_REQUIRED      0x2000000
#define ADS_UF_PARTIAL_SECRETS_ACCOUNT    0x4000000
CONST_TXT cUserAccountControl[] =
{
   { ADS_UF_ACCOUNTDISABLE,                           L"DISABLE" },
   { ADS_UF_LOCKOUT,                                  L"LOCKOUT" },
   { ADS_UF_PASSWD_NOTREQD,                           L"PASSWD_NOTREQD" },
   { ADS_UF_PASSWD_CANT_CHANGE,                       L"PASSWD_CANT_CHANGE" },
   { ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED,          L"TEXT_PASSWORD" },
   { ADS_UF_PASSWORD_EXPIRED,                         L"PASSWORD_EXPIRED" },
   { ADS_UF_DONT_EXPIRE_PASSWD,                       L"DONT_EXPIRE_PASSWD" },

   { ADS_UF_DONT_REQUIRE_PREAUTH,                     L"DONT_REQUIRE_PREAUTH" },
   { ADS_UF_SMARTCARD_REQUIRED,                       L"SMARTCARD_REQUIRED" },
   { ADS_UF_USE_DES_KEY_ONLY,                         L"USE_DES_KEY_ONLY" },
   { ADS_UF_NOT_DELEGATED,                            L"NOT_DELEGATED" },
   { ADS_UF_TRUSTED_FOR_DELEGATION,                   L"TRUSTED_FOR_DELEGATION" },
   { ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,   L"T2A4F" },

   { ADS_UF_TEMP_DUPLICATE_ACCOUNT,                   L"TEMP_DUPLICATE_ACCOUNT" },
   { ADS_UF_NORMAL_ACCOUNT,                           L"NORMAL_ACCOUNT" },
   { ADS_UF_INTERDOMAIN_TRUST_ACCOUNT,                L"INTERDOMAIN_ACCOUNT" },
   { ADS_UF_WORKSTATION_TRUST_ACCOUNT,                L"WORKSTATION_ACCOUNT" },
   { ADS_UF_SERVER_TRUST_ACCOUNT,                     L"SERVER_ACCOUNT" },
   { ADS_UF_PARTIAL_SECRETS_ACCOUNT,                  L"PARTIAL_SECRETS_ACCOUNT" },

   { ADS_UF_MNS_LOGON_ACCOUNT,                        L"MNS_LOGON_ACCOUNT" },
   { ADS_UF_NO_AUTH_DATA_REQUIRED,                    L"NO_AUTH_DATA_REQUIRED" },
   { ADS_UF_SCRIPT,                                   L"SCRIPT" },
   { ADS_UF_HOMEDIR_REQUIRED,                         L"HOMEDIR_REQUIRED" },

   { FILTER_FLAG, NULL }
};

#define FLAG_ATTR_REQ_PARTIAL_SET_MEMBER              0x00000002
#define FLAG_ATTR_IS_OPERATIONAL                      0x00000008
#define FLAG_SCHEMA_BASE_OBJECT                       0x00000010
#define FLAG_ATTR_IS_RDN                              0x00000020
#define FLAG_DISALLOW_MOVE_ON_DELETE                  0x02000000
CONST_TXT cSystemFlags [] =
{
   { (DWORD)ADS_SYSTEMFLAG_ATTR_NOT_REPLICATED,                L"NOT_REPLICATED/NC" },
   { FLAG_ATTR_REQ_PARTIAL_SET_MEMBER,                         L"PARTIAL_SET_MEMBER/DOMAIN" },
   { (DWORD)ADS_SYSTEMFLAG_ATTR_IS_CONSTRUCTED,                L"CONSTRUCTED/NOT_GC_REPLICATED" },
   { FLAG_ATTR_IS_OPERATIONAL,                                 L"OPERATIONAL" },
   { FLAG_SCHEMA_BASE_OBJECT,                                  L"BASE_OBJECT" },
   { FLAG_ATTR_IS_RDN,                                         L"RDN" },

   { FLAG_DISALLOW_MOVE_ON_DELETE,                             L"DISALLOW_MOVE_ON_DELETE" },
   { (DWORD)ADS_SYSTEMFLAG_DOMAIN_DISALLOW_MOVE,               L"DISALLOW_MOVE" },
   { (DWORD)ADS_SYSTEMFLAG_DOMAIN_DISALLOW_RENAME,             L"DISALLOW_RENAME" },
   { (DWORD)ADS_SYSTEMFLAG_CONFIG_ALLOW_LIMITED_MOVE,          L"ALLOW_LIMITED_MOVE" },
   { (DWORD)ADS_SYSTEMFLAG_CONFIG_ALLOW_MOVE,                  L"ALLOW_MOVE" },
   { (DWORD)ADS_SYSTEMFLAG_CONFIG_ALLOW_RENAME,                L"ALLOW_RENAME" },
   { (DWORD)ADS_SYSTEMFLAG_DISALLOW_DELETE,                    L"DISALLOW_DELETE" },

   { FILTER_FLAG, NULL }
};

#define fATTINDEX                0x1
#define fPDNTATTINDEX            0x2
#define fANR                     0x4
#define fPRESERVEONDELETE        0x8
#define fCOPY                    0x10
#define fTUPLEINDEX              0x20
#define fSUBTREEATTINDEX         0x40
#define fCONFIDENTIAL            0x80
#define fNEVERVALUEAUDIT         0x100
#define fRODCFilteredAttribute   0x200
#define fEXTENDEDLINKTRACKING    0x400
#define fBASEONLY                0x800
#define fPARTITIONSECRET         0x1000
CONST_TXT cSearchFlags[] =
{
   { fATTINDEX,                                    L"ATTINDEX" },
   { fPDNTATTINDEX,                                L"PDNTATTINDEX" },
   { fANR,                                         L"ANR" },
   { fPRESERVEONDELETE,                            L"PRESERVEONDELETE" },
   { fCOPY,                                        L"COPY" },
   { fTUPLEINDEX,                                  L"TUPLEINDEX" },
   { fSUBTREEATTINDEX,                             L"SUBTREEATTINDEX" },
   { fCONFIDENTIAL,                                L"CONFIDENTIAL" },
   { fNEVERVALUEAUDIT,                             L"NEVERVALUEAUDIT" },
   { fRODCFilteredAttribute,                       L"RODCFilteredAttribute" },
   { fEXTENDEDLINKTRACKING,                        L"EXTENDEDLINKTRACKING" },
   { fBASEONLY,                                    L"BASEONLY" },
   { fPARTITIONSECRET,                             L"PARTITIONSECRET" },
   { FILTER_FLAG, NULL }
};

#define FLAG_ATTR_IS_CRITICAL             0x1
CONST_TXT cSchemaFlagsEx[] =
{
   { FLAG_ATTR_IS_CRITICAL,                        L"IS_CRITICAL" },
   { FILTER_FLAG, NULL }
};

#define GROUP_TYPE_BUILTIN_LOCAL_GROUP    0x1
#define GROUP_TYPE_ACCOUNT_GROUP          0x2
#define GROUP_TYPE_RESOURCE_GROUP         0x4
#define GROUP_TYPE_UNIVERSAL_GROUP        0x8
#define GROUP_TYPE_APP_BASIC_GROUP        0x10
#define GROUP_TYPE_APP_QUERY_GROUP        0x20
#define GROUP_TYPE_SECURITY_ENABLED       0x80000000
CONST_TXT cGroupType[] =
{
   { GROUP_TYPE_BUILTIN_LOCAL_GROUP,               L"BUILTIN_LOCAL" },
   { GROUP_TYPE_ACCOUNT_GROUP,                     L"ACCOUNT" },
   { GROUP_TYPE_RESOURCE_GROUP,                    L"RESOURCE" },
   { GROUP_TYPE_UNIVERSAL_GROUP,                   L"UNIVERSAL" },
   { GROUP_TYPE_APP_BASIC_GROUP,                   L"APP_BASIC" },
   { GROUP_TYPE_APP_QUERY_GROUP,                   L"APP_QUERY" },
   { GROUP_TYPE_SECURITY_ENABLED,                  L"SECURITY_ENABLED" },
   { FILTER_FLAG, NULL }
};

#define DES_CBC_CRC                             0x1
#define DES_CBC_MD5                             0x2
#define RC4_HMAC                                0x4
#define AES128_CTS_HMAC_SHA1_96                 0x8
#define AES256_CTS_HMAC_SHA1_96                 0x10
#define FAST_supported                          0x10000
#define Compound_identity_supported             0x20000
#define Claims_supported                        0x40000
#define Resource_SID_compression_disabled       0x80000
CONST_TXT cSupportedEncryptionTypes[] =
{
   { DES_CBC_CRC,                               L"DES_CRC" },
   { DES_CBC_MD5,                               L"DES_MD5" },
   { RC4_HMAC,                                  L"RC4" },
   { AES128_CTS_HMAC_SHA1_96,                   L"AES128" },
   { AES256_CTS_HMAC_SHA1_96,                   L"AES256" },
   { Compound_identity_supported,               L"Compound" },
   { FAST_supported,                            L"FAST" },
   { Claims_supported,                          L"Claims" },
   { Resource_SID_compression_disabled,         L"SID_compression_disabled" },
   { FILTER_FLAG, NULL }
};

#define TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION           0x00000080
#ifndef TRUST_ATTRIBUTE_TREE_PARENT
#define TRUST_ATTRIBUTE_TREE_PARENT    0x00400000     // Denotes that we are setting the trust
                                                      // to our parent in the org tree
#endif // !TRUST_ATTRIBUTE_TREE_PARENT
#ifndef TRUST_ATTRIBUTE_TREE_ROOT
#define TRUST_ATTRIBUTE_TREE_ROOT      0x00800000     // Denotes that we are setting the trust
                                                      // to another tree root in a forest
#endif // !TRUST_ATTRIBUTE_TREE_ROOT

// Compatibility for SDK v7
#ifndef TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION
#define TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION 0x00000200       // do not forward TGT to the other side of the trust which is not part of this enterprise
#endif
#ifndef TRUST_ATTRIBUTE_PIM_TRUST
#define TRUST_ATTRIBUTE_PIM_TRUST      0x00000400     // Outgoing trust to a PIM forest.
#endif

CONST_TXT cTrustAttributes[] =
{
   { TRUST_ATTRIBUTE_NON_TRANSITIVE,                        L"NON_TRANSITIVE" },
   { TRUST_ATTRIBUTE_UPLEVEL_ONLY,                          L"UPLEVEL_ONLY" },
   { TRUST_ATTRIBUTE_QUARANTINED_DOMAIN,                    L"QUARANTINED_DOMAIN" },
   { TRUST_ATTRIBUTE_FOREST_TRANSITIVE,                     L"FOREST_TRANSITIVE" },
   { TRUST_ATTRIBUTE_CROSS_ORGANIZATION,                    L"CROSS_ORGANIZATION" },
   { TRUST_ATTRIBUTE_WITHIN_FOREST,                         L"WITHIN_FOREST" },
   { TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL,                     L"TREAT_AS_EXTERNAL" },
   { TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION,                   L"USES_RC4_ENCRYPTION" },
   { TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION,  L"CROSS_ORGANIZATION_NO_TGT_DELEGATION" },
   { TRUST_ATTRIBUTE_PIM_TRUST,                             L"PIM_TRUST" },
   { TRUST_ATTRIBUTE_TREE_PARENT,                           L"O_TREE_PARENT" },
   { TRUST_ATTRIBUTE_TREE_ROOT,                             L"O_TREE_ROOT" },
   { FILTER_FLAG, NULL }
};

CONST_TXT cTrustDirection[] =
{
   { TRUST_DIRECTION_INBOUND,                L"INBOUND" },
   { TRUST_DIRECTION_OUTBOUND,               L"OUTBOUND" },
   { TRUST_DIRECTION_BIDIRECTIONAL,          L"BIDIRECTIONAL" },
   { FILTER_TYPE, NULL }
};

CONST_TXT cTrustType[] =
{
   { TRUST_TYPE_DOWNLEVEL,                   L"DOWNLEVEL" },
   { TRUST_TYPE_UPLEVEL,                     L"UPLEVEL" },
   { TRUST_TYPE_MIT,                         L"MIT" },
   { FILTER_TYPE, NULL }
};
