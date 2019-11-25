#ifndef TAR_H_
#define TAR_H_

#include <Windows.h>

/*
 * POSIX.1 - 1988 field size valuesand magic.
 */
#define TBLOCK          512
#define NAMSIZ          100
#define PFXSIZ          155

#define TMODLEN         8
#define TUIDLEN         8
#define TGIDLEN         8
#define TSIZLEN         12
#define TMTMLEN         12
#define TCKSLEN         8

#define TMAGIC          "ustar" /* ustar magic 6 chars + '\0' */
#define TMAGLEN         6       /* "ustar" including '\0' */
#define TVERSION        "00"
#define TVERSLEN        2
#define TUNMLEN         32
#define TGNMLEN         32
#define TDEVLEN         8

/*
* POSIX.1-1988 typeflag values
*/
#define REGTYPE         '0'     /* Regular File         */
#define AREGTYPE        '\0'    /* Regular File (outdated) */
#define LNKTYPE         '1'     /* Hard Link                    */
#define SYMTYPE         '2'     /* Symbolic Link                */
#define CHRTYPE         '3'     /* Character Special    */
#define BLKTYPE         '4'     /* Block Special                */
#define DIRTYPE         '5'     /* Directory                    */
#define FIFOTYPE        '6'     /* FIFO (named pipe)    */
#define CONTTYPE        '7'     /* Contiguous File              */

/*
* POSIX.1-2001 typeflag extensions.
* POSIX.1-2001 calls the extended USTAR format PAX although it is
* definitely derived from and based on USTAR. The reason may be that
* POSIX.1-2001 calls the tar program outdated and lists the
* pax program as the successor.
*/
#define LF_GHDR         'g'     /* POSIX.1-2001 global extended header */
#define LF_XHDR         'x'     /* POSIX.1-2001 extended header */

/*
   * star/gnu/Sun tar extensions:
   *
   * Note that the standards committee allows only capital A through
   * capital Z for user-defined expansion.  This means that defining
   * something as, say '8' is a *bad* idea.
   */
#define LF_ACL          'A'     /* Solaris Access Control List  */
#define LF_DUMPDIR      'D'     /* GNU dump dir                 */
#define LF_EXTATTR      'E'     /* Solaris Extended Attribute File      */
#define LF_META         'I'     /* Inode (metadata only) no file content */
#define LF_LONGLINK     'K'     /* NEXT file has a long linkname        */
#define LF_LONGNAME    'L'      /* NEXT file has a long name            */
#define LF_MULTIVOL     'M'     /* Continuation file rest to be skipped */
#define LF_NAMES        'N'     /* OLD GNU for names > 100 characters   */
#define LF_SPARSE       'S'     /* This is for sparse files             */
#define LF_VOLHDR       'V'     /* tape/volume header Ignore on extraction */
#define LF_VU_XHDR      'X'     /* POSIX.1-2001 xtended (Sun VU version) */

/*
* Definitions for the t_mode field
*/
#define TSUID           04000   /* Set UID on execution */
#define TSGID           02000   /* Set GID on execution */
#define TSVTX           01000   /* On directories, restricted deletion flag */
#define TUREAD          00400   /* Read by owner        */
#define TUWRITE         00200   /* Write by owner special */
#define TUEXEC          00100   /* Execute/search by owner */
#define TGREAD          00040   /* Read by group        */
#define TGWRITE         00020   /* Write by group       */
#define TGEXEC          00010   /* Execute/search by group */
#define TOREAD          00004   /* Read by other                */
#define TOWRITE         00002   /* Write by other               */
#define TOEXEC          00001   /* Execute/search by other */

#define TALLMODES       07777   /* The low 12 bits      */

/*
* This is the ustar (Posix 1003.1) header.
*/
// Unused
//struct tar_header {
//   char t_name[NAMSIZ];         /*   0 Filename                 */
//   char t_mode[8];              /* 100 Permissions              */
//   char t_uid[8];               /* 108 Numerical User ID        */
//   char t_gid[8];               /* 116 Numerical Group ID       */
//   char t_size[12];             /* 124 Filesize                 */
//   char t_mtime[12];            /* 136 st_mtime                 */
//   char t_chksum[8];            /* 148 Checksum                 */
//   char t_typeflag;             /* 156 Typ of File              */
//   char t_linkname[NAMSIZ];     /* 157 Target of Links          */
//   char t_magic[TMAGLEN];       /* 257 "ustar"                  */
//   char t_version[TVERSLEN];    /* 263 Version fixed to 00      */
//   char t_uname[TUNMLEN];       /* 265 User Name                */
//   char t_gname[TGNMLEN];       /* 297 Group Name               */
//   char t_devmajor[8];          /* 329 Major for devices        */
//   char t_devminor[8];          /* 337 Minor for devices        */
//   char t_prefix[PFXSIZ];       /* 345 Prefix for t_name        */
//                                /* 500 End                      */
//   char t_mfill[12];            /* 500 Filler up to 512         */
//};

/*
 * star header specific definitions
 */
#define STMAGIC         "tar"   /* star magic */
#define STMAGLEN        4       /* "tar" including '\0' */

/*
* This is the new (post Posix 1003.1-1988) xstar header
* defined in 1994.
*
* t_prefix[130]        is guaranteed to be ' ' to prevent ustar
*                              compliant implementations from failing.
* t_mfill & t_xmagic need to be zero for a 100% ustar compliant
*                              implementation, so setting t_xmagic to
*                              "tar" should be avoided in the future.
*
* A different method to recognize this format is to verify that
* t_prefix[130]                is equal to ' ' and
* t_atime[0]/t_ctime[0]        is an octal number and
* t_atime[11]                  is equal to ' ' and
* t_ctime[11]                  is equal to ' '.
*
* Note that t_atime[11]/t_ctime[11] may be changed in future.
*/
struct xstar_header {
   char t_name[NAMSIZ];         /*   0 Filename                 */
   char t_mode[8];              /* 100 Permissions              */
   char t_uid[8];               /* 108 Numerical User ID        */
   char t_gid[8];               /* 116 Numerical Group ID       */
   char t_size[12];             /* 124 Filesize                 */
   char t_mtime[12];            /* 136 st_mtime                 */
   char t_chksum[8];            /* 148 Checksum                 */
   char t_typeflag;             /* 156 Typ of File              */
   char t_linkname[NAMSIZ];     /* 157 Target of Links          */
   char t_magic[TMAGLEN];       /* 257 "ustar"                  */
   char t_version[TVERSLEN];    /* 263 Version fixed to 00      */
   char t_uname[TUNMLEN];       /* 265 User Name                */
   char t_gname[TGNMLEN];       /* 297 Group Name               */
   char t_devmajor[8];          /* 329 Major for devices        */
   char t_devminor[8];          /* 337 Minor for devices        */
   char t_prefix[PFXSIZ];       /* 345 Prefix for t_name        */
   char t_padding[12];
//   char t_atime[12];            /* 476 st_atime                 */
//   char t_ctime[12];            /* 488 st_ctime                 */
//   char t_mfill[8];             /* 500 Filler up to star magic  */
//   char t_xmagic[4];            /* 508 "tar"                    */
};

struct sparse {
   char t_offset[12];
   char t_numbytes[12];
};

#define SPARSE_EXT_HDR  21

struct xstar_ext_header {
   struct sparse t_sp[21];
   char t_isextended;
};

// Unused
//typedef union hblock {
//   char dummy[TBLOCK];
//   long ldummy[TBLOCK / sizeof (long)];      /* force long alignment */
//   struct tar_header       dbuf;
//   struct xstar_header     xstar_dbuf;
//   struct xstar_ext_header xstar_ext_dbuf;
//} TCB;

#endif /* TAR_H_ */