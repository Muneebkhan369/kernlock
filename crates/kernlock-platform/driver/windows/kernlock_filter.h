/**
 * KernLock Security - Windows Filesystem Minifilter Driver (FLTMGR)
 * Header Definition: Structures and Communication Protocols
 */

#ifndef KERNLOCK_FILTER_H
#define KERNLOCK_FILTER_H

#define KERNLOCK_FILTER_PORT_NAME     L"\\KernLockFilterPort"
#define KERNLOCK_FILTER_ALTITUDE      L"325000"

typedef enum _EXECUTION_VERDICT {
    VerdictAllow = 0,
    VerdictBlock = 1,
    VerdictAudit = 2
} EXECUTION_VERDICT;

typedef struct _KERNLOCK_PORT_CONTEXT {
    unsigned long StrictMode; // 1 for Strict mode (fail-closed on disconnect/timeout), 0 for Protection/Audit
} KERNLOCK_PORT_CONTEXT, *PKERNLOCK_PORT_CONTEXT;

#pragma pack(push, 1)

typedef struct _MINIFILTER_MSG_HEADER {
    unsigned __int64 MessageId;
    unsigned long    ProcessId;
    unsigned long    ThreadId;
    unsigned __int64 Timestamp;
} MINIFILTER_MSG_HEADER, *PMINIFILTER_MSG_HEADER;

typedef struct _EXECUTION_REQUEST_MSG {
    MINIFILTER_MSG_HEADER Header;
    unsigned long         DesiredAccess;
    unsigned long         ParentProcessId;
    unsigned __int64      FileId;
    unsigned long         VolumeSerialNumber;
    wchar_t               FilePath[1024];
} EXECUTION_REQUEST_MSG, *PEXECUTION_REQUEST_MSG;

typedef struct _EXECUTION_RESPONSE_MSG {
    unsigned __int64  MessageId;
    EXECUTION_VERDICT Verdict;
    unsigned long     NtStatus;
    char              Reason[256];
} EXECUTION_RESPONSE_MSG, *PEXECUTION_RESPONSE_MSG;

#pragma pack(pop)

#endif // KERNLOCK_FILTER_H
