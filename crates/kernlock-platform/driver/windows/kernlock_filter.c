/**
 * KernLock Security - Windows Filesystem Minifilter Driver (FLTMGR)
 * Implementation: Pre-operation execution interception and user-mode verdict communication.
 *
 * Compilation with Windows Driver Kit (WDK):
 *   1. Install Windows Driver Kit (WDK) 10/11 and Visual Studio Build Tools.
 *   2. Build driver using MSBuild:
 *      msbuild kernlock_filter.vcxproj /p:Configuration=Release /p:Platform=x64
 *   3. Driver Altitude:
 *      Altitude 325000 belongs to the Microsoft Filter Manager load order band
 *      "FSFilter Anti-Virus" (320000 - 329999).
 *      For testing: bcdedit /set testsigning on, then sign with a test certificate.
 *      For production: request assigned altitude from Microsoft (fsfilt@microsoft.com)
 *      and sign via Microsoft Partner Center WHQL attestation.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "kernlock_filter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

PFLT_FILTER g_FilterHandle = NULL;
PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;
static volatile LONG g_MessageCounter = 0;

// Forward declarations
FLT_PREOP_CALLBACK_STATUS
KernLockPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
KernLockPreAcquireForSectionSynchronization (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
KernLockFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      KernLockPreCreate,
      NULL },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      KernLockPreAcquireForSectionSynchronization,
      NULL },

    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,         //  Version
    0,                                //  Flags
    NULL,                             //  Context
    Callbacks,                        //  Operation callbacks
    KernLockFilterUnload,             //  FilterUnload
    NULL,                             //  InstanceSetup
    NULL,                             //  InstanceQueryTeardown
    NULL,                             //  InstanceTeardownStart
    NULL,                             //  InstanceTeardownComplete
    NULL,                             //  GenerateFileName
    NULL,                             //  NormalizeNameComponent
    NULL                              //  NormalizeContextCleanup
};

NTSTATUS
KernLockPortConnectNotify (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    g_ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID
KernLockPortDisconnectNotify (
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (g_ClientPort != NULL) {
        FltCloseClientPort(g_FilterHandle, &g_ClientPort);
        g_ClientPort = NULL;
    }
}

FLT_PREOP_CALLBACK_STATUS
KernLockPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    EXECUTION_REQUEST_MSG requestMsg;
    EXECUTION_RESPONSE_MSG responseMsg;
    ULONG replyLength = sizeof(EXECUTION_RESPONSE_MSG);
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only intercept user-mode execution requests
    if (Data->RequestorMode != UserMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Check if execution access was requested (FILE_EXECUTE or GENERIC_EXECUTE)
    ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (!(desiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // If no client (daemon) is connected to our communication port, allow (fail-open)
    if (g_ClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    // Populate request message
    RtlZeroMemory(&requestMsg, sizeof(EXECUTION_REQUEST_MSG));
    requestMsg.Header.MessageId = (unsigned __int64)InterlockedIncrement(&g_MessageCounter);
    requestMsg.Header.ProcessId = (unsigned long)(ULONG_PTR)PsGetCurrentProcessId();
    requestMsg.Header.ThreadId = (unsigned long)(ULONG_PTR)PsGetCurrentThreadId();
    requestMsg.DesiredAccess = desiredAccess;

    // Secure File ID extraction to eliminate user-mode TOCTOU path races
    if (FltObjects->FileObject != NULL && FltObjects->Instance != NULL) {
        FILE_INTERNAL_INFORMATION internalInfo;
        RtlZeroMemory(&internalInfo, sizeof(FILE_INTERNAL_INFORMATION));
        if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance,
                                               FltObjects->FileObject,
                                               &internalInfo,
                                               sizeof(FILE_INTERNAL_INFORMATION),
                                               FileInternalInformation,
                                               NULL))) {
            requestMsg.FileId = (unsigned __int64)internalInfo.IndexNumber.QuadPart;
        }
    }

    if (nameInfo->Name.Length < sizeof(requestMsg.FilePath)) {
        RtlCopyMemory(requestMsg.FilePath, nameInfo->Name.Buffer, nameInfo->Name.Length);
    }
    FltReleaseFileNameInformation(nameInfo);

    // 500ms timeout for verdict evaluation
    timeout.QuadPart = -5000000; // 500ms in 100ns units

    status = FltSendMessage(g_FilterHandle,
                            &g_ClientPort,
                            &requestMsg,
                            sizeof(EXECUTION_REQUEST_MSG),
                            &responseMsg,
                            &replyLength,
                            &timeout);

    // CRITICAL: STATUS_TIMEOUT (0x00000102) is a success-class NTSTATUS (>= 0).
    // Testing with NT_SUCCESS(status) would evaluate to TRUE on timeout, reading
    // uninitialized responseMsg memory! We must explicitly check status == STATUS_SUCCESS.
    if (status == STATUS_SUCCESS) {
        if (replyLength >= sizeof(EXECUTION_RESPONSE_MSG) &&
            responseMsg.MessageId == requestMsg.Header.MessageId) {
            if (responseMsg.Verdict == VerdictBlock) {
                // Block execution attempt with ACCESS_DENIED
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
    } else if (status == STATUS_TIMEOUT) {
        // Explicit timeout handling: fail-open by default to avoid freezing system processes
    }

    // Default to allow on timeout or clean verdict
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
KernLockPreAcquireForSectionSynchronization (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    EXECUTION_REQUEST_MSG requestMsg;
    EXECUTION_RESPONSE_MSG responseMsg;
    ULONG replyLength = sizeof(EXECUTION_RESPONSE_MSG);
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only intercept user-mode requests
    if (Data->RequestorMode != UserMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Intercept section creation for executable mapping (SyncTypeCreateSection)
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Verify if executable memory protection was requested
    ULONG pageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if (!(pageProtection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // If no client (daemon) is connected to our communication port, allow (fail-open)
    if (g_ClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data,
                                       FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                                       &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FltParseFileNameInformation(nameInfo);

    RtlZeroMemory(&requestMsg, sizeof(EXECUTION_REQUEST_MSG));
    requestMsg.Header.MessageId = (unsigned __int64)InterlockedIncrement(&g_MessageCounter);
    requestMsg.Header.ProcessId = (unsigned long)(ULONG_PTR)PsGetCurrentProcessId();
    requestMsg.Header.ThreadId = (unsigned long)(ULONG_PTR)PsGetCurrentThreadId();
    requestMsg.DesiredAccess = pageProtection;

    // Secure File ID extraction for section synchronization
    if (FltObjects->FileObject != NULL && FltObjects->Instance != NULL) {
        FILE_INTERNAL_INFORMATION internalInfo;
        RtlZeroMemory(&internalInfo, sizeof(FILE_INTERNAL_INFORMATION));
        if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance,
                                               FltObjects->FileObject,
                                               &internalInfo,
                                               sizeof(FILE_INTERNAL_INFORMATION),
                                               FileInternalInformation,
                                               NULL))) {
            requestMsg.FileId = (unsigned __int64)internalInfo.IndexNumber.QuadPart;
        }
    }

    if (nameInfo->Name.Length < sizeof(requestMsg.FilePath)) {
        RtlCopyMemory(requestMsg.FilePath, nameInfo->Name.Buffer, nameInfo->Name.Length);
    }
    FltReleaseFileNameInformation(nameInfo);

    // 500ms timeout for verdict evaluation
    timeout.QuadPart = -5000000; // 500ms in 100ns units

    status = FltSendMessage(g_FilterHandle,
                            &g_ClientPort,
                            &requestMsg,
                            sizeof(EXECUTION_REQUEST_MSG),
                            &responseMsg,
                            &replyLength,
                            &timeout);

    if (status == STATUS_SUCCESS) {
        if (replyLength >= sizeof(EXECUTION_RESPONSE_MSG) &&
            responseMsg.MessageId == requestMsg.Header.MessageId) {
            if (responseMsg.Verdict == VerdictBlock) {
                // Block executable section creation with ACCESS_DENIED
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
KernLockFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    if (g_ServerPort != NULL) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, KERNLOCK_FILTER_PORT_NAME);
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    InitializeObjectAttributes(&oa,
                               &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               sd);

    status = FltCreateCommunicationPort(g_FilterHandle,
                                        &g_ServerPort,
                                        &oa,
                                        NULL,
                                        KernLockPortConnectNotify,
                                        KernLockPortDisconnectNotify,
                                        NULL,
                                        1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(g_ServerPort);
        FltUnregisterFilter(g_FilterHandle);
    }

    return status;
}
