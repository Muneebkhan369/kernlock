/**
 * KernLock Security - Apple EndpointSecurity (ESF) Client
 * Implementation: es_new_client subscription, AUTH_EXEC callback handling, and verdict dispatch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dispatch/dispatch.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

static es_client_t *g_client = NULL;

static void handle_auth_exec(es_client_t *client, const es_message_t *message) {
    if (message == NULL || message->event_type != ES_EVENT_TYPE_AUTH_EXEC) {
        return;
    }

    const es_process_t *target_process = message->event.exec.target;
    const char *executable_path = target_process->executable->path.data;
    pid_t pid = audit_token_to_pid(target_process->audit_token);
    pid_t ppid = audit_token_to_ppid(target_process->audit_token);

    // Platform binaries (signed by Apple) can be allowed with cache
    if (target_process->is_platform_binary) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
        return;
    }

    // Example safety check: If path contains known test malware pattern, deny execution
    if (strstr(executable_path, "malicious_binary") != NULL) {
        printf("[KernLock ES] Blocked execution of %s (PID: %d, PPID: %d)\n", executable_path, pid, ppid);
        es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false);
        return;
    }

    // Default: Allow clean binaries and cache decision
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
}

int main(int argc, const char * argv[]) {
    es_new_client_result_t result;

    printf("[KernLock ES] Initializing Apple EndpointSecurity client...\n");

    result = es_new_client(&g_client, ^(es_client_t *client, const es_message_t *message) {
        switch (message->event_type) {
            case ES_EVENT_TYPE_AUTH_EXEC:
                handle_auth_exec(client, message);
                break;
            default:
                break;
        }
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "[KernLock ES] Failed to create EndpointSecurity client (Error code: %d)\n", result);
        if (result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED) {
            fprintf(stderr, "[KernLock ES] Error: Application lacks Full Disk Access or System Extension authorization.\n");
        } else if (result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED) {
            fprintf(stderr, "[KernLock ES] Error: Application lacks 'com.apple.developer.endpoint-security.client' entitlement.\n");
        } else if (result == ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED) {
            fprintf(stderr, "[KernLock ES] Error: Must be run as root (superuser).\n");
        }
        return 1;
    }

    // Subscribe to pre-execution authorization events
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT
    };

    if (es_subscribe(g_client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "[KernLock ES] Failed to subscribe to ES events.\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("[KernLock ES] Client active and monitoring execution events.\n");
    dispatch_main();
    return 0;
}
