/**
 * KernLock Security - Apple EndpointSecurity (ESF) System Extension Client
 * Implementation: es_new_client subscription, AUTH_EXEC and AUTH_OPEN callback handling,
 * length-safe token parsing, deadline enforcement, and IPC verdict dispatch.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

#define KERNLOCK_DAEMON_SOCKET_PATH "/var/run/kernlock/kernlock.sock"
#define FALLBACK_SOCKET_PATH       "/tmp/kernlock.sock"

// Operational mode (can be updated via daemon IPC)
typedef enum {
    MODE_AUDIT = 0,
    MODE_PROTECTION = 1,
    MODE_STRICT = 2
} kernlock_mode_t;

static es_client_t *g_client = NULL;
static kernlock_mode_t g_current_mode = MODE_PROTECTION;

/**
 * Length-safe extraction of es_string_token_t into a null-terminated buffer.
 * Note: es_string_token_t.data is NOT guaranteed to be null-terminated by ESF.
 */
static void extract_token_string(const es_string_token_t *token, char *out_buf, size_t max_size) {
    if (token == NULL || token->data == NULL || max_size == 0) {
        if (max_size > 0) out_buf[0] = '\0';
        return;
    }
    size_t copy_len = token->length < (max_size - 1) ? token->length : (max_size - 1);
    memcpy(out_buf, token->data, copy_len);
    out_buf[copy_len] = '\0';
}

/**
 * Query KernLock user-mode daemon via Unix Domain Socket for verdict.
 * Returns:
 *   1 = Block / Deny
 *   0 = Allow
 *  -1 = Communication error / Daemon unreachable
 */
static int query_daemon_verdict(const char *path, pid_t pid, pid_t ppid, int is_exec) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    // Set 250ms socket timeout to respect EndpointSecurity deadline
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, KERNLOCK_DAEMON_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // Try fallback socket path in /tmp
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, FALLBACK_SOCKET_PATH, sizeof(addr.sun_path) - 1);
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            return -1;
        }
    }

    // Format query JSON
    char request_json[2048];
    snprintf(request_json, sizeof(request_json),
             "{\"action\":\"eval_es\",\"path\":\"%s\",\"pid\":%d,\"ppid\":%d,\"is_exec\":%s}\n",
             path, pid, ppid, is_exec ? "true" : "false");

    if (write(sock, request_json, strlen(request_json)) <= 0) {
        close(sock);
        return -1;
    }

    char response_buf[512];
    ssize_t bytes_read = read(sock, response_buf, sizeof(response_buf) - 1);
    close(sock);

    if (bytes_read <= 0) {
        return -1;
    }

    response_buf[bytes_read] = '\0';
    if (strstr(response_buf, "\"verdict\":\"block\"") != NULL ||
        strstr(response_buf, "\"verdict\":\"deny\"") != NULL) {
        return 1;
    }

    return 0;
}

/**
 * Check if the deadline for this message is imminent.
 * Returns true if less than 50ms remains before message->deadline.
 */
static int is_deadline_imminent(const es_message_t *message) {
    if (message == NULL || message->deadline == 0) {
        return 0;
    }

    uint64_t current = mach_absolute_time();
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);

    // Convert nanoseconds margin (50ms = 50,000,000 ns) to Mach absolute time units
    uint64_t margin_mach = (50000000ULL * timebase.denom) / timebase.numer;

    if (current + margin_mach >= message->deadline) {
        return 1;
    }
    return 0;
}

/**
 * Handle ES_EVENT_TYPE_AUTH_EXEC
 */
static void handle_auth_exec(es_client_t *client, const es_message_t *message) {
    if (message == NULL || client == NULL) return;

    // Check deadline expiration
    if (is_deadline_imminent(message)) {
        // Protection mode fails open, Strict mode fails closed
        es_auth_result_t fallback = (g_current_mode == MODE_STRICT) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW;
        es_respond_auth_result(client, message, fallback, false);
        return;
    }

    const es_process_t *target_process = message->event.exec.target;
    if (target_process == NULL || target_process->executable == NULL) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    // Apple platform binaries are trusted and cached
    if (target_process->is_platform_binary) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
        return;
    }

    char executable_path[PATH_MAX];
    extract_token_string(&target_process->executable->path, executable_path, sizeof(executable_path));

    pid_t pid = audit_token_to_pid(target_process->audit_token);
    pid_t ppid = audit_token_to_ppid(target_process->audit_token);

    if (g_current_mode == MODE_AUDIT) {
        // In Audit mode, observe and allow
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    int verdict = query_daemon_verdict(executable_path, pid, ppid, 1);

    if (verdict == 1) {
        // Block execution attempt
        printf("[KernLock ES] BLOCKED execution: %s (PID: %d, PPID: %d)\n", executable_path, pid, ppid);
        es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false);
    } else if (verdict == 0) {
        // Clean binary verified
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
    } else {
        // Daemon unreachable / timeout fallback
        es_auth_result_t fallback = (g_current_mode == MODE_STRICT) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW;
        es_respond_auth_result(client, message, fallback, false);
    }
}

/**
 * Handle ES_EVENT_TYPE_AUTH_OPEN
 */
static void handle_auth_open(es_client_t *client, const es_message_t *message) {
    if (message == NULL || client == NULL) return;

    if (is_deadline_imminent(message)) {
        es_auth_result_t fallback = (g_current_mode == MODE_STRICT) ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW;
        es_respond_auth_result(client, message, fallback, false);
        return;
    }

    if (message->process != NULL && message->process->is_platform_binary) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
        return;
    }

    if (message->event.open.file == NULL) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    char file_path[PATH_MAX];
    extract_token_string(&message->event.open.file->path, file_path, sizeof(file_path));

    pid_t pid = audit_token_to_pid(message->process->audit_token);
    pid_t ppid = audit_token_to_ppid(message->process->audit_token);

    if (g_current_mode == MODE_AUDIT) {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        return;
    }

    int verdict = query_daemon_verdict(file_path, pid, ppid, 0);

    if (verdict == 1) {
        printf("[KernLock ES] BLOCKED file open: %s (PID: %d)\n", file_path, pid);
        es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false);
    } else {
        es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, verdict == 0);
    }
}

int main(int argc, const char * argv[]) {
    printf("[KernLock ES] Initializing Apple EndpointSecurity client...\n");

    es_new_client_result_t result = es_new_client(&g_client, ^(es_client_t *client, const es_message_t *message) {
        switch (message->event_type) {
            case ES_EVENT_TYPE_AUTH_EXEC:
                handle_auth_exec(client, message);
                break;
            case ES_EVENT_TYPE_AUTH_OPEN:
                handle_auth_open(client, message);
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

    // Subscribe to pre-execution and pre-open authorization events
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN
    };

    if (es_subscribe(g_client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "[KernLock ES] Failed to subscribe to ES events.\n");
        es_delete_client(g_client);
        return 1;
    }

    printf("[KernLock ES] Client active and monitoring execution and file open authorization events.\n");
    dispatch_main();
    return 0;
}
