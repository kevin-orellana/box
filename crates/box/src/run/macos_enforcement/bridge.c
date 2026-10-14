/* Apple owns every message. Rust borrows this fixed record during each call. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { BOX_OPEN = 1, BOX_CREATE, BOX_UNLINK, BOX_RENAME, BOX_TRUNCATE };
enum { BOX_AUTH = 1, BOX_NOTIFY, BOX_REPLY };
enum { BOX_FILE = 1, BOX_PARENT = 2 };
enum { BOX_PATH_CAPACITY = 4096 };

typedef struct {
    uint32_t kind, phase, flags, mode;
    uint64_t sequence, deadline;
    int32_t pid;
    uint32_t valid;
    uint64_t source_dev, source_ino, destination_dev, destination_ino;
    uint32_t source_identity, destination_identity, destination_exists, destination_mode, result;
    char path[BOX_PATH_CAPACITY], destination[BOX_PATH_CAPACITY];
} box_event;

typedef bool (*box_callback)(void *, const box_event *, int);
typedef struct {
    es_client_t *client;
    void *context;
    box_callback callback;
} box_client;

size_t box_es_event_size(void) { return sizeof(box_event); }
bool box_es_stop(void *raw);

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0

static bool copy_token(char *out, es_string_token_t token) {
    if (!token.data || token.length == 0 || token.length >= BOX_PATH_CAPACITY ||
        memchr(token.data, 0, token.length)) return false;
    memcpy(out, token.data, token.length);
    out[token.length] = 0;
    return true;
}

static bool file_path(char *out, const es_file_t *file) {
    return file && !file->path_truncated && copy_token(out, file->path);
}

static bool new_path(char *out, const es_file_t *directory, es_string_token_t leaf) {
    if (!file_path(out, directory) || !leaf.data || !leaf.length ||
        memchr(leaf.data, '/', leaf.length) || memchr(leaf.data, 0, leaf.length) ||
        (leaf.length == 1 && leaf.data[0] == '.') ||
        (leaf.length == 2 && memcmp(leaf.data, "..", 2) == 0)) return false;
    size_t length = strlen(out);
    size_t separator = length && out[length - 1] != '/' ? 1 : 0;
    if (leaf.length >= BOX_PATH_CAPACITY - length - separator) return false;
    if (separator) out[length++] = '/';
    memcpy(out + length, leaf.data, leaf.length);
    out[length + leaf.length] = 0;
    return true;
}

static bool source_file(box_event *out, const es_file_t *file, uint32_t identity) {
    if (!file) return false;
    out->source_dev = (uint32_t)file->stat.st_dev;
    out->source_ino = file->stat.st_ino;
    out->source_identity = identity;
    return file_path(out->path, file);
}

static bool decode(const es_message_t *message, box_event *out) {
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            out->kind = BOX_OPEN;
            out->flags = message->event.open.fflag;
            return source_file(out, message->event.open.file, BOX_FILE);
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            out->kind = BOX_TRUNCATE;
            return source_file(out, message->event.truncate.target, BOX_FILE);
        case ES_EVENT_TYPE_AUTH_UNLINK:
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            out->kind = BOX_UNLINK;
            out->mode = message->event.unlink.target->stat.st_mode;
            return source_file(out, message->event.unlink.target, BOX_FILE);
        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_NOTIFY_CREATE: {
            out->kind = BOX_CREATE;
            const es_event_create_t *event = &message->event.create;
            if (event->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                out->destination_exists = 1;
                out->mode = event->destination.existing_file->stat.st_mode;
                return source_file(out, event->destination.existing_file, BOX_FILE);
            }
            if (event->destination_type != ES_DESTINATION_TYPE_NEW_PATH) return false;
            out->mode = event->destination.new_path.mode;
            const es_file_t *parent = event->destination.new_path.dir;
            return source_file(out, parent, BOX_PARENT) &&
                new_path(out->path, parent, event->destination.new_path.filename);
        }
        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_NOTIFY_RENAME: {
            out->kind = BOX_RENAME;
            const es_event_rename_t *event = &message->event.rename;
            if (!source_file(out, event->source, BOX_FILE)) return false;
            if (event->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                out->destination_exists = 1;
                out->destination_dev = (uint32_t)event->destination.existing_file->stat.st_dev;
                out->destination_ino = event->destination.existing_file->stat.st_ino;
                out->destination_mode = event->destination.existing_file->stat.st_mode;
                out->destination_identity = BOX_FILE;
                return file_path(out->destination, event->destination.existing_file);
            }
            if (event->destination_type != ES_DESTINATION_TYPE_NEW_PATH) return false;
            const es_file_t *parent = event->destination.new_path.dir;
            out->destination_dev = (uint32_t)parent->stat.st_dev;
            out->destination_ino = parent->stat.st_ino;
            out->destination_identity = BOX_PARENT;
            return new_path(out->destination, parent, event->destination.new_path.filename);
        }
        default:
            return message->action_type == ES_ACTION_TYPE_NOTIFY;
    }
}

static void receive(box_client *owner, es_client_t *client, const es_message_t *message) {
    box_event event = {0};
    event.phase = message->action_type == ES_ACTION_TYPE_AUTH ? BOX_AUTH : BOX_NOTIFY;
    event.pid = audit_token_to_pid(message->process->audit_token);
    event.deadline = message->deadline;
    /* Version four supplies the global sequence number on this macOS 27 path. */
    event.sequence = message->version >= 4 ? message->global_seq_num : 0;
    event.valid = message->version >= 4 && decode(message, &event);
    if (event.phase == BOX_NOTIFY) {
        /* This is an authorization result, not proof of syscall completion. */
        event.result = message->action.notify.result_type;
        owner->callback(owner->context, &event, 0);
        return;
    }
    bool allow = owner->callback(owner->context, &event, 0);
    if (mach_absolute_time() >= event.deadline) allow = false;
    es_respond_result_t result;
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
        result = es_respond_flags_result(client, message, allow ? event.flags : 0, false);
    } else {
        result = es_respond_auth_result(client, message,
            allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
    }
    event.phase = BOX_REPLY;
    owner->callback(owner->context, &event, result == ES_RESPOND_RESULT_SUCCESS ? 0 : 1);
}

static const es_event_type_t subscriptions[] = {
    ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_CREATE,
    ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_TRUNCATE,
    ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CREATE,
    ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_TRUNCATE,
    ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_WRITE
};

/* Negative errors belong to this bridge. Positive errors are es_new_client_result_t. */
void *box_es_start(void *context, box_callback callback, int *error) {
    *error = -1;
    if (__builtin_available(macOS 27.0, *)) {
        box_client *owner = calloc(1, sizeof(*owner));
        if (!owner) { *error = -2; return NULL; }
        owner->context = context;
        owner->callback = callback;
        *error = es_new_descendants_client(&owner->client,
            ^(es_client_t *client, const es_message_t *message) { receive(owner, client, message); });
        if (*error != ES_NEW_CLIENT_RESULT_SUCCESS) { free(owner); return NULL; }
        es_deadline_miss_mode_t mode;
        if (es_set_deadline_miss_mode(owner->client, ES_DEADLINE_MISS_MODE_FAIL_CLOSED) != ES_RETURN_SUCCESS ||
            es_get_deadline_miss_mode(owner->client, &mode) != ES_RETURN_SUCCESS ||
            mode != ES_DEADLINE_MISS_MODE_FAIL_CLOSED) {
            *error = -3;
            es_delete_client(owner->client);
            free(owner);
            return NULL;
        }
        size_t expected = sizeof(subscriptions) / sizeof(subscriptions[0]);
        es_event_type_t *actual = NULL;
        size_t count = 0;
        bool valid = es_subscribe(owner->client, subscriptions, (uint32_t)expected) == ES_RETURN_SUCCESS &&
            es_subscriptions(owner->client, &count, &actual) == ES_RETURN_SUCCESS && count == expected;
        for (size_t i = 0; valid && i < expected; ++i) {
            bool found = false;
            for (size_t j = 0; j < count; ++j) found |= subscriptions[i] == actual[j];
            valid &= found;
        }
        free(actual);
        if (!valid) {
            *error = -4;
            /* Drain even supervisor notifications before releasing Rust's context. */
            if (!box_es_stop(owner)) abort();
            return NULL;
        }
        *error = 0;
        return owner;
    }
    return NULL;
}

bool box_es_stop(void *raw) {
    if (__builtin_available(macOS 27.0, *)) {
        box_client *owner = raw;
        if (es_unsubscribe_all(owner->client) != ES_RETURN_SUCCESS) return false;
        dispatch_semaphore_t drained = dispatch_semaphore_create(0);
        if (es_sync_client(owner->client, ^{ dispatch_semaphore_signal(drained); }) != ES_RETURN_SUCCESS) {
            dispatch_release(drained);
            return false;
        }
        /* The marker drains handlers before context destruction. */
        dispatch_semaphore_wait(drained, DISPATCH_TIME_FOREVER);
        dispatch_release(drained);
        if (es_delete_client(owner->client) != ES_RETURN_SUCCESS) return false;
        free(owner);
        return true;
    }
    return false;
}

#else

void *box_es_start(void *context, box_callback callback, int *error) {
    (void)context;
    (void)callback;
    *error = -5;
    return NULL;
}

bool box_es_stop(void *raw) {
    (void)raw;
    return false;
}

#endif
