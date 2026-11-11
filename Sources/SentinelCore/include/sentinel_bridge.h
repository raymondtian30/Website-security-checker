#ifndef SENTINEL_BRIDGE_H
#define SENTINEL_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SentinelEngineImpl* SentinelEngineHandle;

typedef void (*SentinelProgressCallback)(
    const char* progress_json,
    void* user_data
);

typedef void (*SentinelFindingCallback)(
    const char* finding_json,
    void* user_data
);

SentinelEngineHandle sentinel_engine_create(void);
void sentinel_engine_destroy(SentinelEngineHandle handle);

const char* sentinel_run_scan(
    SentinelEngineHandle handle,
    const char* config_json,
    SentinelProgressCallback progress_cb,
    SentinelFindingCallback finding_cb,
    void* user_data
);

void sentinel_pause_scan(SentinelEngineHandle handle);
void sentinel_resume_scan(SentinelEngineHandle handle);
void sentinel_cancel_scan(SentinelEngineHandle handle);

const char* sentinel_validate_url_scope(
    const char* config_json,
    const char* candidate_url
);

const char* sentinel_redact_text(const char* raw_text);

void sentinel_free_string(const char* str);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_BRIDGE_H */
