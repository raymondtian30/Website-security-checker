#include "sentinel_bridge.h"
#include "engine.hpp"
#include "redactor.hpp"
#include "scope_guard.hpp"
#include <cstring>
#include <sstream>

struct SentinelEngineImpl {
    sentinel::Engine engine;
};

static const char* heap_dup_string(const std::string& s) {
    char* out = new char[s.size() + 1];
    std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

extern "C" {

SentinelEngineHandle sentinel_engine_create(void) {
    return new SentinelEngineImpl();
}

void sentinel_engine_destroy(SentinelEngineHandle handle) {
    delete handle;
}

const char* sentinel_run_scan(
    SentinelEngineHandle handle,
    const char* config_json,
    SentinelProgressCallback progress_cb,
    SentinelFindingCallback finding_cb,
    void* user_data
) {
    if (!handle || !config_json) {
        return heap_dup_string("{\"success\":false,\"status\":\"Failed\",\"error\":\"Invalid engine handle or config\"}");
    }

    sentinel::ScanConfig cfg = sentinel::Engine::parse_config_json(config_json);
    std::string res = handle->engine.run_scan(
        cfg,
        [&](const std::string& p_json) {
            if (progress_cb) progress_cb(p_json.c_str(), user_data);
        },
        [&](const std::string& f_json) {
            if (finding_cb) finding_cb(f_json.c_str(), user_data);
        }
    );
    return heap_dup_string(res);
}

void sentinel_pause_scan(SentinelEngineHandle handle) {
    if (handle) handle->engine.pause();
}

void sentinel_resume_scan(SentinelEngineHandle handle) {
    if (handle) handle->engine.resume();
}

void sentinel_cancel_scan(SentinelEngineHandle handle) {
    if (handle) handle->engine.cancel();
}

const char* sentinel_validate_url_scope(
    const char* config_json,
    const char* candidate_url
) {
    sentinel::ScanConfig cfg = sentinel::Engine::parse_config_json(config_json ? config_json : "{}");
    sentinel::ScopeValidationResult res = sentinel::ScopeGuard::validate_url(cfg, candidate_url ? candidate_url : "");
    std::ostringstream oss;
    oss << "{"
        << "\"allowed\":" << (res.allowed ? "true" : "false") << ","
        << "\"reason\":\"" << sentinel::json_escape(res.reason) << "\","
        << "\"resolvedIP\":\"" << sentinel::json_escape(res.resolved_ip) << "\""
        << "}";
    return heap_dup_string(oss.str());
}

const char* sentinel_redact_text(const char* raw_text) {
    std::string redacted = sentinel::Redactor::redact(raw_text ? raw_text : "");
    return heap_dup_string(redacted);
}

void sentinel_free_string(const char* str) {
    delete[] str;
}

} // extern "C"
