#ifndef SENTINEL_ENGINE_HPP
#define SENTINEL_ENGINE_HPP

#include "types.hpp"
#include <atomic>
#include <functional>
#include <string>

namespace sentinel {

class Engine {
public:
    Engine();

    std::string run_scan(
        const ScanConfig& config,
        std::function<void(const std::string&)> on_progress_json,
        std::function<void(const std::string&)> on_finding_json
    );

    void pause();
    void resume();
    void cancel();

    static ScanConfig parse_config_json(const std::string& json);
    static std::string serialize_finding_json(const Finding& f);
    static std::string serialize_progress_json(const ScanProgress& p);

private:
    std::atomic<bool> cancel_flag_{false};
    std::atomic<bool> pause_flag_{false};
};

} // namespace sentinel

#endif /* SENTINEL_ENGINE_HPP */
