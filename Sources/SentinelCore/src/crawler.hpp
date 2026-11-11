#ifndef SENTINEL_CRAWLER_HPP
#define SENTINEL_CRAWLER_HPP

#include "types.hpp"
#include "http_client.hpp"
#include <functional>

namespace sentinel {

class Crawler {
public:
    static CrawlData crawl(
        const ScanConfig& config,
        HttpClient& client,
        std::function<void(int endpoints_examined)> on_progress
    );
};

} // namespace sentinel

#endif /* SENTINEL_CRAWLER_HPP */
