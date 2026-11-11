#ifndef SENTINEL_REDACTOR_HPP
#define SENTINEL_REDACTOR_HPP

#include <string>

namespace sentinel {

class Redactor {
public:
    static std::string redact(const std::string& input, size_t max_length = 1200);
    static std::string redact_cookie_header(const std::string& set_cookie_line);
};

} // namespace sentinel

#endif /* SENTINEL_REDACTOR_HPP */
