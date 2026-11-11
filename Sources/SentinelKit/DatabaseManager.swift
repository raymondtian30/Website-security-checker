import Foundation
import SQLite3

private let SQLITE_TRANSIENT_DESTRUCTOR = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

public final class DatabaseManager: @unchecked Sendable {
    private var db: OpaquePointer?
    private let lock = NSLock()
    public let databasePath: String

    public init(customPath: String? = nil) {
        if let customPath {
            self.databasePath = customPath
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            let dir = appSupport.appendingPathComponent("WebsiteSecurityChecker", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            self.databasePath = dir.appendingPathComponent("sentinel_history.sqlite3").path
        }
        openAndInitialize()
    }

    deinit {
        if let db {
            sqlite3_close(db)
        }
    }

    private func openAndInitialize() {
        lock.lock()
        defer { lock.unlock() }

        if sqlite3_open(databasePath, &db) == SQLITE_OK {
            let createScansSQL = """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                target_url TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                overall_score INTEGER NOT NULL,
                letter_grade TEXT NOT NULL,
                coverage_percent REAL NOT NULL,
                status TEXT NOT NULL,
                record_json TEXT NOT NULL
            );
            """
            let createAuditSQL = """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                action TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                authorized_confirmed INTEGER NOT NULL,
                details TEXT NOT NULL
            );
            """
            sqlite3_exec(db, createScansSQL, nil, nil, nil)
            sqlite3_exec(db, createAuditSQL, nil, nil, nil)
        }
    }

    public func saveScan(_ record: ScanRecord) throws {
        lock.lock()
        defer { lock.unlock() }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(record)
        guard let jsonString = String(data: data, encoding: .utf8) else { return }

        let sql = """
        INSERT OR REPLACE INTO scans
        (id, timestamp, target_url, target_domain, overall_score, letter_grade, coverage_percent, status, record_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw NSError(domain: "DatabaseManager", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to prepare saveScan statement."])
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, record.id.uuidString, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_double(stmt, 2, record.timestamp.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 3, record.targetURL, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_text(stmt, 4, record.targetDomain, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_int(stmt, 5, Int32(record.scoreBreakdown.overallScore))
        sqlite3_bind_text(stmt, 6, record.scoreBreakdown.letterGrade, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_double(stmt, 7, record.scoreBreakdown.coveragePercent)
        sqlite3_bind_text(stmt, 8, record.status, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_text(stmt, 9, jsonString, -1, SQLITE_TRANSIENT_DESTRUCTOR)

        if sqlite3_step(stmt) != SQLITE_DONE {
            throw NSError(domain: "DatabaseManager", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to execute saveScan."])
        }
    }

    public func loadAllScans() -> [ScanRecord] {
        lock.lock()
        defer { lock.unlock() }

        let sql = "SELECT record_json FROM scans ORDER BY timestamp DESC;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var results: [ScanRecord] = []

        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cStr = sqlite3_column_text(stmt, 0) {
                let jsonStr = String(cString: cStr)
                if let data = jsonStr.data(using: .utf8),
                   let record = try? decoder.decode(ScanRecord.self, from: data) {
                    results.append(record)
                }
            }
        }
        return results
    }

    public func toggleFindingResolved(scanID: UUID, findingID: String) throws -> ScanRecord? {
        let scans = loadAllScans()
        guard var scan = scans.first(where: { $0.id == scanID }) else { return nil }
        guard let idx = scan.findings.firstIndex(where: { $0.id == findingID }) else { return nil }

        scan.findings[idx].isResolved.toggle()
        let completedChecks = Int((scan.scoreBreakdown.coveragePercent / 100.0) * Double(max(1, scan.configuration.enabledCategories.count)).rounded())
        scan.scoreBreakdown = SecurityScorer.calculateScore(
            findings: scan.findings,
            completedChecks: max(1, completedChecks),
            totalChecks: max(1, scan.configuration.enabledCategories.count)
        )
        try saveScan(scan)
        return scan
    }

    public func deleteScan(id: UUID) {
        lock.lock()
        defer { lock.unlock() }

        let sql = "DELETE FROM scans WHERE id = ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id.uuidString, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_step(stmt)
    }

    public func logAuditEvent(_ entry: AuditLogEntry) {
        lock.lock()
        defer { lock.unlock() }

        let sql = """
        INSERT INTO audit_logs (id, timestamp, action, target_domain, authorized_confirmed, details)
        VALUES (?, ?, ?, ?, ?, ?);
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, entry.id.uuidString, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_double(stmt, 2, entry.timestamp.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 3, entry.action, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_text(stmt, 4, entry.targetDomain, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_bind_int(stmt, 5, entry.authorizedConfirmed ? 1 : 0)
        sqlite3_bind_text(stmt, 6, entry.details, -1, SQLITE_TRANSIENT_DESTRUCTOR)
        sqlite3_step(stmt)
    }

    public func loadAuditLogs(limit: Int = 200) -> [AuditLogEntry] {
        lock.lock()
        defer { lock.unlock() }

        let sql = "SELECT id, timestamp, action, target_domain, authorized_confirmed, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?;"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(limit))

        var logs: [AuditLogEntry] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let idStr = sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? UUID().uuidString
            let ts = sqlite3_column_double(stmt, 1)
            let action = sqlite3_column_text(stmt, 2).map { String(cString: $0) } ?? ""
            let domain = sqlite3_column_text(stmt, 3).map { String(cString: $0) } ?? ""
            let auth = sqlite3_column_int(stmt, 4) != 0
            let details = sqlite3_column_text(stmt, 5).map { String(cString: $0) } ?? ""

            logs.append(AuditLogEntry(
                id: UUID(uuidString: idStr) ?? UUID(),
                timestamp: Date(timeIntervalSince1970: ts),
                action: action,
                targetDomain: domain,
                authorizedConfirmed: auth,
                details: details
            ))
        }
        return logs
    }
}
