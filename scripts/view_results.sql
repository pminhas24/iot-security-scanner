-- IoT Security Scanner - Results Viewer
-- PostgreSQL: psql -d iot_scanner -f scripts/view_results.sql
-- SQLite:     sqlite3 iot_scanner.db < scripts/view_results.sql

-- Latest Scan Summary
SELECT '=== Latest Scan Summary ===' AS section;
SELECT scan_id, scan_timestamp, network_range, scan_type,
       devices_found, duration_sec
FROM scans
ORDER BY scan_timestamp DESC
LIMIT 1;

-- Device Risk Overview
SELECT '=== Device Risk Overview ===' AS section;
SELECT d.ip_address, d.hostname, d.vendor, d.device_type,
       d.risk_score, d.risk_level,
       COUNT(v.vuln_id) AS vuln_count
FROM devices d
LEFT JOIN vulnerabilities v ON d.device_id = v.device_id
WHERE d.scan_id = (SELECT MAX(scan_id) FROM scans)
GROUP BY d.device_id, d.ip_address, d.hostname, d.vendor,
         d.device_type, d.risk_score, d.risk_level
ORDER BY d.risk_score DESC;

-- Critical & High Vulnerabilities
SELECT '=== Critical & High Vulnerabilities ===' AS section;
SELECT d.ip_address, d.device_type, v.vuln_type, v.severity, v.details
FROM vulnerabilities v
JOIN devices d ON v.device_id = d.device_id
WHERE v.severity IN ('critical', 'high')
  AND d.scan_id = (SELECT MAX(scan_id) FROM scans)
ORDER BY
    CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 END,
    d.ip_address;

-- Risk Distribution
SELECT '=== Risk Distribution ===' AS section;
SELECT risk_level, COUNT(*) AS device_count
FROM devices
WHERE scan_id = (SELECT MAX(scan_id) FROM scans)
GROUP BY risk_level
ORDER BY
    CASE risk_level
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;

-- Open Dangerous Ports
SELECT '=== Dangerous Open Ports ===' AS section;
SELECT d.ip_address, d.device_type, p.port, p.service,
       p.severity, p.danger_reason
FROM open_ports p
JOIN devices d ON p.device_id = d.device_id
WHERE p.is_dangerous = 1
  AND d.scan_id = (SELECT MAX(scan_id) FROM scans)
ORDER BY p.severity, d.ip_address;
