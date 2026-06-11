/* IoT Security Scanner - Dashboard JavaScript */

// ============================
// Scan Controls
// ============================

let scanPollInterval = null;

function startScan() {
    const btn = document.getElementById('start-scan-btn');
    const status = document.getElementById('scan-status');
    const scanType = document.getElementById('scan-type').value;

    btn.disabled = true;
    btn.textContent = 'Scanning...';
    status.textContent = 'Starting scan...';

    fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_type: scanType })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            status.textContent = 'Error: ' + data.error;
            btn.disabled = false;
            btn.textContent = 'Start New Scan';
            return;
        }
        // Start polling for status
        scanPollInterval = setInterval(pollScanStatus, 2000);
    })
    .catch(err => {
        status.textContent = 'Error: ' + err.message;
        btn.disabled = false;
        btn.textContent = 'Start New Scan';
    });
}

function pollScanStatus() {
    const btn = document.getElementById('start-scan-btn');
    const status = document.getElementById('scan-status');

    fetch('/api/scan/status')
    .then(response => response.json())
    .then(data => {
        status.textContent = data.progress || '';

        if (!data.running) {
            clearInterval(scanPollInterval);
            scanPollInterval = null;
            btn.disabled = false;
            btn.textContent = 'Start New Scan';

            // Reload page to show new results
            if (data.last_scan_id) {
                setTimeout(() => window.location.reload(), 1000);
            }
        }
    })
    .catch(() => {
        // Ignore polling errors
    });
}

// ============================
// Table Sorting
// ============================

let sortDirection = {};

function sortTable(columnIndex) {
    const table = document.getElementById('device-table');
    if (!table) return;

    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr.device-row'));

    if (rows.length === 0) return;

    // Toggle direction
    sortDirection[columnIndex] = !sortDirection[columnIndex];
    const ascending = sortDirection[columnIndex];

    rows.sort((a, b) => {
        let aVal = a.cells[columnIndex].textContent.trim();
        let bVal = b.cells[columnIndex].textContent.trim();

        // Numeric columns: Ports (4), Vulns (5), Risk Score (6)
        if ([4, 5, 6].includes(columnIndex)) {
            aVal = parseInt(aVal) || 0;
            bVal = parseInt(bVal) || 0;
            return ascending ? aVal - bVal : bVal - aVal;
        }

        // IP address column (0) - sort numerically by octets
        if (columnIndex === 0) {
            const aParts = aVal.split('.').map(Number);
            const bParts = bVal.split('.').map(Number);
            for (let i = 0; i < 4; i++) {
                if (aParts[i] !== bParts[i]) {
                    return ascending
                        ? aParts[i] - bParts[i]
                        : bParts[i] - aParts[i];
                }
            }
            return 0;
        }

        // String columns
        return ascending
            ? aVal.localeCompare(bVal)
            : bVal.localeCompare(aVal);
    });

    // Re-append in sorted order
    rows.forEach(row => tbody.appendChild(row));

    // Update header indicators
    const headers = table.querySelectorAll('th');
    headers.forEach((th, i) => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (i === columnIndex) {
            th.classList.add(ascending ? 'sort-asc' : 'sort-desc');
        }
    });
}

// ============================
// Table Filtering
// ============================

function filterDevices() {
    const filterText = document.getElementById('device-filter').value.toLowerCase();
    const riskFilter = document.getElementById('risk-filter').value.toLowerCase();
    const table = document.getElementById('device-table');

    if (!table) return;

    const rows = table.querySelectorAll('tbody tr.device-row');

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const riskBadge = row.querySelector('.badge');
        const riskLevel = riskBadge
            ? riskBadge.textContent.trim().toLowerCase()
            : '';

        const matchesText = !filterText || text.includes(filterText);
        const matchesRisk = !riskFilter || riskLevel === riskFilter;

        row.style.display = (matchesText && matchesRisk) ? '' : 'none';
    });
}

// ============================
// Initialization
// ============================

document.addEventListener('DOMContentLoaded', function() {
    // Check if a scan is already running on page load
    fetch('/api/scan/status')
    .then(response => response.json())
    .then(data => {
        if (data.running) {
            const btn = document.getElementById('start-scan-btn');
            const status = document.getElementById('scan-status');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Scanning...';
            }
            if (status) {
                status.textContent = data.progress || 'Scan in progress...';
            }
            scanPollInterval = setInterval(pollScanStatus, 2000);
        }
    })
    .catch(() => {
        // Ignore - status endpoint might not be available
    });
});
