function toggleSettings() {
  const panel = document.getElementById('settings-panel');
  panel.classList.toggle('hidden');
  if (!panel.classList.contains('hidden')) {
    _loadSettings();
  }
}

function _loadSettings() {
  fetch('/api/settings')
    .then(r => r.json())
    .then(s => {
      document.getElementById('setting-subnet').value = s.subnet || '';
      document.getElementById('setting-depth').value = s.scan_depth || 'full';
      document.getElementById('setting-ports').value = s.custom_ports || '';
      document.getElementById('setting-dryrun').checked = !!s.dry_run;
      if (!s.subnet) {
        fetch('/api/network/detect')
          .then(r => r.json())
          .then(d => {
            if (d.subnet) document.getElementById('setting-subnet').value = d.subnet;
          });
      }
    });
}

function saveSettings(e) {
  e.preventDefault();
  const settings = {
    subnet: document.getElementById('setting-subnet').value.trim(),
    scan_depth: document.getElementById('setting-depth').value,
    custom_ports: document.getElementById('setting-ports').value.trim(),
    dry_run: document.getElementById('setting-dryrun').checked,
  };
  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  }).then(() => {
    document.getElementById('settings-panel').classList.add('hidden');
  });
}

function startScan() {
  fetch('/api/settings')
    .then(r => r.json())
    .then(settings => {
      const body = {
        scan_type: settings.scan_depth || 'full',
        network_range: settings.subnet || null,
      };
      return fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        alert(data.error);
        return;
      }
      document.getElementById('scan-btn').disabled = true;
      document.getElementById('progress-container').classList.remove('hidden');
      _connectSseStream();
    });
}

function _connectSseStream() {
  const evtSource = new EventSource('/api/scan/stream');

  evtSource.onmessage = function (e) {
    const data = JSON.parse(e.data);
    document.getElementById('progress-text').textContent = data.progress || 'Scanning...';
  };

  evtSource.addEventListener('scan_complete', function () {
    evtSource.close();
    document.getElementById('progress-container').classList.add('hidden');
    document.getElementById('scan-btn').disabled = false;
    window.location.reload();
  });

  evtSource.onerror = function () {
    evtSource.close();
    document.getElementById('progress-text').textContent = 'Scan interrupted — check logs.';
    document.getElementById('scan-btn').disabled = false;
  };
}
