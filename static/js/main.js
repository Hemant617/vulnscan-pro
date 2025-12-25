// Main JavaScript for VulnScan Pro

document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
    }
});

function startScan() {
    const target = document.getElementById('target').value;
    const scanType = document.getElementById('scanType').value;
    
    const options = {
        portScan: document.getElementById('portScan').checked,
        serviceScan: document.getElementById('serviceScan').checked,
        webScan: document.getElementById('webScan').checked
    };

    // Show progress section
    document.getElementById('progressSection').style.display = 'block';
    document.getElementById('scanForm').style.display = 'none';

    // Start scan
    fetch('/api/scan/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            target: target,
            scan_type: scanType,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            monitorScan(data.scan_id);
        } else {
            alert('Error starting scan: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error starting scan');
    });
}

function monitorScan(scanId) {
    const interval = setInterval(() => {
        fetch(`/api/scan/${scanId}/status`)
            .then(response => response.json())
            .then(data => {
                updateProgress(data.progress, data.current_task);
                
                if (data.status === 'completed') {
                    clearInterval(interval);
                    window.location.href = `/results/${scanId}`;
                } else if (data.status === 'failed') {
                    clearInterval(interval);
                    alert('Scan failed');
                }
            })
            .catch(error => {
                console.error('Error monitoring scan:', error);
                clearInterval(interval);
            });
    }, 2000);
}

function updateProgress(progress, task) {
    const progressBar = document.getElementById('progressBar');
    const currentTask = document.getElementById('currentTask');
    
    progressBar.style.width = progress + '%';
    progressBar.textContent = Math.round(progress) + '%';
    currentTask.textContent = task;
}
