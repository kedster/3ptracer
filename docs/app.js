// Simplified Main Application - now just a wrapper around AnalysisController
class App {
    constructor() {
        this.analysisController = AnalysisController.create();
        this.currentDomain = '';
    }

    // Main analysis function - now delegates to AnalysisController
    async analyzeDomain(domain) {
        this.currentDomain = domain;
        await this.analysisController.analyzeDomain(domain);
    }

    // Save results to localStorage
    saveResults() {
        if (this.currentDomain) {
            localStorage.setItem(`3ptracer_last_domain`, this.currentDomain);
        }
    }

    // Load results from localStorage (simplified)
    loadResults(domain) {
        const saved = localStorage.getItem(`3ptracer_last_domain`);
        return saved === domain;
    }
}

// Global app instance
const app = new App();

// Configuration panel functions
function toggleConfigPanel() {
    const content = document.getElementById('configContent');
    const toggle = document.getElementById('configToggle');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.textContent = '▲';
    } else {
        content.style.display = 'none';
        toggle.textContent = '▼';
    }
}

function updateConfigDisplay() {
    const config = appConfig.getDisplayConfig();
    const status = apiClient.getStatus();
    
    document.getElementById('envStatus').textContent = config.environment;
    document.getElementById('workerUrl').textContent = config.workerUrl;
    document.getElementById('apiMode').textContent = config.features.useWorkerAPIs ? 'Worker Proxy' : 'Direct APIs';
    
    // Update debug button
    const debugBtn = document.getElementById('debugToggle');
    debugBtn.textContent = config.features.enableDebugMode ? 'Debug Mode: ON' : 'Debug Mode: OFF';
    debugBtn.style.background = config.features.enableDebugMode ? '#FF9800' : '#2196F3';
}

function toggleDebugMode() {
    const currentMode = appConfig.features.enableDebugMode;
    appConfig.setDebugMode(!currentMode);
    updateConfigDisplay();
}

async function checkWorkerHealth() {
    const healthSpan = document.getElementById('workerHealth');
    
    if (!appConfig.workerUrl) {
        healthSpan.textContent = 'N/A (Worker not configured)';
        healthSpan.style.color = '#666';
        return;
    }
    
    healthSpan.textContent = 'Checking...';
    healthSpan.style.color = '#FFA500';
    
    try {
        const healthy = await appConfig.checkWorkerHealth();
        healthSpan.textContent = healthy ? '✅ Healthy' : '❌ Unhealthy';
        healthSpan.style.color = healthy ? '#4CAF50' : '#F44336';
    } catch (error) {
        healthSpan.textContent = '❌ Error';
        healthSpan.style.color = '#F44336';
    }
}

async function testConnectivity() {
    const resultsDiv = document.getElementById('connectivityResults');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<p>Testing connectivity to all services...</p>';
    
    try {
        const results = await apiClient.testConnectivity();
        
        let html = '<h4>Connectivity Test Results:</h4>';
        
        // Worker results
        if (results.worker !== null) {
            html += `<p><strong>Worker:</strong> ${results.worker ? '✅ Available' : '❌ Unavailable'}</p>`;
        }
        
        // DNS providers
        html += '<p><strong>DNS Providers:</strong></p>';
        for (const [provider, status] of Object.entries(results.dns)) {
            html += `<span style="margin-right: 15px;">${provider}: ${status ? '✅' : '❌'}</span>`;
        }
        
        // CT sources
        html += '<p><strong>Certificate Transparency Sources:</strong></p>';
        for (const [source, status] of Object.entries(results.ct)) {
            html += `<span style="margin-right: 15px;">${source}: ${status ? '✅' : '❌'}</span>`;
        }
        
        resultsDiv.innerHTML = html;
    } catch (error) {
        resultsDiv.innerHTML = `<p style="color: #F44336;">Error testing connectivity: ${error.message}</p>`;
    }
}

// Initialize configuration display on page load
document.addEventListener('DOMContentLoaded', function() {
    updateConfigDisplay();
    checkWorkerHealth();
    
    const domainInput = document.getElementById('domain');
    const savedDomain = localStorage.getItem('3ptracer_last_domain');
    if (savedDomain) {
        domainInput.value = savedDomain;
    }
});
// Main analysis function (called from HTML)
async function analyzeDomain() {
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.querySelector('.analyze-btn');
    const domain = domainInput.value.trim();
    
    if (!domain) {
        alert('Please enter a domain name');
        return;
    }
    
    // Disable button and show progress
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing...';
    
    // Hide previous results
    document.getElementById('results').style.display = 'none';
    
    try {
        await app.analyzeDomain(domain);
        app.saveResults();
    } catch (error) {
        console.error('Analysis failed:', error);
    } finally {
        // Re-enable button
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Analyze Domain';
    }
}

// Handle Enter key in input field
document.getElementById('domain').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        analyzeDomain();
    }
});

// Load saved results on page load
document.addEventListener('DOMContentLoaded', function() {
    const domainInput = document.getElementById('domain');
    const savedDomain = localStorage.getItem('3ptracer_last_domain');
    if (savedDomain) {
        domainInput.value = savedDomain;
    }
}); 