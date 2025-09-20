/**
 * Configuration Module for 3ptracer
 * Handles environment-specific settings and API endpoints
 */

class Config {
    constructor() {
        // Detect if running on Cloudflare Pages
        this.isCloudflarePages = this.detectCloudflarePages();
        
        // Worker URL - update this with your actual worker URL
        this.workerUrl = this.getWorkerUrl();
        
        // Feature flags
        this.features = {
            useWorkerAPIs: this.isCloudflarePages, // Use worker APIs when on CF Pages
            enableCaching: true,
            enableDebugMode: localStorage.getItem('3ptracer_debug') === 'true',
            fallbackToDirectAPIs: true // Fallback if worker fails
        };
        
        console.log('Config initialized:', {
            isCloudflarePages: this.isCloudflarePages,
            useWorkerAPIs: this.features.useWorkerAPIs,
            workerUrl: this.workerUrl
        });
    }
    
    /**
     * Detect if running on Cloudflare Pages
     */
    detectCloudflarePages() {
        // Check for Cloudflare Pages specific indicators
        const hostname = window.location.hostname;
        return (
            hostname.includes('.pages.dev') ||
            hostname.includes('3ptracer.pages.dev') ||
            // Check for CF-Ray header (set by Cloudflare)
            document.cookie.includes('__cf') ||
            // Environment variable check (if available)
            (window.CF_PAGES && window.CF_PAGES === true)
        );
    }
    
    /**
     * Get the Worker URL based on environment
     */
    getWorkerUrl() {
        // If we have an environment variable or meta tag with worker URL
        const metaWorkerUrl = document.querySelector('meta[name="worker-url"]')?.content;
        if (metaWorkerUrl) {
            return metaWorkerUrl;
        }
        
        // Default worker URL - update this with your actual worker domain
        if (this.isCloudflarePages) {
            return 'https://3ptracer-worker.your-subdomain.workers.dev';
        }
        
        // For local development, we can use a proxy or direct calls
        return null;
    }
    
    /**
     * Get API endpoint for DNS queries
     */
    getDNSEndpoint(provider = 'cloudflare') {
        if (this.features.useWorkerAPIs && this.workerUrl) {
            return `${this.workerUrl}/api/dns?provider=${provider}`;
        }
        
        // Fallback to direct DoH endpoints
        switch (provider) {
            case 'cloudflare':
                return 'https://cloudflare-dns.com/dns-query';
            case 'google':
                return 'https://dns.google/resolve';
            case 'quad9':
                return 'https://dns.quad9.net:5053/dns-query';
            default:
                return 'https://cloudflare-dns.com/dns-query';
        }
    }
    
    /**
     * Get API endpoint for Certificate Transparency queries
     */
    getCTEndpoint(source) {
        if (this.features.useWorkerAPIs && this.workerUrl) {
            return `${this.workerUrl}/api/ct/${source}`;
        }
        
        // Fallback to direct endpoints
        switch (source) {
            case 'crtsh':
                return 'https://crt.sh/';
            case 'certspotter':
                return 'https://certspotter.com/api/v0/certs';
            case 'otx':
                return 'https://otx.alienvault.com/api/v1/indicators/domain';
            case 'hackertarget':
                return 'https://api.hackertarget.com/hostsearch/';
            default:
                return null;
        }
    }
    
    /**
     * Check if Worker APIs are available
     */
    async checkWorkerHealth() {
        if (!this.workerUrl) return false;
        
        try {
            const response = await fetch(`${this.workerUrl}/api/health`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            const data = await response.json();
            return response.ok && data.status === 'ok';
        } catch (error) {
            console.warn('Worker health check failed:', error);
            return false;
        }
    }
    
    /**
     * Enable/disable debug mode
     */
    setDebugMode(enabled) {
        this.features.enableDebugMode = enabled;
        localStorage.setItem('3ptracer_debug', enabled.toString());
        console.log(`Debug mode ${enabled ? 'enabled' : 'disabled'}`);
    }
    
    /**
     * Get configuration for display
     */
    getDisplayConfig() {
        return {
            environment: this.isCloudflarePages ? 'Cloudflare Pages' : 'Direct',
            workerUrl: this.workerUrl || 'N/A',
            features: this.features,
            version: '2.0.0-cf'
        };
    }
}

// Global configuration instance
const appConfig = new Config();

// Export for use in other modules
window.AppConfig = appConfig;