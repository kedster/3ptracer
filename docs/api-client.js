/**
 * API Client for 3ptracer
 * Handles both direct API calls and Cloudflare Worker proxy calls
 * with automatic fallback and error handling
 */

class APIClient {
    constructor(config) {
        this.config = config;
        this.workerHealthy = null; // Cache worker health status
    }
    
    /**
     * Make a DNS query via Worker or direct DoH
     */
    async queryDNS(domain, type = 'A', provider = 'cloudflare') {
        const useWorker = this.config.features.useWorkerAPIs && this.config.workerUrl;
        
        if (useWorker) {
            try {
                // Check worker health if not already cached
                if (this.workerHealthy === null) {
                    this.workerHealthy = await this.config.checkWorkerHealth();
                }
                
                if (this.workerHealthy) {
                    return await this.queryDNSViaWorker(domain, type, provider);
                }
            } catch (error) {
                console.warn('DNS query via Worker failed, falling back to direct:', error);
                this.workerHealthy = false;
            }
        }
        
        // Fallback to direct DoH query
        return await this.queryDNSDirect(domain, type, provider);
    }
    
    /**
     * DNS query via Cloudflare Worker
     */
    async queryDNSViaWorker(domain, type, provider) {
        const url = `${this.config.workerUrl}/api/dns?domain=${encodeURIComponent(domain)}&type=${type}&provider=${provider}`;
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'User-Agent': '3ptracer/2.0'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Worker DNS query failed: ${response.status}`);
        }
        
        return await response.json();
    }
    
    /**
     * Direct DNS over HTTPS query
     */
    async queryDNSDirect(domain, type, provider) {
        let dohUrl;
        let headers = {
            'Accept': 'application/dns-json',
            'User-Agent': '3ptracer/2.0'
        };
        
        switch (provider) {
            case 'cloudflare':
                dohUrl = `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`;
                break;
            case 'google':
                dohUrl = `https://dns.google/resolve?name=${domain}&type=${type}`;
                break;
            case 'quad9':
                dohUrl = `https://dns.quad9.net:5053/dns-query?name=${domain}&type=${type}`;
                headers.Accept = 'application/dns-json';
                break;
            default:
                dohUrl = `https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`;
        }
        
        const response = await fetch(dohUrl, { headers });
        
        if (!response.ok) {
            throw new Error(`Direct DNS query failed: ${response.status}`);
        }
        
        return await response.json();
    }
    
    /**
     * Query Certificate Transparency logs
     */
    async queryCT(domain, source) {
        const useWorker = this.config.features.useWorkerAPIs && this.config.workerUrl;
        
        if (useWorker) {
            try {
                if (this.workerHealthy === null) {
                    this.workerHealthy = await this.config.checkWorkerHealth();
                }
                
                if (this.workerHealthy) {
                    return await this.queryCTViaWorker(domain, source);
                }
            } catch (error) {
                console.warn(`CT ${source} query via Worker failed, falling back to direct:`, error);
                this.workerHealthy = false;
            }
        }
        
        // Fallback to direct CT query
        return await this.queryCTDirect(domain, source);
    }
    
    /**
     * CT query via Cloudflare Worker
     */
    async queryCTViaWorker(domain, source) {
        const url = `${this.config.workerUrl}/api/ct/${source}?domain=${encodeURIComponent(domain)}`;
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'User-Agent': '3ptracer/2.0'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Worker CT ${source} query failed: ${response.status}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        } else {
            return await response.text();
        }
    }
    
    /**
     * Direct CT query
     */
    async queryCTDirect(domain, source) {
        let url;
        let headers = {
            'Accept': 'application/json',
            'User-Agent': '3ptracer/2.0'
        };
        
        switch (source) {
            case 'crtsh':
                url = `https://crt.sh/?q=%25.${domain}&output=json`;
                break;
            case 'certspotter':
                url = `https://certspotter.com/api/v0/certs?domain=${domain}`;
                break;
            case 'otx':
                url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
                break;
            case 'hackertarget':
                url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
                headers.Accept = 'text/plain';
                break;
            default:
                throw new Error(`Unknown CT source: ${source}`);
        }
        
        const response = await fetch(url, { headers });
        
        if (!response.ok) {
            throw new Error(`Direct CT ${source} query failed: ${response.status}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (source === 'hackertarget' || (contentType && contentType.includes('text/plain'))) {
            return await response.text();
        } else {
            return await response.json();
        }
    }
    
    /**
     * Test connectivity to all services
     */
    async testConnectivity() {
        const results = {
            worker: null,
            dns: {
                cloudflare: null,
                google: null,
                quad9: null
            },
            ct: {
                crtsh: null,
                certspotter: null,
                otx: null,
                hackertarget: null
            }
        };
        
        // Test worker health
        if (this.config.workerUrl) {
            try {
                results.worker = await this.config.checkWorkerHealth();
            } catch (error) {
                results.worker = false;
            }
        }
        
        // Test DNS providers (using a simple domain like google.com)
        const testDomain = 'google.com';
        for (const provider of ['cloudflare', 'google', 'quad9']) {
            try {
                await this.queryDNSDirect(testDomain, 'A', provider);
                results.dns[provider] = true;
            } catch (error) {
                results.dns[provider] = false;
            }
        }
        
        // Test CT sources (using a simple domain)
        for (const source of ['crtsh', 'certspotter', 'otx', 'hackertarget']) {
            try {
                await this.queryCTDirect(testDomain, source);
                results.ct[source] = true;
            } catch (error) {
                results.ct[source] = false;
            }
        }
        
        return results;
    }
    
    /**
     * Get API status for debugging
     */
    getStatus() {
        return {
            workerHealthy: this.workerHealthy,
            workerUrl: this.config.workerUrl,
            useWorkerAPIs: this.config.features.useWorkerAPIs,
            fallbackEnabled: this.config.features.fallbackToDirectAPIs
        };
    }
}

// Global API client instance
const apiClient = new APIClient(appConfig);

// Export for use in other modules
window.APIClient = apiClient;