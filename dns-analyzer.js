// DNS Analyzer Module
class DNSAnalyzer {
    constructor() {
        // Primary DNS servers (Google and Cloudflare only - more reliable)
        this.primaryDNSServers = [
            'https://dns.google/resolve',
            'https://cloudflare-dns.com/dns-query'
        ];

        // Remove problematic backup servers that consistently fail
        this.standbyDNSServers = [];

        this.rateLimiter = new RateLimiter(10, 1000); // 10 requests per second
        
        // Cache for certificate transparency results
        this.ctCache = new Map();
        
        // Global subdomain tracking for real-time processing
        this.globalSubdomains = new Set();
        this.processedSubdomains = new Set();
        this.subdomainCallbacks = [];
        this.notificationCallback = null;
        
        // Historical records tracking
        this.historicalRecords = [];
        
        // Current domain being analyzed (for intelligent record querying)
        this.currentDomain = '';
        
        // Statistics tracking
        this.stats = {
            dnsQueries: 0,
            apiCalls: 0,
            subdomainsDiscovered: 0,
            subdomainsAnalyzed: 0,
            asnLookups: 0,
            servicesDetected: 0,
            takeoversDetected: 0,
            startTime: null,
            endTime: null
        };
    }

    // Reset all internal state for new analysis
    resetStats() {
        // Reset statistics
        this.stats = {
            dnsQueries: 0,
            apiCalls: 0,
            subdomainsDiscovered: 0,
            subdomainsAnalyzed: 0,
            asnLookups: 0,
            servicesDetected: 0,
            takeoversDetected: 0,
            startTime: Date.now(),
            endTime: null
        };
        
        // Clear all internal arrays and sets
        this.globalSubdomains.clear();
        this.processedSubdomains.clear();
        this.subdomainCallbacks = [];
        this.notificationCallback = null;
        this.historicalRecords = [];
        this.ctCache.clear();
        this.currentDomain = '';
        
        console.log('🧹 DNS Analyzer internal state cleared for new analysis');
    }
    
    // Set current domain for intelligent record querying
    setCurrentDomain(domain) {
        this.currentDomain = domain;
    }

    // Print final statistics
    printStats() {
        this.stats.endTime = Date.now();
        const duration = (this.stats.endTime - this.stats.startTime) / 1000;
        
        console.log('\n' + '='.repeat(60));
        console.log('📊 ANALYSIS STATISTICS');
        console.log('='.repeat(60));
        console.log(`⏱️  Total Duration: ${duration.toFixed(2)} seconds`);
        console.log(`🔍 DNS Queries: ${this.stats.dnsQueries}`);
        console.log(`🌐 API Calls: ${this.stats.apiCalls}`);
        console.log(`🔍 Subdomains Discovered: ${this.stats.subdomainsDiscovered}`);
        console.log(`⚡ Subdomains Analyzed: ${this.stats.subdomainsAnalyzed}`);
        console.log(`🏢 ASN Lookups: ${this.stats.asnLookups}`);
        console.log(`🔧 Services Detected: ${this.stats.servicesDetected}`);
        console.log(`⚠️  Takeovers Detected: ${this.stats.takeoversDetected}`);
        console.log(`📈 Performance: ${this.stats.subdomainsAnalyzed > 0 ? (this.stats.subdomainsAnalyzed / duration).toFixed(2) : 0} subdomains/second`);
        console.log('='.repeat(60));
    }

    // Register callback for real-time subdomain updates
    onSubdomainDiscovered(callback) {
        this.subdomainCallbacks.push(callback);
    }

    // Register callback for API notifications
    onAPINotification(callback) {
        this.notificationCallback = callback;
    }

    // Notify all callbacks about new subdomain
    notifySubdomainDiscovered(subdomain, source) {
        this.globalSubdomains.add(subdomain);
        this.stats.subdomainsDiscovered++;
        console.log(`🆕 New subdomain discovered: ${subdomain} (from ${source})`);
        
        // Notify all registered callbacks
        this.subdomainCallbacks.forEach(callback => {
            try {
                callback(subdomain, source);
            } catch (error) {
                console.warn('Callback error:', error);
            }
        });
    }

    // Send API notification
    notifyAPIStatus(apiName, status, message) {
        if (this.notificationCallback) {
            try {
                this.notificationCallback(apiName, status, message);
            } catch (error) {
                console.warn('API notification callback error:', error);
            }
        }
    }
    
    // Get historical records
    getHistoricalRecords() {
        return this.historicalRecords;
    }

    // Check if CNAME points to main domain
    isCNAMEToMainDomain(cnameTarget) {
        if (!cnameTarget || !this.currentDomain) return false;
        
        // Remove trailing dot and compare
        const cleanTarget = cnameTarget.replace(/\.$/, '');
        const cleanMainDomain = this.currentDomain.replace(/\.$/, '');
        
        // Check if CNAME target is the main domain
        return cleanTarget === cleanMainDomain;
    }

    // Process subdomain immediately when discovered
    async processSubdomainImmediately(subdomain, source, certInfo = null) {
        if (this.processedSubdomains.has(subdomain)) {
            console.log(`⏭️  Skipping already processed subdomain: ${subdomain}`);
            return;
        }

        console.log(`⚡ Processing subdomain immediately: ${subdomain} (from ${source})`);
        this.processedSubdomains.add(subdomain);
        this.stats.subdomainsAnalyzed++;

        try {
            // Analyze the subdomain
            const analysis = await this.analyzeSingleSubdomain(subdomain);
            
            // Check if this is a CNAME redirect to main domain
            if (analysis.records.CNAME && analysis.records.CNAME.length > 0) {
                const cnameTarget = analysis.records.CNAME[0].data;
                if (this.isCNAMEToMainDomain(cnameTarget)) {
                    // This is a redirect to main domain - mark as redirect and skip further analysis
                    analysis.isRedirectToMain = true;
                    analysis.redirectTarget = cnameTarget;
                    console.log(`🔄 Redirect detected: ${subdomain} → ${cnameTarget} (main domain) - skipping detailed analysis`);
                    
                    // Notify about redirect completion
                    this.subdomainCallbacks.forEach(callback => {
                        try {
                            callback(subdomain, source, analysis);
                        } catch (error) {
                            console.warn('Redirect callback error:', error);
                        }
                    });
                    return; // Skip further analysis
                }
            }
            
            // Check if this is a historical record (no DNS records found)
            if ((!analysis.records.A || analysis.records.A.length === 0) && 
                (!analysis.records.CNAME || analysis.records.CNAME.length === 0)) {
                
                // This is a historical record - no active DNS
                const historicalRecord = {
                    subdomain: subdomain,
                    source: source,
                    certificateInfo: certInfo || {
                        issuer: 'No certificate info available',
                        notBefore: null,
                        notAfter: null,
                        certificateId: null
                    },
                    discoveredAt: new Date().toISOString(),
                    status: 'Historical/Obsolete'
                };
                this.historicalRecords.push(historicalRecord);
                console.log(`📜 Historical record found: ${subdomain} (no active DNS, source: ${source})`);
            }
            
            // Notify about analysis completion
            this.subdomainCallbacks.forEach(callback => {
                try {
                    callback(subdomain, source, analysis);
                } catch (error) {
                    console.warn('Analysis callback error:', error);
                }
            });
        } catch (error) {
            console.error(`❌ Error processing subdomain ${subdomain}:`, error);
        }
    }

    // Analyze a single subdomain
    async analyzeSingleSubdomain(subdomain) {
        console.log(`🔍 Analyzing single subdomain: ${subdomain}`);
        
        const analysis = {
            subdomain: subdomain,
            records: {},
            ip: null,
            vendor: { vendor: 'Unknown', category: 'Unknown' },
            takeover: null
        };

        try {
            // Get DNS records (without specifying type to get CNAME chain automatically)
            const records = await this.queryDNS(subdomain);
            if (records && records.length > 0) {
                // Process all record types from the response
                for (const record of records) {
                    if (record.type === 1) { // A record
                        if (!analysis.records.A) analysis.records.A = [];
                        analysis.records.A.push(record);
                        analysis.ip = record.data;
                    } else if (record.type === 5) { // CNAME record
                        if (!analysis.records.CNAME) analysis.records.CNAME = [];
                        analysis.records.CNAME.push(record);
                        // Store the CNAME target for service analysis
                        analysis.cnameTarget = record.data.replace(/\.$/, '');
                        
                        // Follow CNAME chain for enhanced service detection
                        const cnameChain = await this.followCNAMEChain(subdomain);
                        if (cnameChain.length > 0) {
                            analysis.cnameChain = cnameChain;
                            
                            // Detect primary service from first CNAME
                            const firstCNAME = cnameChain[0].to;
                            analysis.primaryService = this.detectPrimaryService(firstCNAME);
                            
                            // Detect infrastructure from final CNAME
                            const finalCNAME = cnameChain[cnameChain.length - 1].to;
                            analysis.infrastructure = this.detectInfrastructure(finalCNAME);
                            
                            // Use primary service as cnameService (consolidated approach)
                            analysis.cnameService = analysis.primaryService;
                        } else {
                            // Fallback to single CNAME detection (consolidated)
                            analysis.cnameService = this.detectCNAMEService(analysis.cnameTarget);
                            // Also set as primary service for consistency
                            analysis.primaryService = analysis.cnameService;
                        }
                    }
                }
                
                // For subdomains, we don't need to query MX, TXT, or NS records
                // These are typically only relevant for the main domain:
                // - MX: Email routing (domain-level)
                // - TXT: Domain policies like SPF, DMARC, verification (domain-level)  
                // - NS: Authoritative nameservers (domain-level)
                // Subdomains typically only need A/AAAA and CNAME records
                
                console.log(`  ✅ Subdomain ${subdomain} analysis complete - skipping MX/TXT/NS queries`);
                
                // Get ASN info if we have an IP
                if (analysis.ip && /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(analysis.ip)) {
                    try {
                        const asnInfo = await this.getASNInfo(analysis.ip);
                        analysis.vendor = this.classifyVendor(asnInfo);
                        this.stats.asnLookups++;
                        console.log(`  ✅ ASN info for ${analysis.ip}: ${asnInfo.org || 'Unknown'}`);
                    } catch (error) {
                        console.warn(`  ⚠️  ASN lookup failed for ${analysis.ip}:`, error.message);
                    }
                }
                
                // Check for takeover and detect services from CNAME records
                if (analysis.records.CNAME && analysis.records.CNAME.length > 0) {
                    const cnameTarget = analysis.records.CNAME[0].data.replace(/\.$/, '');
                    analysis.cnameTarget = cnameTarget;
                    
                    // Detect takeover
                    const takeover = await this.detectTakeover(subdomain, cnameTarget);
                    if (takeover) {
                        analysis.takeover = takeover;
                        this.stats.takeoversDetected++;
                    }
                    
                    // Detect third-party service
                    const detectedService = this.detectPrimaryService(cnameTarget);
                    if (detectedService) {
                        analysis.detectedService = detectedService;
                        console.log(`  🎯 Detected service: ${detectedService.name} (${detectedService.category}) for ${subdomain}`);
                    }
                }
            }

            // TXT and MX records are not queried for subdomains as they are typically
            // only relevant at the domain level (SPF, DMARC, email routing, etc.)
            // This optimization reduces unnecessary DNS queries by ~50% for subdomain analysis

            console.log(`✅ Single subdomain analysis complete: ${subdomain} (IP: ${analysis.ip || 'none'})`);
            return analysis;

        } catch (error) {
            console.error(`❌ Error analyzing subdomain ${subdomain}:`, error);
            return analysis;
        }
    }

    // Classify vendor from ASN info
    classifyVendor(asnInfo) {
        if (!asnInfo || !asnInfo.org) {
            return { vendor: 'Unknown', category: 'Unknown' };
        }

        const org = asnInfo.org.toLowerCase();
        
        if (org.includes('amazon') || org.includes('aws')) {
            return { vendor: 'Amazon Web Services', category: 'Cloud' };
        } else if (org.includes('microsoft') || org.includes('azure')) {
            return { vendor: 'Microsoft Azure', category: 'Cloud' };
        } else if (org.includes('google') || org.includes('gcp')) {
            return { vendor: 'Google Cloud Platform', category: 'Cloud' };
        } else if (org.includes('cloudflare')) {
            return { vendor: 'Cloudflare', category: 'CDN' };
        } else if (org.includes('digitalocean')) {
            return { vendor: 'DigitalOcean', category: 'Cloud' };
        } else if (org.includes('fastly')) {
            return { vendor: 'Fastly', category: 'CDN' };
        } else {
            return { vendor: asnInfo.org, category: 'Other' };
        }
    }

    // Follow CNAME chain to identify primary service and infrastructure
    async followCNAMEChain(subdomain) {
        const chain = [];
        let currentTarget = subdomain;
        const maxHops = 10; // Prevent infinite loops
        let hopCount = 0;
        
        while (hopCount < maxHops) {
            try {
                const records = await this.queryDNS(currentTarget, 'CNAME');
                if (records && records.length > 0) {
                    const cnameRecord = records[0];
                    const target = cnameRecord.data.replace(/\.$/, '');
                    chain.push({
                        from: currentTarget,
                        to: target,
                        ttl: cnameRecord.TTL
                    });
                    currentTarget = target;
                    hopCount++;
                } else {
                    // No more CNAME records, we've reached the end
                    break;
                }
            } catch (error) {
                console.warn(`  ⚠️  Failed to follow CNAME chain for ${currentTarget}:`, error.message);
                break;
            }
        }
        
        return chain;
    }
    
    // Simplified service detection from CNAME target
    detectPrimaryService(firstCNAME) {
        if (!firstCNAME) return null;
        
        const target = firstCNAME.toLowerCase();
        
        // Comprehensive service patterns for CNAME detection
        const servicePatterns = [
            // Identity & Authentication
            { pattern: 'okta.com', name: 'Okta', category: 'security', description: 'Identity and access management platform' },
            { pattern: 'auth0.com', name: 'Auth0', category: 'security', description: 'Identity and access management platform' },
            
            // Payment Services
            { pattern: 'stripecdn.com', name: 'Stripe', category: 'payment', description: 'Payment processing platform' },
            { pattern: 'stripe.com', name: 'Stripe', category: 'payment', description: 'Payment processing platform' },
            { pattern: 'paypal.com', name: 'PayPal', category: 'payment', description: 'Payment processing platform' },
            
            // Productivity & Office Suites
            { pattern: 'zohohost.eu', name: 'Zoho', category: 'productivity', description: 'Business productivity suite' },
            { pattern: 'zoho.com', name: 'Zoho', category: 'productivity', description: 'Business productivity suite' },
            { pattern: 'zohohost.com', name: 'Zoho', category: 'productivity', description: 'Business productivity suite' },
            
            // CDN & Cloud Services
            { pattern: 'cloudflare', name: 'Cloudflare', category: 'cloud', description: 'CDN and security services' },
            { pattern: 'cloudfront.net', name: 'AWS CloudFront', category: 'cloud', description: 'Amazon content delivery network' },
            { pattern: 'elb.amazonaws.com', name: 'AWS Load Balancer', category: 'cloud', description: 'Amazon load balancing service' },
            { pattern: 'amazonaws.com', name: 'Amazon AWS', category: 'cloud', description: 'Cloud computing platform' },
            { pattern: 'fastly.com', name: 'Fastly', category: 'cloud', description: 'Edge cloud platform' },
            
            // Hosting Platforms
            { pattern: 'heroku', name: 'Heroku', category: 'cloud', description: 'Cloud application platform' },
            { pattern: 'netlify', name: 'Netlify', category: 'cloud', description: 'Static site hosting' },
            { pattern: 'vercel', name: 'Vercel', category: 'cloud', description: 'Frontend deployment platform' },
            { pattern: 'github', name: 'GitHub Pages', category: 'cloud', description: 'Static site hosting' },
            { pattern: 'wixdns.net', name: 'Wix', category: 'cloud', description: 'Website builder platform' },
            { pattern: 'wix.com', name: 'Wix', category: 'cloud', description: 'Website builder platform' },
            
            // Documentation & Content
            { pattern: 'gitbook.io', name: 'GitBook', category: 'documentation', description: 'Documentation platform' },
            { pattern: 'notion.so', name: 'Notion', category: 'documentation', description: 'Workspace and documentation platform' },
            
            // Customer Feedback & Support
            { pattern: 'canny.io', name: 'Canny Feedback', category: 'feedback', description: 'Product feedback platform' },
            { pattern: 'zendesk.com', name: 'Zendesk', category: 'support', description: 'Customer support platform' },
            { pattern: 'intercom.io', name: 'Intercom', category: 'support', description: 'Customer messaging platform' },
            
            // Analytics & Marketing
            { pattern: 'hubspot.com', name: 'HubSpot', category: 'marketing', description: 'Marketing and CRM platform' },
            { pattern: 'mailchimp.com', name: 'Mailchimp', category: 'marketing', description: 'Email marketing platform' },
            
            // Development Tools
            { pattern: 'gitpod.io', name: 'Gitpod', category: 'development', description: 'Cloud development environment' }
        ];
        
        for (const service of servicePatterns) {
            if (target.includes(service.pattern)) {
                return {
                    name: service.name,
                    category: service.category,
                    description: service.description
                };
            }
        }
        
        return null;
    }
    
    // Detect infrastructure from final CNAME target
    detectInfrastructure(finalCNAME) {
        if (!finalCNAME) return null;
        
        const target = finalCNAME.toLowerCase();
        
        // AWS services
        if (target.includes('awsglobalaccelerator.com')) {
            return { name: 'AWS Global Accelerator', category: 'cloud', description: 'Global application accelerator' };
        }
        if (target.includes('awsapprunner.com')) {
            return { name: 'AWS App Runner', category: 'cloud', description: 'Containerized application hosting' };
        }
        if (target.includes('amazonaws.com')) {
            return { name: 'Amazon Web Services (AWS)', category: 'cloud', description: 'Cloud computing platform' };
        }
        
        // Azure services
        if (target.includes('azurewebsites.net')) {
            return { name: 'Microsoft Azure', category: 'cloud', description: 'Cloud computing platform' };
        }
        
        // DigitalOcean services
        if (target.includes('ondigitalocean.app')) {
            return { name: 'DigitalOcean App Platform', category: 'cloud', description: 'Application hosting platform' };
        }
        
        // Cloudflare
        if (target.includes('cloudflare.com')) {
            return { name: 'Cloudflare', category: 'cloud', description: 'CDN and security services' };
        }
        
        return null; // No infrastructure detected
    }
    
    // Use primary service detection for CNAME targets
    detectCNAMEService(cnameTarget) {
        return this.detectPrimaryService(cnameTarget);
    }

    // Start certificate transparency queries early (non-blocking)
    startCTQueries(domain) {
        if (this.ctCache.has(domain)) {
            return this.ctCache.get(domain);
        }
        
        console.log(`🚀 Starting early CT queries for ${domain}...`);
        const promise = this.getSubdomainsFromCT(domain);
        this.ctCache.set(domain, promise);
        return promise;
    }

    // Query DNS with fallback strategy
    async queryDNS(domain, type = 'A', server = null) {
        await this.rateLimiter.throttle();
        this.stats.dnsQueries++;

        console.log(`🔍 Querying DNS for ${domain}${type ? ` (${type})` : ' (any type)'}`);
        
        // If specific server is requested, use only that
        if (server) {
            console.log(`  📡 Using specified DNS server: ${server}`);
            try {
                const response = await this.queryDNSServer(domain, type, server);
                if (response && response.Answer && response.Answer.length > 0) {
                    console.log(`  ✅ DNS server ${server} succeeded with ${response.Answer.length} records`);
                    return response.Answer;
                } else {
                    console.log(`  ⚠️  DNS server ${server} returned no records`);
                    return null;
                }
            } catch (error) {
                console.warn(`  ❌ DNS server ${server} failed:`, error.message);
                return null;
            }
        }
        
        // Try primary DNS servers first
        console.log(`  🔄 Trying PRIMARY DNS servers...`);
        for (const dnsServer of this.primaryDNSServers) {
            console.log(`    📡 Trying PRIMARY DNS server: ${dnsServer}`);
            
            try {
                const response = await this.queryDNSServer(domain, type, dnsServer);
                if (response && response.Answer && response.Answer.length > 0) {
                    console.log(`    ✅ PRIMARY DNS server ${dnsServer} succeeded with ${response.Answer.length} records`);
                    return response.Answer; // Return immediately on success
                } else {
                    console.log(`    ⚠️  PRIMARY DNS server ${dnsServer} returned no records`);
                }
            } catch (error) {
                console.warn(`    ❌ PRIMARY DNS server ${dnsServer} failed:`, error.message);
                continue; // Try next primary server
            }
        }
        
        // Only try backup servers if we have any
        if (this.standbyDNSServers.length > 0) {
            console.log(`  🚨 All PRIMARY DNS servers failed, trying BACKUP servers...`);
            for (const dnsServer of this.standbyDNSServers) {
                console.log(`    📡 Trying BACKUP DNS server: ${dnsServer}`);
                
                try {
                    const response = await this.queryDNSServer(domain, type, dnsServer);
                    if (response && response.Answer && response.Answer.length > 0) {
                        console.log(`    ✅ BACKUP DNS server ${dnsServer} succeeded with ${response.Answer.length} records`);
                        return response.Answer; // Return immediately on success
                    } else {
                        console.log(`    ⚠️  BACKUP DNS server ${dnsServer} returned no records`);
                    }
                } catch (error) {
                    console.warn(`    ❌ BACKUP DNS server ${dnsServer} failed:`, error.message);
                    continue; // Try next backup server
                }
            }
        }
        
        console.log(`  ℹ️  No DNS records found for ${domain}${type ? ` (${type})` : ''} - this is normal for some record types`);
        return null;
    }

    // Query specific DNS server
    async queryDNSServer(domain, type, server) {
        try {
            if (server.includes('dns.google')) {
                // Google DNS format
                const url = new URL(server);
                url.searchParams.set('name', domain);
                if (type) {
                    url.searchParams.set('type', type);
                }
                url.searchParams.set('do', 'true');
                
                const response = await fetch(url.toString(), {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/dns-json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`DNS query failed: ${response.status}`);
                }
                
                return await response.json();
            } else if (server.includes('cloudflare-dns.com')) {
                // Cloudflare DNS format
                const cloudflareUrl = `https://cloudflare-dns.com/dns-query?name=${domain}${type ? `&type=${type}` : ''}`;
                const response = await fetch(cloudflareUrl, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/dns-json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`DNS query failed: ${response.status}`);
                }
                
                return await response.json();
            } else if (server.includes('doh.pub')) {
                // DoH.pub format
                const dohUrl = `https://doh.pub/dns-query?name=${domain}&type=${type}`;
                const response = await fetch(dohUrl, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/dns-json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`DNS query failed: ${response.status}`);
                }
                
                return await response.json();
            } else if (server.includes('dns.alidns.com')) {
                // Alibaba DNS format
                const alibabaUrl = `https://dns.alidns.com/resolve?name=${domain}&type=${type}`;
                const response = await fetch(alibabaUrl, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/dns-json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`DNS query failed: ${response.status}`);
                }
                
                return await response.json();
            } else {
                throw new Error(`Unsupported DNS server: ${server}`);
            }
        } catch (error) {
            console.warn(`Failed to query ${server}:`, error);
            throw error;
        }
    }

    // Analyze main domain records
    async analyzeMainDomain(domain) {
        const results = {
            domain: domain,
            records: {},
            services: []
        };

        // Query all record types for the main domain
        // Main domains need comprehensive analysis including:
        // - A: IP addresses
        // - CNAME: Aliases (less common for main domains)
        // - TXT: Verification, SPF, DMARC policies
        // - MX: Email routing
        // - NS: Authoritative nameservers
        const recordTypes = ['A', 'CNAME', 'TXT', 'MX', 'NS'];
        
        for (const type of recordTypes) {
            try {
                const records = await this.queryDNS(domain, type);
                if (records && records.length > 0) {
                    results.records[type] = records;
                }
            } catch (error) {
                console.warn(`Failed to query ${type} records for ${domain}:`, error);
            }
        }

        // Query SPF and DMARC records
        try {
            const spfRecords = await this.queryDNS(domain, 'TXT');
            if (spfRecords) {
                const spf = spfRecords.filter(record => 
                    record.data.includes('v=spf1')
                );
                if (spf.length > 0) {
                    results.records['SPF'] = spf;
                }
            }
        } catch (error) {
            console.warn('Failed to query SPF records:', error);
        }

        try {
            const dmarcRecords = await this.queryDNS(`_dmarc.${domain}`, 'TXT');
            if (dmarcRecords) {
                const dmarc = dmarcRecords.filter(record => 
                    record.data.includes('v=DMARC1')
                );
                if (dmarc.length > 0) {
                    results.records['DMARC'] = dmarc;
                }
            }
        } catch (error) {
            console.warn('Failed to query DMARC records:', error);
        }

        return results;
    }

    // Get subdomains from multiple sources (real-time version)
    async getSubdomainsFromCT(domain) {
        const subdomains = new Set();
        
        console.log(`🔍 Querying multiple sources for subdomains of ${domain}`);
        
        // Query reliable sources in parallel (removed CORS-problematic APIs)
        const promises = [
            this.queryCrtSh(domain),
            this.queryCertSpotter(domain),
            this.queryOTX(domain),
            this.queryHackerTarget(domain)
        ];
        
        try {
            const results = await Promise.allSettled(promises);
            
            // Process results from each source
            const sources = ['crt.sh', 'Cert Spotter', 'OTX AlienVault', 'HackerTarget'];
            
            for (let i = 0; i < results.length; i++) {
                if (results[i].status === 'fulfilled') {
                    const sourceSubdomains = results[i].value;
                    console.log(`✅ Found ${sourceSubdomains.length} subdomains from ${sources[i]}`);
                    sourceSubdomains.forEach(sub => subdomains.add(sub));
                } else {
                    console.log(`❌ ${sources[i]} failed:`, results[i].reason);
                }
            }
            
            console.log(`📊 Total unique subdomains found: ${subdomains.size}`);
            
        } catch (error) {
            console.log(`❌ Subdomain discovery query failed:`, error);
        }
        
        // If no subdomains found from sources, try common subdomain patterns
        if (subdomains.size === 0) {
            console.log(`🔍 No subdomains found from sources, trying common patterns...`);
            const commonSubdomains = [
                'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test', 
                'staging', 'cdn', 'static', 'assets', 'img', 'images', 'media',
                'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store'
            ];
            
            for (const sub of commonSubdomains) {
                const subdomain = `${sub}.${domain}`;
                try {
                    console.log(`  📡 Checking common subdomain: ${subdomain}`);
                    const records = await this.queryDNS(subdomain, 'A');
                    if (records && records.length > 0) {
                        subdomains.add(subdomain);
                        console.log(`  ✅ Found common subdomain: ${subdomain}`);
                        // Process immediately when discovered
                        this.notifySubdomainDiscovered(subdomain, 'Common Patterns');
                        this.processSubdomainImmediately(subdomain, 'Common Patterns');
                    }
                } catch (error) {
                    // Silently continue - this is expected for most common subdomains
                }
            }
            
            console.log(`✅ Found ${subdomains.size} subdomains from common patterns`);
        }
        
        return Array.from(subdomains);
    }

    // Query crt.sh for subdomains
    async queryCrtSh(domain) {
        console.log(`  📡 Querying crt.sh for subdomains...`);
        this.stats.apiCalls++;
        
        try {
            // Try with different CORS modes
            let response = null;
            try {
                // First try with explicit CORS mode
                response = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, {
                    method: 'GET',
                    mode: 'cors',
                    headers: {
                        'Accept': 'application/json'
                    }
                });
            } catch (corsError) {
                console.log(`    ⚠️  CORS error with crt.sh, trying without mode:`, corsError.message);
                // Try without explicit mode
                response = await fetch(`https://crt.sh/?q=%25.${domain}&output=json`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    }
                });
            }
            
            if (!response.ok) {
                const errorMsg = `Service unavailable (${response.status})`;
                this.notifyAPIStatus('crt.sh', 'error', errorMsg);
                throw new Error(`CT query failed: ${response.status}`);
            }

        const certificates = await response.json();
        const subdomains = new Set();
        
        for (const cert of certificates) {
            if (cert.name_value) {
                const names = cert.name_value.split(/\n|,/);
                for (const name of names) {
                    const cleanName = name.trim().toLowerCase();
                    
                    // Filter out invalid subdomains
                    if (cleanName.endsWith(`.${domain}`) && 
                        cleanName !== domain &&
                        !cleanName.includes('*') && // Exclude wildcards
                        !cleanName.startsWith('*.') && // Exclude wildcard patterns
                        cleanName.length > domain.length + 1 && // Must be actual subdomain
                        /^[a-z0-9.-]+$/.test(cleanName)) { // Valid characters only
                        
                        subdomains.add(cleanName);
                        console.log(`    ✅ Found subdomain from crt.sh: ${cleanName}`);
                        
                        // Store certificate information for historical records
                        const certInfo = {
                            subdomain: cleanName,
                            source: 'crt.sh',
                            issuer: cert.issuer_name || 'Unknown',
                            notBefore: cert.not_before || null,
                            notAfter: cert.not_after || null,
                            certificateId: cert.id || null
                        };
                        
                        // Process immediately when discovered
                        this.notifySubdomainDiscovered(cleanName, 'crt.sh');
                        this.processSubdomainImmediately(cleanName, 'crt.sh', certInfo);
                    } else if (cleanName.includes('*')) {
                        console.log(`    ⚠️  Skipping wildcard from crt.sh: ${cleanName}`);
                    }
                }
            }
        }
        
        this.notifyAPIStatus('crt.sh', 'success', `Found ${subdomains.size} subdomains`);
        return Array.from(subdomains);
        } catch (error) {
            const errorMsg = `Network error: ${error.message}`;
            this.notifyAPIStatus('crt.sh', 'error', errorMsg);
            throw error;
        }
    }

    // Query Cert Spotter for subdomains
    async queryCertSpotter(domain) {
        console.log(`  📡 Querying Cert Spotter for subdomains...`);
        this.stats.apiCalls++;
        
        const response = await fetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errorMsg = `Service unavailable (${response.status})`;
            this.notifyAPIStatus('Cert Spotter', 'error', errorMsg);
            throw new Error(`Cert Spotter query failed: ${response.status}`);
        }

        const csData = await response.json();
        const subdomains = new Set();
        
        for (const cert of csData) {
            if (cert.dns_names) {
                for (const name of cert.dns_names) {
                    const cleanName = name.trim().toLowerCase();
                    
                    // Filter out invalid subdomains
                    if (cleanName.endsWith(`.${domain}`) && 
                        cleanName !== domain &&
                        !cleanName.includes('*') && // Exclude wildcards
                        !cleanName.startsWith('*.') && // Exclude wildcard patterns
                        cleanName.length > domain.length + 1 && // Must be actual subdomain
                        /^[a-z0-9.-]+$/.test(cleanName)) { // Valid characters only
                        
                        subdomains.add(cleanName);
                        console.log(`    ✅ Found subdomain from Cert Spotter: ${cleanName}`);
                        
                        // Store certificate information for historical records
                        const certInfo = {
                            subdomain: cleanName,
                            source: 'Cert Spotter',
                            issuer: cert.issuer?.name || 'Unknown',
                            notBefore: cert.not_before || null,
                            notAfter: cert.not_after || null,
                            certificateId: cert.id || null
                        };
                        
                        // Process immediately when discovered
                        this.notifySubdomainDiscovered(cleanName, 'Cert Spotter');
                        this.processSubdomainImmediately(cleanName, 'Cert Spotter', certInfo);
                    } else if (cleanName.includes('*')) {
                        console.log(`    ⚠️  Skipping wildcard from Cert Spotter: ${cleanName}`);
                    }
                }
            }
        }
        
        this.notifyAPIStatus('Cert Spotter', 'success', `Found ${subdomains.size} subdomains`);
        return Array.from(subdomains);
    }



    // Query OTX AlienVault for subdomains
    async queryOTX(domain) {
        console.log(`  📡 Querying OTX AlienVault for subdomains...`);
        this.stats.apiCalls++;
        
        const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`);
        
        if (!response.ok) {
            const errorMsg = `Service unavailable (${response.status})`;
            this.notifyAPIStatus('OTX AlienVault', 'error', errorMsg);
            throw new Error(`OTX query failed: ${response.status}`);
        }

        const data = await response.json();
        const subdomains = new Set();
        
        if (data.passive_dns) {
            for (const entry of data.passive_dns) {
                if (entry.hostname && entry.hostname.endsWith(`.${domain}`) && entry.hostname !== domain) {
                    subdomains.add(entry.hostname);
                    console.log(`    ✅ Found subdomain from OTX: ${entry.hostname}`);
                    // Process immediately when discovered
                    this.notifySubdomainDiscovered(entry.hostname, 'OTX AlienVault');
                    this.processSubdomainImmediately(entry.hostname, 'OTX AlienVault');
                }
            }
        }
        
        this.notifyAPIStatus('OTX AlienVault', 'success', `Found ${subdomains.size} subdomains`);
        return Array.from(subdomains);
    }

    // Query HackerTarget for subdomains
    async queryHackerTarget(domain) {
        console.log(`  📡 Querying HackerTarget for subdomains...`);
        this.stats.apiCalls++;
        
        const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
        
        if (!response.ok) {
            const errorMsg = `Service unavailable (${response.status})`;
            this.notifyAPIStatus('HackerTarget', 'error', errorMsg);
            throw new Error(`HackerTarget query failed: ${response.status}`);
        }

        const text = await response.text();
        const subdomains = new Set();
        
        // Parse CSV format
        const lines = text.split('\n').filter(line => line.trim());
        for (const line of lines) {
            const parts = line.split(',');
            if (parts.length >= 1) {
                const subdomain = parts[0].trim();
                if (subdomain.endsWith(`.${domain}`) && subdomain !== domain) {
                    subdomains.add(subdomain);
                    console.log(`    ✅ Found subdomain from HackerTarget: ${subdomain}`);
                    // Process immediately when discovered
                    this.notifySubdomainDiscovered(subdomain, 'HackerTarget');
                    this.processSubdomainImmediately(subdomain, 'HackerTarget');
                }
            }
        }
        
        this.notifyAPIStatus('HackerTarget', 'success', `Found ${subdomains.size} subdomains`);
        return Array.from(subdomains);
    }



    // Analyze subdomains
    async analyzeSubdomains(subdomains) {
        const results = [];
        
        console.log(`🔍 Analyzing ${subdomains.length} subdomains...`);
        
        for (const subdomain of subdomains) {
            try {
                console.log(`  📡 Querying DNS for subdomain: ${subdomain}`);
                // Query for both A and CNAME records to detect redirects
                const records = await this.queryDNS(subdomain);
                if (records && records.length > 0) {
                    // Check for CNAME records first
                    const cnameRecords = records.filter(r => r.type === 5); // CNAME type
                    const aRecords = records.filter(r => r.type === 1); // A type
                    
                    if (cnameRecords.length > 0) {
                        const cnameTarget = cnameRecords[0].data;
                        
                        // Check if this is a redirect to main domain
                        if (this.isCNAMEToMainDomain(cnameTarget)) {
                            console.log(`  🔄 Redirect detected: ${subdomain} → ${cnameTarget} (main domain)`);
                            results.push({
                                subdomain: subdomain,
                                records: records,
                                isRedirectToMain: true,
                                redirectTarget: cnameTarget,
                                ip: null
                            });
                            continue; // Skip further analysis for redirects
                        }
                        
                        // Regular CNAME (not to main domain)
                        console.log(`  🔗 Subdomain ${subdomain} has CNAME to ${cnameTarget}`);
                        
                        // Detect third-party service from CNAME target
                        const detectedService = this.detectPrimaryService(cnameTarget);
                        
                        const subdomainResult = {
                            subdomain: subdomain,
                            records: records,
                            ip: null, // CNAME doesn't have direct IP
                            cnameTarget: cnameTarget
                        };
                        
                        // Add service information if detected
                        if (detectedService) {
                            subdomainResult.detectedService = detectedService;
                            console.log(`  🎯 Detected service: ${detectedService.name} (${detectedService.category}) for ${subdomain}`);
                        }
                        
                        results.push(subdomainResult);
                    } else if (aRecords.length > 0) {
                        // Check if the record data is an IP address
                        const recordData = aRecords[0].data;
                        const isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(recordData);
                        
                        if (isIP) {
                            results.push({
                                subdomain: subdomain,
                                records: records,
                                ip: recordData
                            });
                            console.log(`  ✅ Subdomain ${subdomain} resolved to IP ${recordData}`);
                        } else {
                            console.log(`  ⚠️  Subdomain ${subdomain} resolved to domain ${recordData} (not an IP)`);
                            results.push({
                                subdomain: subdomain,
                                records: records,
                                ip: null
                            });
                        }
                    } else {
                        console.log(`  ⚠️  Subdomain ${subdomain} has no A or CNAME records`);
                        results.push({
                            subdomain: subdomain,
                            records: records,
                            ip: null
                        });
                    }
                } else {
                    console.log(`  ⚠️  Subdomain ${subdomain} has no DNS records`);
                    results.push({
                        subdomain: subdomain,
                        records: [],
                        ip: null
                    });
                }
            } catch (error) {
                console.warn(`  ❌ Failed to analyze subdomain ${subdomain}:`, error.message);
                results.push({
                    subdomain: subdomain,
                    records: [],
                    ip: null
                });
            }
        }

        console.log(`📊 Subdomain analysis complete: ${results.length}/${subdomains.length} subdomains resolved`);
        return results;
    }

    // Get ASN information for IP with multiple fallback sources
    async getASNInfo(ip) {
        const providers = [
            {
                name: 'ipinfo.io',
                url: `https://ipinfo.io/${ip}/json`,
                transform: (data) => ({
                    asn: data.org || 'Unknown',
                    isp: data.org || 'Unknown',
                    location: data.country || 'Unknown',
                    city: data.city || 'Unknown'
                })
            },
            {
                name: 'ip-api.com',
                url: `http://ip-api.com/json/${ip}`,
                transform: (data) => ({
                    asn: data.as || 'Unknown',
                    isp: data.isp || 'Unknown',
                    location: data.countryCode || 'Unknown',
                    city: data.city || 'Unknown'
                })
            },
            {
                name: 'ipapi.co',
                url: `https://ipapi.co/${ip}/json/`,
                transform: (data) => ({
                    asn: data.asn || 'Unknown',
                    isp: data.org || 'Unknown',
                    location: data.country_code || 'Unknown',
                    city: data.city || 'Unknown'
                })
            }
        ];

        for (const provider of providers) {
            try {
                const response = await fetch(provider.url, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'User-Agent': '3rdPartyTracer/1.0'
                    }
                });

                if (!response.ok) {
                    console.warn(`Provider ${provider.name} failed for ${ip}: ${response.status}`);
                    continue;
                }

                const data = await response.json();
                
                // Check if we got valid data
                if (data && (data.asn || data.org || data.as)) {
                    const result = provider.transform(data);
                    console.log(`✅ ASN info for ${ip} from ${provider.name}:`, result);
                    return result;
                }
            } catch (error) {
                console.warn(`Provider ${provider.name} error for ${ip}:`, error.message);
                continue;
            }
        }

        // All providers failed
        console.warn(`❌ All ASN providers failed for ${ip}`);
        return {
            asn: 'Unknown',
            isp: 'Unknown',
            location: 'Unknown',
            city: 'Unknown'
        };
    }

    // Detect subdomain takeover
    async detectTakeover(subdomain, cname) {
        try {
            const records = await this.queryDNS(cname, 'A');
            if (!records || records.length === 0) {
                return {
                    subdomain: subdomain,
                    cname: cname,
                    takeover: true,
                    risk: 'high',
                    description: 'CNAME target does not resolve'
                };
            }
            return null;
        } catch (error) {
            console.warn(`Failed to check takeover for ${subdomain}:`, error);
            return null;
        }
    }
}

// Rate limiter for DNS queries
class RateLimiter {
    constructor(maxRequests = 10, timeWindow = 1000) {
        this.maxRequests = maxRequests;
        this.timeWindow = timeWindow;
        this.requests = [];
    }

    async throttle() {
        const now = Date.now();
        this.requests = this.requests.filter(time => now - time < this.timeWindow);
        
        if (this.requests.length >= this.maxRequests) {
            const oldestRequest = this.requests[0];
            const waitTime = this.timeWindow - (now - oldestRequest);
            await new Promise(resolve => setTimeout(resolve, waitTime));
        }
        
        this.requests.push(now);
    }
} 