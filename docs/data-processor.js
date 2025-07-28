// Data Processing Engine
class DataProcessor {
    constructor() {
        this.processedData = {
            services: new Map(),
            subdomains: new Map(),
            redirectsToMain: [],
            historicalRecords: [],
            dnsRecords: []
        };
    }

    // Process and consolidate all analysis results
    processAnalysisResults(mainDomainResults, subdomainResults, historicalRecords, dnsRecords = []) {
        // Clear previous data
        this.clearProcessedData();

        // Process main domain services
        if (mainDomainResults?.services) {
            this.processServices(mainDomainResults.services, mainDomainResults.domain);
        }

        // Process subdomains and separate redirects
        const { regularSubdomains, redirects } = this.separateRedirects(subdomainResults);
        
        // Store redirects
        this.processedData.redirectsToMain = redirects;

        // Process regular subdomains (these are active subdomains with DNS records)
        for (const subdomain of regularSubdomains) {
            this.processSubdomain(subdomain);
        }

        // Process historical records (these are inactive subdomains from CT logs)
        this.processedData.historicalRecords = this.deduplicateHistoricalRecords(historicalRecords);
        
        // Store DNS records separately from services
        this.processedData.dnsRecords = dnsRecords || [];

        console.log(`📊 Data processing complete: ${regularSubdomains.length} active subdomains, ${historicalRecords.length} historical records`);

        return this.getProcessedData();
    }

    // Separate redirects from regular subdomains
    separateRedirects(subdomainResults) {
        const regularSubdomains = [];
        const redirects = [];

        for (const subdomain of subdomainResults) {
            if (subdomain.isRedirectToMain) {
                redirects.push({
                    subdomain: subdomain.subdomain,
                    redirectTarget: subdomain.redirectTarget,
                    source: 'batch-analysis'
                });
            } else {
                regularSubdomains.push(subdomain);
            }
        }

        return { regularSubdomains, redirects };
    }

    // Process services and add to consolidated map
    processServices(services, sourceSubdomain = null) {
        for (const service of services) {
            const serviceKey = this.generateServiceKey(service);
            
            if (this.processedData.services.has(serviceKey)) {
                // Merge with existing service
                this.mergeService(this.processedData.services.get(serviceKey), service, sourceSubdomain);
            } else {
                // Add new service
                this.processedData.services.set(serviceKey, this.createServiceEntry(service, sourceSubdomain));
            }
        }
    }

    // Process individual subdomain
    processSubdomain(subdomain) {
        const subdomainKey = subdomain.subdomain;
        
        // Create standardized subdomain data with safe defaults
        const subdomainData = {
            subdomain: subdomain.subdomain,
            records: subdomain.records || {},
            ipAddresses: subdomain.ip ? [subdomain.ip] : [],
            cnameChain: subdomain.cnameChain || [],
            cnameTarget: subdomain.cnameTarget || null,
            primaryService: subdomain.primaryService || null,
            infrastructure: subdomain.infrastructure || null,
            vendor: (subdomain.vendor && typeof subdomain.vendor === 'object') ? 
                subdomain.vendor : { vendor: 'Unknown', category: 'Unknown' },
            takeover: subdomain.takeover || null,
            status: 'analyzed'
        };

        // Process CNAME-detected service if available
        if (subdomain.detectedService) {
            console.log(`🔧 Processing CNAME-detected service: ${subdomain.detectedService.name} for ${subdomain.subdomain}`);
            
            // Convert detected service to service entry format
            const serviceEntry = {
                name: subdomain.detectedService.name,
                description: subdomain.detectedService.description,
                category: subdomain.detectedService.category,
                confidence: 'high',
                evidenceType: 'CNAME',
                records: [
                    {
                        type: 'CNAME',
                        subdomain: subdomain.subdomain,
                        data: subdomain.cnameTarget
                    }
                ]
            };
            
            // Add the service to our services collection
            this.processServices([serviceEntry], subdomain.subdomain);
            
            // Link the primary service to the subdomain
            subdomainData.primaryService = {
                name: subdomain.detectedService.name,
                category: subdomain.detectedService.category
            };
        }

        this.processedData.subdomains.set(subdomainKey, subdomainData);

        // Process services from this subdomain
        if (subdomain.detectedServices) {
            this.processServices(subdomain.detectedServices, subdomain.subdomain);
        }

        // Process primary service if exists
        if (subdomain.primaryService) {
            const primaryServiceData = {
                name: subdomain.primaryService.name,
                category: subdomain.primaryService.category,
                description: subdomain.primaryService.description,
                records: this.buildCNAMERecords(subdomain),
                recordTypes: ['CNAME']
            };
            this.processServices([primaryServiceData], subdomain.subdomain);
        }

        // Process vendor-based service if no primary service
        if (!subdomain.primaryService && 
            subdomainData.vendor && 
            subdomainData.vendor.vendor && 
            subdomainData.vendor.vendor !== 'Unknown' &&
            subdomainData.ipAddresses.length > 0) {
            const vendorService = {
                name: subdomainData.vendor.vendor,
                category: 'infrastructure',
                description: 'Infrastructure service based on IP classification',
                records: [{
                    type: 1, // A record
                    data: subdomainData.ipAddresses[0], // Use standardized ipAddresses array
                    subdomain: subdomain.subdomain
                }],
                recordTypes: ['A']
            };
            this.processServices([vendorService], subdomain.subdomain);
        }
    }

    // Build CNAME records from subdomain chain data
    buildCNAMERecords(subdomain) {
        const cnameRecords = [];
        
        if (subdomain.cnameChain && subdomain.cnameChain.length > 0) {
            subdomain.cnameChain.forEach(link => {
                cnameRecords.push({
                    type: 5, // CNAME
                    data: link.to,
                    subdomain: subdomain.subdomain,
                    TTL: link.ttl || null
                });
            });
        } else if (subdomain.cnameTarget) {
            cnameRecords.push({
                type: 5, // CNAME
                data: subdomain.cnameTarget,
                subdomain: subdomain.subdomain
            });
        }
        
        return cnameRecords;
    }

    // Generate unique service key
    generateServiceKey(service) {
        // For vendor consolidation, use only name for certain services
        const vendorServices = ['Amazon AWS', 'Microsoft Azure', 'Google Cloud Platform', 'DigitalOcean'];
        
        if (vendorServices.includes(service.name)) {
            return service.name.toLowerCase().replace(/\s+/g, '-');
        }
        
        return `${service.name}-${service.category}`.toLowerCase().replace(/\s+/g, '-');
    }

    // Create new service entry
    createServiceEntry(service, sourceSubdomain = null) {
        return {
            name: service.name,
            category: service.category,
            description: service.description,
            records: service.records || [],
            recordTypes: service.recordTypes || [],
            sourceSubdomains: sourceSubdomain ? [sourceSubdomain] : [],
            infrastructure: service.infrastructure || null,
            isInfrastructure: service.isInfrastructure || false,
            primaryService: service.primaryService || null
        };
    }

    // Merge services
    mergeService(existingService, newService, sourceSubdomain) {
        // Add source subdomain if not already present
        if (sourceSubdomain && !existingService.sourceSubdomains.includes(sourceSubdomain)) {
            existingService.sourceSubdomains.push(sourceSubdomain);
        }

        // Merge records
        if (newService.records) {
            existingService.records = [...existingService.records, ...newService.records];
        }

        // Merge record types
        if (newService.recordTypes) {
            for (const recordType of newService.recordTypes) {
                if (!existingService.recordTypes.includes(recordType)) {
                    existingService.recordTypes.push(recordType);
                }
            }
        }

        // Update infrastructure information
        if (newService.infrastructure) {
            existingService.infrastructure = newService.infrastructure;
        }

        // Prefer cloud category over infrastructure for vendor services
        const vendorServices = ['Amazon AWS', 'Microsoft Azure', 'Google Cloud Platform', 'DigitalOcean'];
        if (vendorServices.includes(existingService.name) && 
            newService.category === 'cloud' && 
            existingService.category === 'infrastructure') {
            existingService.category = 'cloud';
            existingService.description = newService.description || existingService.description;
        }
    }

    // Deduplicate historical records
    deduplicateHistoricalRecords(historicalRecords) {
        const recordsMap = new Map();
        const uniqueRecords = [];

        for (const record of historicalRecords) {
            const key = record.subdomain;
            
            if (!recordsMap.has(key)) {
                recordsMap.set(key, record);
                uniqueRecords.push(record);
            } else {
                // Keep the record with more information
                const existingRecord = recordsMap.get(key);
                const existingScore = this.getRecordInfoScore(existingRecord);
                const newScore = this.getRecordInfoScore(record);
                
                if (newScore > existingScore) {
                    const index = uniqueRecords.findIndex(r => r.subdomain === key);
                    if (index !== -1) {
                        uniqueRecords[index] = record;
                        recordsMap.set(key, record);
                    }
                }
            }
        }

        return uniqueRecords;
    }

    // Score record information completeness
    getRecordInfoScore(record) {
        let score = 0;
        
        if (record.issuer && record.issuer !== 'Unknown') score += 2;
        if (record.expiry && record.expiry !== 'Unknown') score += 2;
        if (record.source && record.source !== 'Unknown') score += 1;
        if (record.discovered) score += 1;
        
        // Prefer certain sources
        if (record.source === 'crt.sh') score += 1;
        if (record.source === 'Cert Spotter') score += 1;
        
        return score;
    }

    // Get services by category
    getServicesByCategory(category) {
        return Array.from(this.processedData.services.values())
            .filter(service => service.category === category);
    }

    // Get services by vendor
    getServicesByVendor(vendor) {
        return Array.from(this.processedData.services.values())
            .filter(service => this.getVendorFromService(service) === vendor);
    }

    // Get vendor from service
    getVendorFromService(service) {
        if (service.name.includes('Microsoft')) return 'Microsoft';
        if (service.name.includes('Amazon') || service.name.includes('AWS')) return 'Amazon AWS';
        if (service.name.includes('ProofPoint')) return 'ProofPoint';
        if (service.name.includes('Google')) return 'Google';
        if (service.name.includes('Cloudflare')) return 'Cloudflare';
        if (service.name.includes('DigitalOcean')) return 'DigitalOcean';
        return 'Other';
    }

    // Get all services
    getAllServices() {
        return Array.from(this.processedData.services.values());
    }

    // Get unclassified subdomains (only those that don't appear anywhere else)
    getUnclassifiedSubdomains() {
        const allServices = this.getAllServices();
        const categorizedSubdomains = new Set();
        
        // Collect all subdomains that are categorized in services
        for (const service of allServices) {
            if (service.sourceSubdomains) {
                service.sourceSubdomains.forEach(sub => categorizedSubdomains.add(sub));
            }
        }

        // Also collect subdomains that appear in CNAME mappings
        const cnameSubdomains = this.getCNAMEMappings();
        const cnameSubdomainNames = new Set(cnameSubdomains.map(sub => sub.subdomain));

        // Return subdomains that are:
        // 1. Not categorized in any service
        // 2. Not in CNAME mappings
        // 3. Have IP addresses (not historical)
        // 4. Not redirects to main domain
        const unclassified = Array.from(this.processedData.subdomains.values()).filter(subdomain => 
            !categorizedSubdomains.has(subdomain.subdomain) && 
            !cnameSubdomainNames.has(subdomain.subdomain) &&
            subdomain.ipAddresses.length > 0 &&
            !this.hasSignificantCNAME(subdomain)
        );

        console.log(`🔍 Subdomain classification: ${categorizedSubdomains.size} in services, ${cnameSubdomainNames.size} in CNAME mappings, ${unclassified.length} unclassified`);
        
        return unclassified;
    }

    // Check if subdomain has significant CNAME (for CNAME mappings section)
    hasSignificantCNAME(subdomain) {
        return (subdomain.cnameTarget && subdomain.cnameTarget !== subdomain.subdomain) ||
               (subdomain.cnameChain && subdomain.cnameChain.length > 0);
    }

    // Get CNAME mappings
    getCNAMEMappings() {
        const allServices = this.getAllServices();
        const categorizedSubdomains = new Set();
        
        // Collect categorized subdomains
        for (const service of allServices) {
            if (service.sourceSubdomains) {
                service.sourceSubdomains.forEach(sub => categorizedSubdomains.add(sub));
            }
        }

        // Return subdomains with CNAME that are not categorized
        return Array.from(this.processedData.subdomains.values()).filter(subdomain => 
            this.hasSignificantCNAME(subdomain) && 
            !categorizedSubdomains.has(subdomain.subdomain)
        );
    }

    // Calculate statistics
    calculateStats() {
        const allActiveSubdomains = this.getActiveSubdomains();
        const unclassifiedSubdomains = this.getUnclassifiedSubdomains();
        const cnameSubdomains = this.getCNAMEMappings();
        
        const stats = {
            totalServices: this.processedData.services.size,
            totalSubdomains: allActiveSubdomains.length, // Total active subdomains (not just unclassified)
            totalUnclassifiedSubdomains: unclassifiedSubdomains.length, // For internal use
            totalCNAMESubdomains: cnameSubdomains.length, // For internal use
            totalHistoricalRecords: this.processedData.historicalRecords.length,
            totalProviders: new Set(this.getAllServices().map(s => this.getVendorFromService(s))).size,
            totalRedirects: this.processedData.redirectsToMain.length
        };

        console.log(`📊 Stats calculated: ${stats.totalServices} services, ${stats.totalSubdomains} active subdomains (${stats.totalUnclassifiedSubdomains} unclassified, ${stats.totalCNAMESubdomains} CNAME mappings), ${stats.totalProviders} providers, ${stats.totalHistoricalRecords} historical`);

        return stats;
    }

    // Get active subdomains only (exclude historical records)
    getActiveSubdomains() {
        return Array.from(this.processedData.subdomains.values()).filter(subdomain =>
            (subdomain.ipAddresses && subdomain.ipAddresses.length > 0) ||
            subdomain.ip ||
            this.hasSignificantCNAME(subdomain)
        );
    }

    // Get processed data
    getProcessedData() {
        return {
            services: this.processedData.services,
            subdomains: this.processedData.subdomains,
            redirectsToMain: this.processedData.redirectsToMain,
            historicalRecords: this.processedData.historicalRecords,
            stats: this.calculateStats()
        };
    }

    // Clear all processed data
    clearProcessedData() {
        this.processedData.services.clear();
        this.processedData.subdomains.clear();
        this.processedData.redirectsToMain = [];
        this.processedData.historicalRecords = [];
        this.processedData.dnsRecords = [];
    }

    // Group subdomains by provider (for display)
    groupSubdomainsByProvider(subdomains) {
        const providerMap = new Map();
        
        for (const subdomain of subdomains) {
            let vendor = 'Unknown';
            
            if (subdomain.primaryService && subdomain.primaryService.name) {
                vendor = subdomain.primaryService.name;
            } else if (subdomain.vendor && 
                       typeof subdomain.vendor === 'object' && 
                       subdomain.vendor.vendor) {
                vendor = subdomain.vendor.vendor;
            }
            
            if (!providerMap.has(vendor)) {
                providerMap.set(vendor, {
                    vendor: vendor,
                    subdomains: [],
                    totalSubdomains: 0,
                    ips: new Set()
                });
            }
            
            const provider = providerMap.get(vendor);
            provider.subdomains.push(subdomain);
            provider.totalSubdomains++;
            
            if (subdomain.ipAddresses.length > 0) {
                subdomain.ipAddresses.forEach(ip => provider.ips.add(ip));
            }
        }
        
        // Convert to array format
        return Array.from(providerMap.values()).map(provider => ({
            ...provider,
            ips: Array.from(provider.ips),
            uniqueIPs: provider.ips.size
        }));
    }
} 