// Main Application Logic
class App {
    constructor() {
        this.results = {
            services: new ServiceRegistry(),
            subdomains: [],
            security: {
                takeovers: [],
                dnsIssues: [],
                emailIssues: [],
                cloudIssues: []
            },
            interestingFindings: [],
            stats: {
                totalServices: 0,
                totalSubdomains: 0,
                totalProviders: 0,
                totalTakeovers: 0,
                totalHistoricalRecords: 0
            }
        };
        
        this.dnsAnalyzer = new DNSAnalyzer();
        this.serviceDetector = new ServiceDetector();
        this.subdomainRegistry = new SubdomainRegistry();
        
        // Initialize API notifications
        this.apiNotifications = [];
        
        // Debug utility
        this.debug = {
            isEnabled: false,
            log: (message, data = null) => {
                if (this.debug.isEnabled) {
                    if (data) {
                        console.log(`🔍 DEBUG: ${message}`, data);
                    } else {
                        console.log(`🔍 DEBUG: ${message}`);
                    }
                }
            },
            logJSON: (message, data) => {
                if (this.debug.isEnabled) {
                    console.log(`🔍 DEBUG: ${message}`);
                    console.log(JSON.stringify(data, null, 2));
                }
            },
            logStats: (stats) => {
                if (this.debug.isEnabled) {
                    console.log('📊 DEBUG: Final Statistics');
                    console.log(JSON.stringify(stats, null, 2));
                } else {
                    console.log(`📊 Analysis Complete: ${stats.totalServices} services, ${stats.totalSubdomains} subdomains, ${stats.totalTakeovers} security issues`);
                }
            }
        };
    }

    // Main analysis function
    async analyzeDomain(domain) {
        // Check debug mode
        const debugCheckbox = document.getElementById('debugMode');
        this.debug.isEnabled = debugCheckbox ? debugCheckbox.checked : false;
        
        if (this.debug.isEnabled) {
            console.log('🔍 DEBUG MODE ENABLED - Detailed output will be shown');
        }
        
        console.log(`🚀 Starting analysis for domain: ${domain}`);
        
        // Reset all internal state for new analysis
        this.dnsAnalyzer.resetStats();
        this.dnsAnalyzer.setCurrentDomain(domain);
        
        this.currentDomain = domain;
        this.results = {
            domain: domain,
            mainDomain: {},
            subdomains: new SubdomainRegistry(), // Phase 1: Replace array with registry
            historicalRecords: [],
            services: new ServiceRegistry(), // Phase 2: Replace arrays with registry
            interestingFindings: [],
            redirectsToMain: [], // Subdomains that redirect to main domain
            security: {
                takeovers: [],
                vulnerabilities: [],
                dnsIssues: [],
                emailIssues: [],
                cloudIssues: []
            },
            stats: {
                totalServices: 0,
                totalSubdomains: 0,
                totalTakeovers: 0,
                totalHistoricalRecords: 0
            }
        };
        
        // Clear all registries for new analysis
        this.results.subdomains.clear();
        this.results.services.clear();
        
        // Reset API notifications for new analysis
        this.apiNotifications = [];
        
        console.log('🧹 All internal arrays and registries cleared for new analysis');

        // Set up real-time subdomain processing
        this.setupRealTimeProcessing();
        
        // Set up API notification handling
        this.dnsAnalyzer.onAPINotification((apiName, status, message) => {
            this.addAPINotification(apiName, status, message);
        });

        try {
            // Start certificate transparency queries early (non-blocking)
            console.log(`🔍 Starting certificate transparency queries early...`);
            const ctPromise = this.dnsAnalyzer.startCTQueries(domain);
            
            // Show progress
            this.updateProgress(10, 'Analyzing main domain...');
            
            // Analyze main domain
            const mainDomainResults = await this.dnsAnalyzer.analyzeMainDomain(domain);
            this.results.mainDomain = mainDomainResults;
            this.debug.logJSON('Main domain analysis complete. Records found:', mainDomainResults.records || {});
            console.log(`📋 Main domain analysis complete. Records found:`, Object.keys(mainDomainResults.records || {}));
            
            // Detect services from main domain
            this.updateProgress(30, 'Detecting services...');
            console.log(`🔍 Detecting services from main domain records...`);
            // Add domain information to each record
            const mainDomainRecordsWithDomain = {};
            if (mainDomainResults.records && typeof mainDomainResults.records === 'object') {
                for (const [recordType, records] of Object.entries(mainDomainResults.records)) {
                    // Ensure records is an array before mapping
                    const recordsArray = Array.isArray(records) ? records : [];
                    mainDomainRecordsWithDomain[recordType] = recordsArray.map(record => ({
                        ...record,
                        subdomain: domain
                    }));
                }
            }
            const services = this.serviceDetector.detectServices(mainDomainRecordsWithDomain);
            this.categorizeServices(services, domain);
            this.debug.logJSON('Services detected from main domain:', services);
            console.log(`✅ Found ${services.length} services from main domain`);
            
            // Wait for certificate transparency results (they should be ready by now)
            this.updateProgress(50, 'Discovering subdomains...');
            console.log(`📊 Step 2: Discovering subdomains from certificate transparency...`);
            const subdomains = await ctPromise;
            this.debug.logJSON('Certificate transparency subdomains found:', subdomains);
            console.log(`✅ Certificate transparency complete. Found ${subdomains.length} subdomains`);
            
            // Analyze subdomains
            this.updateProgress(70, 'Analyzing subdomains...');
            console.log(`📊 Step 3: Analyzing subdomains...`);
            const subdomainResults = await this.dnsAnalyzer.analyzeSubdomains(subdomains);
            this.debug.logJSON('Subdomain analysis results:', subdomainResults);
            
            // Phase 1: Use new SubdomainRegistry for batch processing
            const redirectsToMain = [];
            
            for (const subdomain of subdomainResults) {
                // Check if this is a redirect to main domain
                if (subdomain.isRedirectToMain) {
                    redirectsToMain.push({
                        subdomain: subdomain.subdomain,
                        redirectTarget: subdomain.redirectTarget,
                        source: 'batch-analysis'
                    });
                    console.log(`🔄 Redirect to main domain: ${subdomain.subdomain} → ${subdomain.redirectTarget}`);
                } else {
                    // Convert to new format
                    const subdomainData = {
                        records: subdomain.records || {},
                        ipAddresses: subdomain.ip ? [subdomain.ip] : [],
                        cnameChain: subdomain.cnameChain || [],
                        primaryService: subdomain.primaryService || null,
                        infrastructure: subdomain.infrastructure || null,
                        detectedServices: subdomain.detectedServices || [],
                        vendor: subdomain.vendor || { vendor: 'Unknown', category: 'Unknown' },
                        takeover: subdomain.takeover || null,
                        vulnerabilities: subdomain.vulnerabilities || [],
                        status: 'analyzed'
                    };
                    
                    // Add to registry (handles merging automatically)
                    this.results.subdomains.addSubdomain(subdomain.subdomain, 'batch-analysis', subdomainData);
                }
            }
            
            // Store redirects separately
            this.results.redirectsToMain = redirectsToMain;
            
            console.log(`✅ Subdomain analysis complete: ${subdomainResults.length} subdomains processed`);
            
            // Get ASN information for subdomain IPs
            this.updateProgress(80, 'Getting ASN information...');
            console.log(`📊 Step 4: Getting ASN information for subdomain IPs...`);
            
            for (const subdomain of subdomainResults) {
                if (subdomain.ip) {
                    console.log(`  📡 Getting ASN info for IP: ${subdomain.ip}`);
                    const asnInfo = await this.dnsAnalyzer.getASNInfo(subdomain.ip);
                    subdomain.vendor = this.serviceDetector.classifyVendor(asnInfo);
                    console.log(`  ✅ ASN info for ${subdomain.ip}: ${asnInfo.org || 'Unknown'}`);
                } else {
                    console.log(`  ⚠️  Skipping ASN lookup for ${subdomain.subdomain} (no IP address)`);
                    subdomain.vendor = { vendor: 'Unknown', category: 'Unknown' };
                }
            }
            
            // Detect security issues
            this.updateProgress(90, 'Analyzing security...');
            console.log(`📊 Step 5: Analyzing security and takeover detection...`);
            
            // Comprehensive security analysis
            console.log(`🔒 Step 6: Performing comprehensive security analysis...`);
            
            // Check for subdomain takeovers
            if (mainDomainResults && mainDomainResults.records && mainDomainResults.records.CNAME) {
                const takeovers = this.serviceDetector.detectTakeoverFromCNAME(mainDomainResults.records.CNAME);
                this.results.security.takeovers.push(...takeovers);
                console.log(`🔒 Found ${takeovers.length} potential takeover vulnerabilities`);
            }
            
            // Check for DNS security issues
            if (mainDomainResults && mainDomainResults.records) {
                const dnsIssues = this.serviceDetector.detectDNSSecurityIssues(mainDomainResults.records);
                this.results.security.dnsIssues = dnsIssues;
                this.debug.logJSON('DNS security issues found:', dnsIssues);
                console.log(`🔒 Found ${dnsIssues.length} DNS security issues`);
            }
            
            // Check for email security issues
            if (mainDomainResults && mainDomainResults.records) {
                const emailIssues = this.serviceDetector.detectEmailSecurityIssues(mainDomainResults.records);
                this.results.security.emailIssues = emailIssues;
                this.debug.logJSON('Email security issues found:', emailIssues);
                console.log(`🔒 Found ${emailIssues.length} email security issues`);
            }
            
            // Check for interesting infrastructure findings
            const infrastructureFindings = this.serviceDetector.detectInterestingInfrastructureFindings(
                mainDomainResults?.records || {}, 
                subdomainResults
            );
            this.results.interestingFindings = infrastructureFindings;
            this.debug.logJSON('Interesting infrastructure findings:', infrastructureFindings);
            console.log(`🔍 Found ${infrastructureFindings.length} interesting infrastructure patterns`);
            
            // Check for cloud security issues
            const cloudIssues = this.serviceDetector.detectCloudSecurityIssues(
                mainDomainResults?.records || {}, 
                subdomainResults
            );
            this.results.security.cloudIssues = cloudIssues;
            this.debug.logJSON('Cloud security issues found:', cloudIssues);
            console.log(`🔒 Found ${cloudIssues.length} cloud security issues`);
            
            // Detect services from subdomains
            console.log(`🔍 Detecting services from subdomain records...`);
            for (const subdomain of subdomainResults) {
                if (subdomain.records) {
                    // Add subdomain information to each record
                    const recordsWithSubdomain = {};
                    if (subdomain.records && typeof subdomain.records === 'object') {
                        for (const [recordType, records] of Object.entries(subdomain.records)) {
                            // Ensure records is an array before mapping
                            const recordsArray = Array.isArray(records) ? records : [];
                            recordsWithSubdomain[recordType] = recordsArray.map(record => ({
                                ...record,
                                subdomain: subdomain.subdomain
                            }));
                        }
                    }
                    const services = this.serviceDetector.detectServices(recordsWithSubdomain);
                    this.categorizeServices(services, subdomain.subdomain);
                    this.dnsAnalyzer.stats.servicesDetected += services.length;
                }
                
                // Categorize primary service and infrastructure
                if (subdomain.primaryService) {
                    // Build complete CNAME chain record
                    const cnameRecords = [];
                    if (subdomain.cnameChain && subdomain.cnameChain.length > 0) {
                        // Add each step in the CNAME chain
                        subdomain.cnameChain.forEach((link, index) => {
                            cnameRecords.push({
                                type: 5, // CNAME
                                data: link.to,
                                subdomain: subdomain.subdomain,
                                TTL: link.ttl || null
                            });
                        });
                    } else if (subdomain.cnameTarget) {
                        // Fallback to single CNAME target
                        cnameRecords.push({
                            type: 5, // CNAME
                            data: subdomain.cnameTarget,
                            subdomain: subdomain.subdomain
                        });
                    }
                    
                    const primaryService = {
                        name: subdomain.primaryService.name,
                        category: subdomain.primaryService.category,
                        description: subdomain.primaryService.description,
                        records: cnameRecords,
                        recordTypes: ['CNAME'],
                        infrastructure: subdomain.infrastructure // Include infrastructure info
                    };
                    this.categorizeServices([primaryService], subdomain.subdomain);
                    this.dnsAnalyzer.stats.servicesDetected++;
                }
                
                // Categorize subdomains with IP-based vendor classification (ASN)
                if (subdomain.vendor && subdomain.vendor.vendor && subdomain.vendor.vendor !== 'Unknown' && !subdomain.primaryService) {
                    // Create a service based on the vendor classification
                    const vendorService = {
                        name: subdomain.vendor.vendor,
                        category: 'infrastructure',
                        description: `Infrastructure service based on IP classification`,
                        records: [{
                            type: 1, // A record
                            data: subdomain.ip,
                            subdomain: subdomain.subdomain,
                            TTL: null
                        }],
                        recordTypes: ['A'],
                        isIPBased: true
                    };
                    this.categorizeServices([vendorService], subdomain.subdomain);
                    this.dnsAnalyzer.stats.servicesDetected++;
                }
                
                // Only categorize infrastructure separately if it's different from primary service AND not already categorized
                if (subdomain.infrastructure && subdomain.primaryService && 
                    subdomain.infrastructure.name !== subdomain.primaryService.name) {
                    
                    // Check if this infrastructure service is already categorized as a primary service
                    const existingServices = this.results.services.cloud || [];
                    const isAlreadyCategorized = existingServices.some(existing => 
                        existing.name === subdomain.infrastructure.name
                    );
                    
                    if (!isAlreadyCategorized) {
                        // Build complete CNAME chain record for infrastructure
                        const cnameRecords = [];
                        if (subdomain.cnameChain && subdomain.cnameChain.length > 0) {
                            // Add each step in the CNAME chain
                            subdomain.cnameChain.forEach((link, index) => {
                                cnameRecords.push({
                                    type: 5, // CNAME
                                    data: link.to,
                                    subdomain: subdomain.subdomain,
                                    TTL: link.ttl || null
                                });
                            });
                        } else if (subdomain.cnameTarget) {
                            // Fallback to single CNAME target
                            cnameRecords.push({
                                type: 5, // CNAME
                                data: subdomain.cnameTarget,
                                subdomain: subdomain.subdomain
                            });
                        }
                        
                        const infrastructureService = {
                            name: subdomain.infrastructure.name,
                            category: subdomain.infrastructure.category,
                            description: subdomain.infrastructure.description,
                            records: cnameRecords,
                            recordTypes: ['CNAME'],
                            isInfrastructure: true,
                            primaryService: subdomain.primaryService.name
                        };
                        this.categorizeServices([infrastructureService], subdomain.subdomain);
                        this.dnsAnalyzer.stats.servicesDetected++;
                    }
                }
            }
            
            this.updateProgress(100, 'Analysis complete!');
            console.log(`🎉 Analysis complete for ${domain}!`);
            
            // Collect historical records
            this.results.historicalRecords = this.dnsAnalyzer.getHistoricalRecords();
            this.results.stats.totalHistoricalRecords = this.results.historicalRecords.length;
            console.log(`📜 Found ${this.results.historicalRecords.length} historical records`);
            
            // Calculate stats
            this.calculateStats();
            
            // Final check: Filter out already categorized items before displaying results
            this.filterUncategorizedItems();
            
            // Display results
            this.displayResults();
            
            // Print final statistics
            this.dnsAnalyzer.printStats();
            
            // Debug: Log final results structure
            this.debug.logJSON('Final analysis results:', this.results);
            
            // Phase 2: Print complete JSON structure
            console.log('🎯 COMPLETE DATA STRUCTURE JSON:');
            console.log('='.repeat(60));
            
            // Convert registries to serializable format for JSON
            const completeStructure = {
                domain: this.results.domain,
                analysisStartTime: this.results.analysisStartTime,
                analysisEndTime: this.results.analysisEndTime,
                mainDomain: this.results.mainDomain,
                subdomains: {
                    registry: this.results.subdomains.getAllSubdomains(),
                    stats: this.results.subdomains.getStats()
                },
                services: {
                    registry: this.results.services.getAllServices(),
                    stats: this.results.services.getStats(),
                    categories: Object.fromEntries(
                        Object.entries(this.results.services.categories).map(([category, serviceIds]) => [
                            category, 
                            Array.from(serviceIds).map(id => this.results.services.services.get(id))
                        ])
                    )
                },
                security: this.results.security,
                stats: this.results.stats,
                apiStatus: this.results.apiStatus
            };
            
            console.log(JSON.stringify(completeStructure, null, 2));
            console.log('='.repeat(60));
            
        } catch (error) {
            console.error('❌ Analysis failed:', error);
            this.showError('Analysis failed: ' + error.message);
        }
    }

    // Set up real-time subdomain processing
    setupRealTimeProcessing() {
        // Register callback for subdomain discovery
        this.dnsAnalyzer.onSubdomainDiscovered((subdomain, source, analysis) => {
            console.log(`🆕 Real-time subdomain update: ${subdomain} from ${source}`);
            
            if (analysis) {
                // Phase 1: Use new SubdomainRegistry methods
                // Convert analysis to new format
                const subdomainData = {
                    records: analysis.records || {},
                    ipAddresses: analysis.ip ? [analysis.ip] : [],
                    cnameChain: analysis.cnameChain || [],
                    primaryService: analysis.primaryService || null,
                    infrastructure: analysis.infrastructure || null,
                    detectedServices: analysis.detectedServices || [],
                    vendor: analysis.vendor || { vendor: 'Unknown', category: 'Unknown' },
                    takeover: analysis.takeover || null,
                    vulnerabilities: analysis.vulnerabilities || [],
                    status: 'analyzed'
                };
                
                // Add to registry (handles merging automatically)
                this.results.subdomains.addSubdomain(subdomain, source, subdomainData);
                
                // Detect services from the subdomain
                if (analysis.records) {
                    // Add subdomain information to each record
                    const recordsWithSubdomain = {};
                    if (analysis.records && typeof analysis.records === 'object') {
                        for (const [recordType, records] of Object.entries(analysis.records)) {
                            // Ensure records is an array before mapping
                            const recordsArray = Array.isArray(records) ? records : [];
                            recordsWithSubdomain[recordType] = recordsArray.map(record => ({
                                ...record,
                                subdomain: analysis.subdomain
                            }));
                        }
                    }
                    const services = this.serviceDetector.detectServices(recordsWithSubdomain);
                    this.categorizeServices(services, analysis.subdomain);
                    this.dnsAnalyzer.stats.servicesDetected += services.length;
                }
                
                // Categorize primary service and infrastructure
                if (analysis.primaryService) {
                    // Build complete CNAME chain record
                    const cnameRecords = [];
                    if (analysis.cnameChain && analysis.cnameChain.length > 0) {
                        // Add each step in the CNAME chain
                        analysis.cnameChain.forEach((link, index) => {
                            cnameRecords.push({
                                type: 5, // CNAME
                                data: link.to,
                                subdomain: analysis.subdomain,
                                TTL: link.ttl || null
                            });
                        });
                    } else if (analysis.cnameTarget) {
                        // Fallback to single CNAME target
                        cnameRecords.push({
                            type: 5, // CNAME
                            data: analysis.cnameTarget,
                            subdomain: analysis.subdomain
                        });
                    }
                    
                    const primaryService = {
                        name: analysis.primaryService.name,
                        category: analysis.primaryService.category,
                        description: analysis.primaryService.description,
                        records: cnameRecords,
                        recordTypes: ['CNAME'],
                        infrastructure: analysis.infrastructure // Include infrastructure info
                    };
                    this.categorizeServices([primaryService], analysis.subdomain);
                    this.dnsAnalyzer.stats.servicesDetected++;
                }
                
                // Categorize subdomains with IP-based vendor classification (ASN)
                if (analysis.vendor && analysis.vendor.vendor && analysis.vendor.vendor !== 'Unknown' && !analysis.primaryService) {
                    // Create a service based on the vendor classification
                    const vendorService = {
                        name: analysis.vendor.vendor,
                        category: 'infrastructure',
                        description: `Infrastructure service based on IP classification`,
                        records: [{
                            type: 1, // A record
                            data: analysis.ip,
                            subdomain: analysis.subdomain,
                            TTL: null
                        }],
                        recordTypes: ['A'],
                        isIPBased: true
                    };
                    this.categorizeServices([vendorService], analysis.subdomain);
                    this.dnsAnalyzer.stats.servicesDetected++;
                }
                
                // Only categorize infrastructure separately if it's different from primary service AND not already categorized
                if (analysis.infrastructure && analysis.primaryService && 
                    analysis.infrastructure.name !== analysis.primaryService.name) {
                    
                    // Check if this infrastructure service is already categorized as a primary service
                    const existingServices = this.results.services.cloud || [];
                    const isAlreadyCategorized = existingServices.some(existing => 
                        existing.name === analysis.infrastructure.name
                    );
                    
                    if (!isAlreadyCategorized) {
                        // Build complete CNAME chain record for infrastructure
                        const cnameRecords = [];
                        if (analysis.cnameChain && analysis.cnameChain.length > 0) {
                            // Add each step in the CNAME chain
                            analysis.cnameChain.forEach((link, index) => {
                                cnameRecords.push({
                                    type: 5, // CNAME
                                    data: link.to,
                                    subdomain: analysis.subdomain,
                                    TTL: link.ttl || null
                                });
                            });
                        } else if (analysis.cnameTarget) {
                            // Fallback to single CNAME target
                            cnameRecords.push({
                                type: 5, // CNAME
                                data: analysis.cnameTarget,
                                subdomain: analysis.subdomain
                            });
                        }
                        
                        const infrastructureService = {
                            name: analysis.infrastructure.name,
                            category: analysis.infrastructure.category,
                            description: analysis.infrastructure.description,
                            records: cnameRecords,
                            recordTypes: ['CNAME'],
                            isInfrastructure: true,
                            primaryService: analysis.primaryService.name
                        };
                        this.categorizeServices([infrastructureService], analysis.subdomain);
                        this.dnsAnalyzer.stats.servicesDetected++;
                    }
                }
                
                // Update stats
                this.calculateStats();
                
                // Final check: Filter out already categorized items
                this.filterUncategorizedItems();
                
                // Update UI immediately
                this.displayResults();
                
                console.log(`✅ Real-time processing complete for ${subdomain}`);
            }
        });
    }

    // Phase 2: Categorize services using new ServiceRegistry
    categorizeServices(services, sourceSubdomain = null) {
        for (const service of services) {
            // Add subdomain information to the service
            if (sourceSubdomain) {
                service.sourceSubdomain = sourceSubdomain;
            }
            
            // Use new ServiceRegistry to handle deduplication and categorization
            this.results.services.addService(service, sourceSubdomain);
        }
    }
    
    // Final check: Filter out already categorized items and deduplicate
    filterUncategorizedItems() {
        // Get all services that have been categorized
        const categorizedServices = this.results.services.getAllServices();
        const categorizedSubdomains = new Set();
        
        // Collect all subdomains that are already categorized in vendor-specific sections
        for (const service of categorizedServices) {
            if (service.sourceSubdomains) {
                service.sourceSubdomains.forEach(subdomain => {
                    categorizedSubdomains.add(subdomain);
                });
            }
        }
        
        // Mark subdomains as categorized in the registry
        const allSubdomains = this.results.subdomains.getAllSubdomains();
        for (const subdomain of allSubdomains) {
            if (categorizedSubdomains.has(subdomain.subdomain)) {
                // Mark as categorized so it won't appear in "Unknown" or "CNAME Mappings"
                subdomain.isCategorized = true;
            }
        }
        
        // Final deduplication check across all sections
        this.deduplicateAllSections();
        
        console.log(`✅ Filtered ${categorizedSubdomains.size} categorized subdomains from unknown/CNAME sections`);
    }
    
    // Deduplicate entries across all sections
    deduplicateAllSections() {
        const allSubdomains = this.results.subdomains.getAllSubdomains();
        const subdomainSections = new Map(); // Track which section each subdomain appears in
        
        // First pass: identify which section each subdomain should appear in (priority order)
        for (const subdomain of allSubdomains) {
            let section = null;
            
            // Priority 1: Vendor-specific service sections
            if (subdomain.primaryService || subdomain.cnameService || subdomain.isCategorized) {
                section = 'vendor';
            }
            // Priority 2: Historical records (no IP)
            else if (!subdomain.ip) {
                section = 'historical';
            }
            // Priority 3: Unknown section (has IP but no service)
            else if (subdomain.ip) {
                section = 'unknown';
            }
            // Priority 4: CNAME mappings (has CNAME but no service)
            else if (subdomain.cnameTarget) {
                section = 'cname';
            }
            
            if (section) {
                subdomainSections.set(subdomain.subdomain, section);
            }
        }
        
        // Second pass: mark subdomains that appear in multiple sections
        const duplicateSubdomains = new Set();
        const sectionCounts = new Map();
        
        for (const [subdomain, section] of subdomainSections) {
            if (!sectionCounts.has(subdomain)) {
                sectionCounts.set(subdomain, new Set());
            }
            sectionCounts.get(subdomain).add(section);
            
            // If a subdomain appears in multiple sections, mark it as duplicate
            if (sectionCounts.get(subdomain).size > 1) {
                duplicateSubdomains.add(subdomain);
            }
        }
        
        // Third pass: resolve duplicates by keeping only the highest priority section
        for (const subdomain of duplicateSubdomains) {
            const sections = Array.from(sectionCounts.get(subdomain));
            
            // Priority order: vendor > historical > unknown > cname
            const priorityOrder = ['vendor', 'historical', 'unknown', 'cname'];
            let highestPriority = null;
            
            for (const priority of priorityOrder) {
                if (sections.includes(priority)) {
                    highestPriority = priority;
                    break;
                }
            }
            
            // Mark subdomain to only appear in highest priority section
            const subdomainObj = allSubdomains.find(s => s.subdomain === subdomain);
            if (subdomainObj) {
                subdomainObj.dedupSection = highestPriority;
            }
        }
        
        // Fourth pass: handle historical records that appear in both CT logs and DNS analysis
        this.deduplicateHistoricalRecords();
        
        console.log(`✅ Deduplication complete: ${duplicateSubdomains.size} duplicates resolved`);
        
        // Final validation: ensure no duplicates exist in final output
        this.validateNoDuplicates();
    }
    
    // Validate that no subdomain appears in multiple sections
    validateNoDuplicates() {
        const allSubdomains = this.results.subdomains.getAllSubdomains();
        const subdomainSections = new Map();
        
        // Check vendor sections
        const vendorServices = this.results.services.getAllServices();
        for (const service of vendorServices) {
            if (service.sourceSubdomains) {
                for (const subdomain of service.sourceSubdomains) {
                    if (!subdomainSections.has(subdomain)) {
                        subdomainSections.set(subdomain, []);
                    }
                    subdomainSections.get(subdomain).push('vendor');
                }
            }
        }
        
        // Check unknown section
        const unknownSubdomains = allSubdomains.filter(subdomain => 
            !subdomain.primaryService && !subdomain.cnameService && !subdomain.isCategorized && subdomain.ip &&
            (!subdomain.dedupSection || subdomain.dedupSection === 'unknown')
        );
        for (const subdomain of unknownSubdomains) {
            if (!subdomainSections.has(subdomain.subdomain)) {
                subdomainSections.set(subdomain.subdomain, []);
            }
            subdomainSections.get(subdomain.subdomain).push('unknown');
        }
        
        // Check historical section
        const historicalSubdomains = allSubdomains.filter(subdomain => 
            !subdomain.ip && !subdomain.primaryService && !subdomain.cnameService && !subdomain.isCategorized &&
            (!subdomain.dedupSection || subdomain.dedupSection === 'historical')
        );
        for (const subdomain of historicalSubdomains) {
            if (!subdomainSections.has(subdomain.subdomain)) {
                subdomainSections.set(subdomain.subdomain, []);
            }
            subdomainSections.get(subdomain.subdomain).push('historical');
        }
        
        // Check CNAME mappings section
        const cnameSubdomains = allSubdomains.filter(sub => 
            sub.cnameTarget && !sub.primaryService && !sub.cnameService && !sub.isCategorized &&
            (!sub.dedupSection || sub.dedupSection === 'cname')
        );
        for (const subdomain of cnameSubdomains) {
            if (!subdomainSections.has(subdomain.subdomain)) {
                subdomainSections.set(subdomain.subdomain, []);
            }
            subdomainSections.get(subdomain.subdomain).push('cname');
        }
        
        // Report any duplicates found
        const duplicates = [];
        for (const [subdomain, sections] of subdomainSections) {
            if (sections.length > 1) {
                duplicates.push({ subdomain, sections });
            }
        }
        
        if (duplicates.length > 0) {
            console.warn(`⚠️  Found ${duplicates.length} subdomains still appearing in multiple sections:`, duplicates);
        } else {
            console.log(`✅ Validation complete: No duplicates found in final output`);
        }
    }
    
    // Deduplicate historical records that appear in both CT logs and DNS analysis
    deduplicateHistoricalRecords() {
        const historicalRecords = this.results.historicalRecords || [];
        const allSubdomains = this.results.subdomains.getAllSubdomains();
        
        // Get subdomains without IP from DNS analysis
        const dnsHistoricalSubdomains = allSubdomains.filter(subdomain => 
            !subdomain.ip && !subdomain.primaryService && !subdomain.cnameService && !subdomain.isCategorized
        );
        
        // Create a map to track unique CT log entries by subdomain
        const ctSubdomainsMap = new Map();
        const uniqueCTRecords = [];
        
        for (const record of historicalRecords) {
            const key = record.subdomain;
            
            if (!ctSubdomainsMap.has(key)) {
                // First occurrence of this subdomain
                ctSubdomainsMap.set(key, record);
                uniqueCTRecords.push(record);
            } else {
                // Duplicate found - keep the one with more information
                const existingRecord = ctSubdomainsMap.get(key);
                const existingInfo = this.getRecordInfoScore(existingRecord);
                const newInfo = this.getRecordInfoScore(record);
                
                if (newInfo > existingInfo) {
                    // Replace with the record that has more information
                    const index = uniqueCTRecords.findIndex(r => r.subdomain === key);
                    if (index !== -1) {
                        uniqueCTRecords[index] = record;
                        ctSubdomainsMap.set(key, record);
                    }
                }
            }
        }
        
        // Update the historical records to remove duplicates
        this.results.historicalRecords = uniqueCTRecords;
        
        // Mark DNS analysis subdomains that also appear in CT logs
        for (const subdomain of dnsHistoricalSubdomains) {
            if (ctSubdomainsMap.has(subdomain.subdomain)) {
                // This subdomain appears in both CT logs and DNS analysis
                // Mark it to only appear in CT logs (higher priority)
                subdomain.dedupSection = 'historical';
                subdomain.ctLogDuplicate = true; // Flag to skip in DNS analysis
            }
        }
        
        console.log(`✅ Historical records deduplication: ${ctSubdomainsMap.size} unique CT log entries, ${dnsHistoricalSubdomains.length} DNS analysis entries`);
    }
    
    // Helper method to score record information completeness
    getRecordInfoScore(record) {
        let score = 0;
        
        // Prefer records with more complete information
        if (record.issuer && record.issuer !== 'Unknown') score += 2;
        if (record.expiry && record.expiry !== 'Unknown') score += 2;
        if (record.source && record.source !== 'Unknown') score += 1;
        if (record.discovered) score += 1;
        
        // Prefer certain sources over others
        if (record.source === 'crt.sh') score += 1;
        if (record.source === 'Cert Spotter') score += 1;
        
        return score;
    }
    
    // Phase 2: AWS service handling is now done by ServiceRegistry
    // Removed old AWS service methods - now handled automatically by ServiceRegistry

    // Consolidate subdomains by hosting provider
    consolidateSubdomainsByProvider() {
        const providerMap = new Map();
        
        // Phase 1: Use new registry methods
        const subdomains = this.results.subdomains.getAllSubdomains();
        
        for (const subdomain of subdomains) {
            // Priority: CNAME service classification over IP vendor classification
            let vendor = 'Unknown';
            
            if (subdomain.cnameService) {
                // Use CNAME service for classification
                vendor = subdomain.cnameService.name;
            } else if (subdomain.vendor?.vendor) {
                // Fall back to IP vendor classification
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
            if (subdomain.ip) {
                provider.ips.add(subdomain.ip);
            }
        }
        
        // Convert to array and add IP count
        const consolidated = Array.from(providerMap.values()).map(provider => ({
            ...provider,
            ips: Array.from(provider.ips),
            uniqueIPs: provider.ips.size
        }));
        
        return consolidated;
    }

    // Phase 2: Calculate statistics using new ServiceRegistry
    calculateStats() {
        // Get total services from ServiceRegistry
        this.results.stats.totalServices = this.results.services.getTotalServiceCount();
        
        // Calculate total security issues (all types)
        const totalSecurityIssues = 
            this.results.security.takeovers.length +
            this.results.security.dnsIssues.length +
            this.results.security.emailIssues.length +
            this.results.security.cloudIssues.length;
        
        this.results.stats.totalTakeovers = totalSecurityIssues;
        
        // Phase 1: Use new registry methods for stats calculation
        const unclassifiedSubdomains = this.results.subdomains.filter(subdomain => 
            !subdomain.primaryService && !subdomain.cnameService
        );
        this.results.stats.totalSubdomains = unclassifiedSubdomains.length;
        
        // Add provider consolidation stats
        const consolidatedProviders = this.consolidateSubdomainsByProvider();
        this.results.stats.totalProviders = consolidatedProviders.length;
        this.results.stats.consolidatedProviders = consolidatedProviders;
        
        // Log final statistics
        this.debug.logStats(this.results.stats);
    }

    // Update progress bar
    updateProgress(percentage, text) {
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const progressSection = document.getElementById('progressSection');
        
        progressSection.style.display = 'block';
        progressFill.style.width = percentage + '%';
        progressText.textContent = text;
    }

    // Display results
    displayResults() {
        const resultsDiv = document.getElementById('results');
        resultsDiv.style.display = 'block';
        
        this.displayStats();
        this.displayAPINotifications();
        this.displayServicesByVendor();
        this.displaySecurity();
        this.displayInterestingFindings();
        this.displayRedirectsToMain();
        this.displayCNAMEMappings();
        this.displaySubdomains(); // Moved to end to avoid duplicates
        this.displayHistoricalRecords();
    }

    // Display statistics
    displayStats() {
        const statsDiv = document.getElementById('stats');
        const stats = this.results.stats;
        
        statsDiv.innerHTML = `
            <div class="stat-card">
                <div class="stat-number">${stats.totalServices}</div>
                <div class="stat-label">Services Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalSubdomains}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalProviders || 0}</div>
                <div class="stat-label">Hosting Providers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalTakeovers}</div>
                <div class="stat-label">Security Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalHistoricalRecords || 0}</div>
                <div class="stat-label">Historical Records</div>
            </div>
        `;
    }

    // Phase 2: Display services grouped by vendor
    displayServicesByVendor() {
        const allServices = this.results.services.getAllServices();
        
        // First, hide all vendor sections
        this.hideAllVendorSections();
        
        // Group services by vendor
        const vendorGroups = {};
        allServices.forEach(service => {
            const vendor = this.getVendorFromService(service);
            if (!vendorGroups[vendor]) {
                vendorGroups[vendor] = [];
            }
            vendorGroups[vendor].push(service);
        });
        
        // Display each vendor group (only if they have services)
        Object.entries(vendorGroups).forEach(([vendor, services]) => {
            if (services.length > 0) {
                this.displayVendorServices(vendor, services);
            }
        });
    }
    
    // Hide all vendor sections initially
    hideAllVendorSections() {
        const vendorSections = [
            'microsoftServices',
            'awsServices', 
            'proofpointServices',
            'googleServices',
            'cloudflareServices',
            'otherServices'
        ];
        
        vendorSections.forEach(containerId => {
            const container = document.getElementById(containerId);
            const section = container?.closest('.service-category');
            if (section) {
                section.style.display = 'none';
            }
        });
    }
    
    // Get vendor name from service
    getVendorFromService(service) {
        if (service.name.includes('Microsoft')) return 'Microsoft';
        if (service.name.includes('Amazon') || service.name.includes('AWS')) return 'Amazon AWS';
        if (service.name.includes('ProofPoint')) return 'ProofPoint';
        if (service.name.includes('Google')) return 'Google';
        if (service.name.includes('Cloudflare')) return 'Cloudflare';
        if (service.name.includes('DigitalOcean')) return 'DigitalOcean';
        return 'Other';
    }
    
    // Display services for a specific vendor
    displayVendorServices(vendor, services) {
        const containerId = this.getVendorContainerId(vendor);
        const container = document.getElementById(containerId);
        const section = container?.closest('.service-category');
        
        if (!container) return;
        
        if (services.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        if (section) section.style.display = 'block';
        
        let html = '';
        services.forEach(service => {
            html += this.displayService(service);
        });
        
        container.innerHTML = html;
    }
    
    // Get container ID for vendor
    getVendorContainerId(vendor) {
        const vendorMap = {
            'Microsoft': 'microsoftServices',
            'Amazon AWS': 'awsServices',
            'ProofPoint': 'proofpointServices',
            'Google': 'googleServices',
            'Cloudflare': 'cloudflareServices',
            'DigitalOcean': 'otherServices', // Will appear in Other Services section
            'Other': 'otherServices'
        };
        
        return vendorMap[vendor] || 'otherServices';
    }
    
    // Extract domain name from CNAME target
    extractDomainFromCNAME(cnameTarget) {
        if (!cnameTarget) return '';
        
        // Remove trailing dot if present
        let domain = cnameTarget.replace(/\.$/, '');
        
        // Split by dots and get the last two parts for domain name
        const parts = domain.split('.');
        
        if (parts.length >= 2) {
            // For domains like 'xmpp-hosting.conversations.im', return 'conversations.im'
            // For domains like 'api.example.com', return 'example.com'
            // For domains like 'subdomain.example.co.uk', return 'example.co.uk'
            
            // Handle special cases like .co.uk, .com.au, etc.
            const specialTLDs = ['co.uk', 'com.au', 'co.za', 'co.nz', 'co.jp', 'co.in', 'co.kr', 'co.th', 'co.id', 'co.my', 'co.sg', 'co.ph', 'co.ke', 'co.ug', 'co.tz', 'co.zw', 'co.bw', 'co.na', 'co.za', 'co.mw', 'co.zm', 'co.zw', 'co.bw', 'co.na', 'co.za', 'co.mw', 'co.zm'];
            
            for (const specialTLD of specialTLDs) {
                if (domain.endsWith('.' + specialTLD)) {
                    const beforeSpecialTLD = domain.substring(0, domain.length - specialTLD.length - 1);
                    const beforeParts = beforeSpecialTLD.split('.');
                    if (beforeParts.length >= 1) {
                        return beforeParts[beforeParts.length - 1] + '.' + specialTLD;
                    }
                }
            }
            
            // Standard case: return last two parts
            return parts.slice(-2).join('.');
        }
        
        // Fallback: return the original domain if we can't parse it
        return domain;
    }
    
    // Phase 2: Display services using new ServiceRegistry (legacy method)
    displayServices(containerId, category, title) {
        const container = document.getElementById(containerId);
        const section = container.closest('.service-category');
        
        // Get services from ServiceRegistry
        const services = this.results.services.getServicesByCategory(category);
        
        if (services.length === 0) {
            // Hide the entire section if no services
            if (section) {
                section.style.display = 'none';
            }
            return;
        }
        
        // Show the section and populate with services
        if (section) {
            section.style.display = 'block';
        }
        
        let html = '';
        for (const service of services) {
            html += this.displayService(service);
        }
        
        container.innerHTML = html;
    }

    // Phase 2: Display a single service with enhanced CNAME chain display
    displayService(service) {
        // Count unique subdomains instead of total records
        const uniqueSubdomains = new Set();
        for (const record of service.records) {
            if (record.subdomain) {
                uniqueSubdomains.add(record.subdomain);
            }
        }
        const subdomainCount = uniqueSubdomains.size;
        const recordTypes = service.recordTypes || [service.type];
        const recordTypesText = recordTypes.length > 1 ? ` (${recordTypes.join(', ')} records)` : ` (${subdomainCount} records)`;
        
        let html = `
            <div class="service-card">
                <div class="service-header">
                    <h3>${service.name}${recordTypesText}</h3>
                </div>
                <p class="service-description">${service.description}</p>
        `;
        
        // Phase 2: Subdomain information is now shown as hyperlinks in the CNAME chains
        
        // Show infrastructure information if available
        if (service.infrastructure) {
            html += `
                <div class="service-infrastructure" style="background: #f8f9fa; padding: 8px; margin: 8px 0; border-radius: 4px; border-left: 3px solid #007bff;">
                    <strong>🏗️ Infrastructure:</strong> ${service.infrastructure.name}<br>
                    <span style="color: #666; font-size: 0.9em;">${service.infrastructure.description}</span>
                </div>
            `;
        }
        
        // Show if this is infrastructure for another service
        if (service.isInfrastructure && service.primaryService) {
            html += `
                <div class="service-infrastructure" style="background: #f8f9fa; padding: 8px; margin: 8px 0; border-radius: 4px; border-left: 3px solid #28a745;">
                    <strong>🔗 Infrastructure for:</strong> ${service.primaryService}
                </div>
            `;
        }
        
        html += `
                <div class="service-records">
        `;
        
        // Phase 2: Enhanced record display with complete CNAME chain mapping for all services
        const groupedRecords = {};
        for (const record of service.records) {
            const recordType = this.getDNSRecordTypeName(record.type) || 'UNKNOWN';
            if (!groupedRecords[recordType]) {
                groupedRecords[recordType] = [];
            }
            // Include TTL information in the display
            const ttl = record.TTL ? ` (TTL: ${record.TTL}s)` : '';
            groupedRecords[recordType].push({
                data: record.data,
                ttl: ttl,
                priority: record.priority || null,
                subdomain: record.subdomain || null
            });
        }
        
        for (const [recordType, records] of Object.entries(groupedRecords)) {
            // Count unique subdomains for this record type
            const uniqueSubdomains = new Set();
            for (const record of records) {
                if (record.subdomain) {
                    uniqueSubdomains.add(record.subdomain);
                }
            }
            const subdomainCount = uniqueSubdomains.size;
            const countText = subdomainCount > 1 ? ` (${subdomainCount} records)` : '';
            
            html += `<strong>${recordType}${countText}:</strong><br>`;
            
            // Group records by subdomain to show complete chains
            const subdomainGroups = {};
            for (const record of records) {
                const subdomain = record.subdomain || 'unknown';
                if (!subdomainGroups[subdomain]) {
                    subdomainGroups[subdomain] = [];
                }
                subdomainGroups[subdomain].push(record);
            }
            
            // Display each subdomain's complete chain with hyperlinked subdomain
            for (const [subdomain, subdomainRecords] of Object.entries(subdomainGroups)) {
                if (subdomainRecords.length > 1) {
                    // Build complete chain for this subdomain with hyperlinked subdomain
                    const chain = [this.createSubdomainLink(subdomain)];
                    subdomainRecords.forEach(record => {
                        chain.push(record.data);
                    });
                    html += `• ${chain.join(' → ')}<br>`;
                } else {
                    // Single record - still show as mapping with hyperlinked subdomain
                    const record = subdomainRecords[0];
                    let recordText = `• ${this.createSubdomainLink(subdomain)} → ${record.data}`;
                    if (record.ttl) {
                        recordText += record.ttl;
                    }
                    if (record.priority !== null) {
                        recordText += ` (Priority: ${record.priority})`;
                    }
                    html += `${recordText}<br>`;
                }
            }
        }
        
        html += `
                </div>
            </div>
        `;
        
        return html;
    }

    // Helper function to create subdomain links that open in new tabs
    createSubdomainLink(subdomain) {
        return `<a href="https://${subdomain}" target="_blank" style="color: #2196f3; text-decoration: underline;">${subdomain}</a>`;
    }

    // Display comprehensive security analysis
    displaySecurity() {
        const container = document.getElementById('securityServices');
        const section = container.closest('.service-category');
        
        // Collect all security issues
        const allIssues = [
            ...this.results.security.takeovers.map(issue => ({ ...issue, category: 'takeover' })),
            ...this.results.security.dnsIssues.map(issue => ({ ...issue, category: 'dns' })),
            ...this.results.security.emailIssues.map(issue => ({ ...issue, category: 'email' })),
            ...this.results.security.cloudIssues.map(issue => ({ ...issue, category: 'cloud' }))
        ];
        
        if (allIssues.length === 0) {
            // Hide the entire section if no security issues
            if (section) {
                section.style.display = 'none';
            }
            return;
        }
        
        // Show the section and populate with security issues
        if (section) {
            section.style.display = 'block';
        }
        
        // Group issues by risk level
        const highRisk = allIssues.filter(issue => issue.risk === 'high');
        const mediumRisk = allIssues.filter(issue => issue.risk === 'medium');
        const lowRisk = allIssues.filter(issue => issue.risk === 'low');
        
        let html = '';
        
        // Display high risk issues
        if (highRisk.length > 0) {
            html += `<div class="risk-section"><h4>🚨 High Risk Issues (${highRisk.length})</h4>`;
            for (const issue of highRisk) {
                html += this.formatSecurityIssue(issue);
            }
            html += '</div>';
        }
        
        // Display medium risk issues
        if (mediumRisk.length > 0) {
            html += `<div class="risk-section"><h4>⚠️ Medium Risk Issues (${mediumRisk.length})</h4>`;
            for (const issue of mediumRisk) {
                html += this.formatSecurityIssue(issue);
            }
            html += '</div>';
        }
        
        // Display low risk issues
        if (lowRisk.length > 0) {
            html += `<div class="risk-section"><h4>ℹ️ Low Risk Issues (${lowRisk.length})</h4>`;
            for (const issue of lowRisk) {
                html += this.formatSecurityIssue(issue);
            }
            html += '</div>';
        }
        
        container.innerHTML = html;
    }
    
    // Display interesting findings
    displayInterestingFindings() {
        const container = document.getElementById('interestingFindings');
        const section = container.closest('.service-category');
        
        if (!this.results.interestingFindings || this.results.interestingFindings.length === 0) {
            // Hide the section if no interesting findings
            if (section) {
                section.style.display = 'none';
            }
            return;
        }
        
        // Show the section and populate with interesting findings
        if (section) {
            section.style.display = 'block';
        }
        
        // Group findings by type
        const patternFindings = this.results.interestingFindings.filter(f => f.type === 'interesting_subdomain');
        const serviceFindings = this.results.interestingFindings.filter(f => f.type === 'service_subdomain');
        
        let html = `<div class="risk-section"><h4>🔍 Interesting Infrastructure Findings (${this.results.interestingFindings.length})</h4>`;
        html += '<p style="color: #666; font-size: 0.9rem; margin-bottom: 15px;"><em>⚠️ Note: These findings are based on pattern matching only. No actual content verification is performed.</em></p>';
        
        // Display service-related findings
        if (serviceFindings.length > 0) {
            html += `<div style="margin-bottom: 20px;"><h5 style="color: #17a2b8; margin-bottom: 10px;">🔧 Service-Related Subdomains (${serviceFindings.length})</h5>`;
            for (const finding of serviceFindings) {
                html += this.formatInterestingFinding(finding);
            }
            html += '</div>';
        }
        
        // Display pattern-based findings
        if (patternFindings.length > 0) {
            html += `<div style="margin-bottom: 20px;"><h5 style="color: #17a2b8; margin-bottom: 10px;">🔍 Interesting Patterns (${patternFindings.length})</h5>`;
            for (const finding of patternFindings) {
                html += this.formatInterestingFinding(finding);
            }
            html += '</div>';
        }
        
        html += '</div>';
        
        container.innerHTML = html;
    }
    
    // Display redirects to main domain
    displayRedirectsToMain() {
        const container = document.getElementById('redirectsToMain');
        if (!container) return;
        
        if (!this.results.redirectsToMain || this.results.redirectsToMain.length === 0) {
            container.style.display = 'none';
            return;
        }
        
        let html = `<div class="risk-section"><h4>🔄 Subdomain Redirects to Main Domain (${this.results.redirectsToMain.length})</h4>`;
        html += '<p style="color: #666; font-size: 0.9rem; margin-bottom: 15px;"><em>ℹ️ These subdomains redirect to the main domain and serve the same content.</em></p>';
        
        for (const redirect of this.results.redirectsToMain) {
            html += `
                <div class="service-item" style="border-left: 4px solid #28a745;">
                    <div class="service-name">🔄 ${redirect.subdomain}</div>
                    <div class="service-description">
                        <strong>Redirects to:</strong> ${this.createSubdomainLink(redirect.redirectTarget)}<br>
                        <strong>Source:</strong> ${redirect.source}<br>
                        <em>Note: This subdomain serves the same content as the main domain</em>
                    </div>
                </div>
            `;
        }
        
        html += '</div>';
        
        container.innerHTML = html;
        container.style.display = 'block';
    }
    
    // Format individual interesting finding
    formatInterestingFinding(finding) {
        let html = `
            <div class="service-item" style="border-left: 4px solid #17a2b8;">
                <div class="service-name">🔍 ${finding.description}</div>
                <div class="service-description">
        `;
        
        if (finding.type === 'interesting_subdomain') {
            html += `
                    <strong>Pattern:</strong> ${finding.pattern}<br>
                    <strong>Subdomain:</strong> ${this.createSubdomainLink(finding.subdomain)}<br>
            `;
        } else if (finding.type === 'service_subdomain') {
            html += `
                    <strong>Service:</strong> ${finding.service.toUpperCase()}<br>
                    <strong>Subdomain:</strong> ${this.createSubdomainLink(finding.subdomain)}<br>
                    <strong>IP:</strong> ${finding.ip}<br>
            `;
        }
        
        html += `${finding.recommendation ? `<strong>Note:</strong> ${finding.recommendation}<br>` : ''}
                </div>
            </div>
        `;
        
        return html;
    }
    
    // Format individual security issue
    formatSecurityIssue(issue) {
        const riskColors = {
            critical: '#8B0000', // Dark red
            high: '#FF8C00',     // Orange
            medium: '#FFD700',   // Yellow
            low: '#0066CC',      // Blue
            info: '#FFFFFF'      // White
        };
        
        const categoryIcons = {
            takeover: '🎯',
            dns: '🌐',
            email: '📧',
            infrastructure: '🏗️',
            cloud: '☁️'
        };
        
        const icon = categoryIcons[issue.category] || '🔍';
        const color = riskColors[issue.risk] || '#6c757d';
        
        let html = `
            <div class="service-item security-issues" style="border-left: 4px solid ${color};">
                <div class="service-name">${icon} ${issue.description}</div>
                <div class="service-description">
                    <strong>Risk:</strong> ${issue.risk.toUpperCase()}<br>
                    <strong>Type:</strong> ${issue.type}<br>
                    ${issue.recommendation ? `<strong>Recommendation:</strong> ${issue.recommendation}<br>` : ''}
                </div>
        `;
        
        // Add specific details based on issue type
        if (issue.subdomain) {
            html += `<div class="service-records"><strong>Subdomain:</strong> ${this.createSubdomainLink(issue.subdomain)}<br>`;
        }
        if (issue.cname) {
            html += `<strong>CNAME:</strong> ${issue.cname}<br>`;
        }
        if (issue.service) {
            html += `<strong>Service:</strong> ${issue.service}<br>`;
        }
        if (issue.ip) {
            html += `<strong>IP:</strong> ${issue.ip}<br>`;
        }
        if (issue.record) {
            html += `<strong>Record:</strong> ${issue.record}<br>`;
        }
        if (issue.pattern) {
            html += `<strong>Pattern:</strong> ${issue.pattern}<br>`;
        }
        if (issue.cname) {
            html += `<strong>CNAME:</strong> ${issue.cname}<br>`;
        }
        
        html += '</div></div>';
        
        return html;
    }

    // Helper function to check if subdomain is already categorized in ServiceRegistry
    isSubdomainCategorizedInServices(subdomain) {
        const allServices = this.results.services.getAllServices();
        
        // Safety check: ensure allServices is an array
        if (!allServices || !Array.isArray(allServices)) {
            return false;
        }
        
        for (const service of allServices) {
            if (service && service.sourceSubdomains && service.sourceSubdomains.includes(subdomain)) {
                return true;
            }
        }
        return false;
    }

    // Helper function to check if subdomain is already in CNAME mappings
    isSubdomainInCNAMEMappings(subdomain) {
        // Check if this subdomain is already displayed in the CNAME mappings section
        // This prevents duplicate display in the "Unknown" section
        const allSubdomains = this.results.subdomains;
        
        // Safety check: ensure allSubdomains is an array
        if (!allSubdomains || !Array.isArray(allSubdomains)) {
            return false;
        }
        
        for (const sub of allSubdomains) {
            if (sub && sub.subdomain === subdomain) {
                // Check if this subdomain has CNAME information (either cnameTarget or cnameChain)
                if ((sub.cnameTarget && sub.cnameTarget !== sub.subdomain) || 
                    (sub.cnameChain && sub.cnameChain.length > 0)) {
                    return true;
                }
            }
        }
        return false;
    }

    // Helper function to check if a subdomain should be in CNAME mappings section
    shouldBeInCNAMEMappings(subdomain) {
        // A subdomain should be in CNAME mappings if it has CNAME information
        // and is not already categorized in other sections
        return (subdomain.cnameTarget && subdomain.cnameTarget !== subdomain.subdomain) || 
               (subdomain.cnameChain && subdomain.cnameChain.length > 0);
    }

    // Display subdomains grouped by provider (only unclassified ones)
    displaySubdomains() {
        const container = document.getElementById('subdomainServices');
        const section = container.closest('.service-category');
        
        // Phase 1: Use new registry methods
        // Filter out subdomains that have primary services OR are already categorized in vendor sections
        // Also filter out subdomains without IP addresses (historical records)
        // Respect deduplication flags
        // IMPORTANT: This is called AFTER all other classifications, so we only show truly unclassified subdomains
        const unclassifiedSubdomains = this.results.subdomains.filter(subdomain => 
            !subdomain.primaryService && !subdomain.cnameService && !subdomain.isCategorized && subdomain.ip &&
            (!subdomain.dedupSection || subdomain.dedupSection === 'unknown') &&
            !this.isSubdomainCategorizedInServices(subdomain.subdomain) &&
            !this.isSubdomainInCNAMEMappings(subdomain.subdomain) &&
            !this.shouldBeInCNAMEMappings(subdomain)
        );
        
        // Group unclassified subdomains by provider
        const providerMap = new Map();
        for (const subdomain of unclassifiedSubdomains) {
            // Priority: CNAME service classification over IP vendor classification
            let vendor = 'Unknown';
            
            if (subdomain.cnameService) {
                // Use CNAME service for classification
                vendor = subdomain.cnameService.name;
            } else if (subdomain.vendor?.vendor) {
                // Fall back to IP vendor classification
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
            if (subdomain.ip) {
                provider.ips.add(subdomain.ip);
            }
        }
        
        const consolidatedProviders = Array.from(providerMap.values()).map(provider => ({
            ...provider,
            ips: Array.from(provider.ips),
            uniqueIPs: provider.ips.size
        }));
        
        if (consolidatedProviders.length === 0) {
            // Hide the entire section if no unclassified subdomains
            if (section) {
                section.style.display = 'none';
            }
            return;
        }
        
        // Show the section and populate with unclassified subdomains
        if (section) {
            section.style.display = 'block';
        }
        
        let html = '';
        for (const provider of consolidatedProviders) {
            html += `
                <div class="service-item">
                    <div class="service-name">🏢 ${provider.vendor}</div>
                    <div class="service-description">
                        ${provider.totalSubdomains} subdomains • ${provider.uniqueIPs} unique IPs
                    </div>
                    <div class="service-records">
                        <strong>Subdomains:</strong><br>
                                        ${provider.subdomains.map(sub => {
                    let info = sub.ip || 'no IP';
                    if (sub.cnameChain && sub.cnameChain.length > 0) {
                        // Build full CNAME chain
                        const chain = [sub.subdomain];
                        sub.cnameChain.forEach(link => {
                            chain.push(link.to);
                        });
                        if (sub.ip) {
                            chain.push(sub.ip);
                        }
                        info = chain.join(' → ');
                    } else if (sub.cnameTarget) {
                        if (sub.ip) {
                            info = `CNAME → ${sub.cnameTarget} → ${sub.ip}`;
                        } else {
                            info = `CNAME → ${sub.cnameTarget}`;
                        }
                    }
                    return `• ${this.createSubdomainLink(sub.subdomain)} (${info})`;
                }).join('<br>')}
                        ${provider.uniqueIPs > 1 ? `<br><br><strong>IPs:</strong><br>${provider.ips.join(', ')}` : ''}
                    </div>
                </div>
            `;
        }
        
        container.innerHTML = html;
    }

    // Display CNAME mappings for third-party service analysis (only unclassified ones)
    displayCNAMEMappings() {
        const container = document.getElementById('cnameMappings');
        const section = container.closest('.service-category');
        if (!container) return; // Skip if container doesn't exist
        
        // Phase 1: Use new registry methods
        // Filter out CNAME subdomains that have primary services OR are already categorized in vendor sections
        // Respect deduplication flags
        const unclassifiedCNAMESubdomains = this.results.subdomains.filter(sub => 
            (sub.cnameTarget || (sub.cnameChain && sub.cnameChain.length > 0)) && 
            !sub.primaryService && !sub.cnameService && !sub.isCategorized &&
            (!sub.dedupSection || sub.dedupSection === 'cname') &&
            !this.isSubdomainCategorizedInServices(sub.subdomain)
        );
        
        if (unclassifiedCNAMESubdomains.length === 0) {
            // Hide the entire section if no unclassified CNAME mappings
            if (section) {
                section.style.display = 'none';
            }
            return;
        }
        
        // Show the section and populate with unclassified CNAME mappings
        if (section) {
            section.style.display = 'block';
        }
        
        // Group by CNAME target to show which services are being used
        const cnameGroups = {};
        for (const sub of unclassifiedCNAMESubdomains) {
            const target = sub.cnameTarget || (sub.cnameChain && sub.cnameChain.length > 0 ? sub.cnameChain[0].to : null);
            if (target && !cnameGroups[target]) {
                cnameGroups[target] = [];
            }
            if (target) {
                cnameGroups[target].push(sub);
            }
        }
        
        let html = '';
        for (const [target, subdomains] of Object.entries(cnameGroups)) {
            // Get service info from first subdomain that has it
            const serviceInfo = subdomains.find(sub => sub.cnameService)?.cnameService;
            
            // Extract domain name from CNAME target
            const domainName = this.extractDomainFromCNAME(target);
            
            // Add CNAME mapping as a service to the ServiceRegistry
            const cnameService = {
                name: domainName,
                category: 'cname',
                description: `CNAME mapping service with ${subdomains.length} subdomain${subdomains.length > 1 ? 's' : ''}`,
                records: subdomains.map(sub => ({
                    subdomain: sub.subdomain,
                    target: target,
                    ip: sub.ip,
                    cnameChain: sub.cnameChain
                })),
                recordTypes: ['CNAME'],
                sourceSubdomains: subdomains.map(sub => sub.subdomain)
            };
            
            // Register the CNAME service
            this.results.services.addService(cnameService);
            
            html += `
                <div class="service-item">
                    <div class="service-name">🎯 ${domainName}</div>
                    <div class="service-description">
                        ${subdomains.length} subdomain${subdomains.length > 1 ? 's' : ''} pointing to this service
                        ${serviceInfo ? `<br><span style="color: #667eea; font-size: 0.9em;">${serviceInfo.name} (${serviceInfo.category})</span>` : ''}
                    </div>
                    <div class="service-records">
                        <strong>Subdomains:</strong><br>
                        ${subdomains.map(sub => {
                            let info = sub.ip || '';
                            if (sub.cnameChain && sub.cnameChain.length > 0) {
                                const chain = [sub.subdomain];
                                sub.cnameChain.forEach(link => {
                                    chain.push(link.to);
                                });
                                if (sub.ip) {
                                    chain.push(sub.ip);
                                }
                                info = ` → ${chain.join(' → ')}`;
                            } else if (sub.ip) {
                                info = ` → ${sub.ip}`;
                            }
                            return `• ${this.createSubdomainLink(sub.subdomain)}${info}`;
                        }).join('<br>')}
                        ${serviceInfo ? `<br><br><strong>Service:</strong><br>• ${serviceInfo.description}` : ''}
                    </div>
                </div>
            `;
        }
        
        container.innerHTML = html;
    }

    // Phase 2: Display AWS services using new ServiceRegistry
    displayAWSServices() {
        const container = document.getElementById('cloudServices');
        const section = container.closest('.service-category');
        
        // Get AWS services from ServiceRegistry
        const awsServices = this.results.services.getServicesByCategory('aws');
        
        if (awsServices.length === 0) {
            return; // No AWS services to display
        }
        
        // Show the section
        if (section) {
            section.style.display = 'block';
        }
        
        let html = `
            <div class="service-card">
                <div class="service-header">
                    <h3>AWS Services (${awsServices.length} services)</h3>
                    <span class="service-category">cloud</span>
                </div>
                <p class="service-description">Amazon Web Services - Cloud computing platform</p>
                <div class="service-records">
                    <strong>AWS Services:</strong><br>
        `;
        
        for (const service of awsServices) {
            html += `
                <div style="margin: 10px 0; padding: 8px; background: #f8f9fa; border-radius: 4px;">
                    <strong>${service.name}</strong><br>
                    <span style="color: #666; font-size: 0.9em;">${service.description}</span>
                    ${service.sourceSubdomains.length > 0 ? `<br><span style="color: #2196f3; font-size: 0.9em;">🌐 Subdomains: ${service.sourceSubdomains.map(sub => this.createSubdomainLink(sub)).join(', ')}</span>` : ''}
                    ${this.formatRecords(service.records)}
                </div>
            `;
        }
        
        html += '</div></div>';
        
        // Add to existing cloud services
        container.innerHTML += html;
    }

    // Display historical records
    displayHistoricalRecords() {
        const container = document.getElementById('historicalRecords');
        const section = container.closest('.service-category');
        if (!container) return; // Skip if container doesn't exist
        
        // Get historical records from CT logs
        const historicalRecords = this.results.historicalRecords || [];
        
        // Get subdomains without IP addresses (also historical)
        // Respect deduplication flags and skip CT log duplicates
        const subdomainsWithoutIP = this.results.subdomains.filter(subdomain => 
            !subdomain.ip && !subdomain.primaryService && !subdomain.cnameService && !subdomain.isCategorized &&
            (!subdomain.dedupSection || subdomain.dedupSection === 'historical') &&
            !subdomain.ctLogDuplicate
        );
        
        // Combine both types of historical records
        const allHistoricalRecords = [...historicalRecords];
        
        // Add subdomains without IP as historical records
        // Use a Set to track subdomains already added to avoid duplicates
        const addedSubdomains = new Set();
        
        // First add CT log historical records (deduplicate within CT logs)
        for (const record of historicalRecords) {
            if (!addedSubdomains.has(record.subdomain)) {
                allHistoricalRecords.push(record);
                addedSubdomains.add(record.subdomain);
            }
        }
        
        // Then add DNS analysis subdomains without IP (only if not already added)
        for (const subdomain of subdomainsWithoutIP) {
            if (!addedSubdomains.has(subdomain.subdomain)) {
                // Use the actual discovery source instead of hardcoding "DNS Analysis"
                const source = subdomain.discoverySources && subdomain.discoverySources.length > 0 
                    ? subdomain.discoverySources[0] 
                    : 'DNS Analysis';
                
                allHistoricalRecords.push({
                    subdomain: subdomain.subdomain,
                    source: source,
                    status: 'Historical/Obsolete',
                    discoveredAt: new Date().toISOString(),
                    certificateInfo: {
                        issuer: 'No certificate found',
                        notBefore: null,
                        notAfter: null,
                        certificateId: null
                    }
                });
                addedSubdomains.add(subdomain.subdomain);
            }
        }
        
        if (allHistoricalRecords.length === 0) {
            // Hide the entire section if no historical records
            if (section) {
                section.style.display = 'none';
            }
            return;
        }
        
        // Show the section and populate with historical records
        if (section) {
            section.style.display = 'block';
        }
        
        let html = '<h3>📜 Historical/Obsolete Records</h3>';
        html += '<p style="color: #666; margin-bottom: 15px;">These subdomains were found in certificate transparency logs but have no active DNS records.</p>';
        
        // Create responsive table
        html += `
            <div style="overflow-x: auto; margin-top: 15px;">
                <table style="width: 100%; border-collapse: collapse; font-family: 'Monaco', 'Menlo', monospace; font-size: 0.85rem; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <thead>
                        <tr style="background: #f8f9fa; border-bottom: 2px solid #dee2e6;">
                            <th style="padding: 12px 8px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; min-width: 200px;">📜 Subdomain</th>
                            <th style="padding: 12px 8px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; min-width: 100px;">Source</th>
                            <th style="padding: 12px 8px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; min-width: 100px;">Discovered</th>
                            <th style="padding: 12px 8px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; min-width: 120px;">Issuer</th>
                            <th style="padding: 12px 8px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; min-width: 100px;">Expiry</th>
                        </tr>
                    </thead>
                    <tbody>
        `;
        
        for (const record of allHistoricalRecords) {
            const certInfo = record.certificateInfo;
            const discoveredDate = new Date(record.discoveredAt).toLocaleDateString();
            
            // Extract issuer name (simplify for display)
            let issuer = 'Unknown';
            if (certInfo.issuer && certInfo.issuer !== 'No certificate found') {
                // Extract just the issuer name from the full issuer string
                if (certInfo.issuer.includes('Let\'s Encrypt')) {
                    issuer = 'Let\'s Encrypt';
                } else if (certInfo.issuer.includes('DigiCert')) {
                    issuer = 'DigiCert';
                } else if (certInfo.issuer.includes('Comodo')) {
                    issuer = 'Comodo';
                } else if (certInfo.issuer.includes('GoDaddy')) {
                    issuer = 'GoDaddy';
                } else if (certInfo.issuer.includes('GlobalSign')) {
                    issuer = 'GlobalSign';
                } else {
                    // Try to extract CN from issuer string
                    const cnMatch = certInfo.issuer.match(/CN=([^,]+)/);
                    issuer = cnMatch ? cnMatch[1] : 'Unknown';
                }
            }
            
            // Format expiry date
            let expiryDate = 'Unknown';
            if (certInfo.notAfter) {
                expiryDate = new Date(certInfo.notAfter).toLocaleDateString();
            }
            
            // Add table row
            html += `
                <tr style="border-bottom: 1px solid #e9ecef;">
                    <td style="padding: 12px 8px; color: #495057; word-break: break-all;">
                        ${this.createSubdomainLink(record.subdomain)}
                    </td>
                    <td style="padding: 12px 8px; color: #6c757d; font-size: 0.8rem;">${record.source}</td>
                    <td style="padding: 12px 8px; color: #6c757d; font-size: 0.8rem;">${discoveredDate}</td>
                    <td style="padding: 12px 8px; color: #6c757d; font-size: 0.8rem;">${issuer}</td>
                    <td style="padding: 12px 8px; color: #6c757d; font-size: 0.8rem;">${expiryDate}</td>
                </tr>
            `;
        }
        
        html += `
                    </tbody>
                </table>
            </div>
        `;
        
        container.innerHTML = html;
    }

    // Convert DNS record type number to human-readable name
    getDNSRecordTypeName(typeNumber) {
        const recordTypes = {
            1: 'A',
            5: 'CNAME',
            6: 'SOA',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            2: 'NS',
            12: 'PTR',
            33: 'SRV',
            46: 'RRSIG',
            47: 'NSEC',
            48: 'DNSKEY',
            43: 'DS',
            44: 'SSHFP',
            45: 'IPSECKEY',
            99: 'SPF',
            250: 'CAA'
        };
        
        return recordTypes[typeNumber] || `Type ${typeNumber}`;
    }

    // Format DNS records for display
    formatRecords(records) {
        if (!records || records.length === 0) return 'No records';
        
        // Group records by type for better display
        const groupedRecords = {};
        
        for (const record of records) {
            const recordType = this.getDNSRecordTypeName(record.type);
            if (!groupedRecords[recordType]) {
                groupedRecords[recordType] = [];
            }
            groupedRecords[recordType].push(record.data);
        }
        
        let html = '';
        for (const [type, dataArray] of Object.entries(groupedRecords)) {
            const uniqueData = [...new Set(dataArray)]; // Remove duplicates
            const count = uniqueData.length;
            const countText = count > 1 ? ` (${count} records)` : '';
            
            html += `<strong>${type}${countText}:</strong><br>`;
            html += uniqueData.map(data => `• ${data}`).join('<br>');
            html += '<br>';
        }
        
        return html;
    }

    // Show error message
    showError(message) {
        const resultsDiv = document.getElementById('results');
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div class="error-message">
                <strong>Error:</strong> ${message}
            </div>
        `;
    }

    // Add API notification
    addAPINotification(apiName, status, message) {
        this.apiNotifications.push({
            api: apiName,
            status: status, // 'success', 'error', 'warning'
            message: message,
            timestamp: new Date().toLocaleTimeString()
        });
        console.log(`📡 API ${apiName}: ${status} - ${message}`);
    }

    // Display API notifications
    displayAPINotifications() {
        const container = document.getElementById('apiNotifications');
        const section = document.getElementById('apiStatusSection');
        if (!container || !section) return;
        
        // Only show notifications if there are errors or warnings
        const errorNotifications = this.apiNotifications.filter(n => n.status === 'error' || n.status === 'warning');
        
        if (errorNotifications.length === 0) {
            section.style.display = 'none';
            return;
        }
        
        // Show the section and populate with error notifications
        section.style.display = 'block';
        
        let html = '';
        for (const notification of errorNotifications) {
            const statusIcon = notification.status === 'warning' ? '⚠️' : '❌';
            const statusClass = notification.status === 'warning' ? 'warning' : 'error';
            
            html += `
                <div class="api-notification ${statusClass}">
                    <span class="api-name">${statusIcon} ${notification.api}</span>
                    <span class="api-message">${notification.message}</span>
                    <span class="api-time">${notification.timestamp}</span>
                </div>
            `;
        }
        
        container.innerHTML = html;
    }

    // Save results to localStorage
    saveResults() {
        if (this.results && this.currentDomain) {
            localStorage.setItem(`3ptracer_${this.currentDomain}`, JSON.stringify(this.results));
        }
    }

    // Load results from localStorage
    loadResults(domain) {
        const saved = localStorage.getItem(`3ptracer_${domain}`);
        if (saved) {
            this.results = JSON.parse(saved);
            this.displayResults();
            return true;
        }
        return false;
    }
}

// Global app instance
const app = new App();

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
        app.showError('Analysis failed: ' + error.message);
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
        if (app.loadResults(savedDomain)) {
            // Show that results are loaded from cache
            const progressText = document.getElementById('progressText');
            progressText.textContent = 'Results loaded from cache';
        }
    }
}); 