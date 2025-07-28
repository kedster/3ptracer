// Centralized Service Detection Engine
class ServiceDetectionEngine {
    constructor() {
        this.servicePatterns = this.initializeServicePatterns();
        this.vendorPatterns = this.initializeVendorPatterns();
    }

    // Initialize service patterns in a cleaner structure
    initializeServicePatterns() {
        return {
            email: {
                'Google Workspace': {
                    patterns: ['googlemail.com', 'google.com', 'gmail.com'],
                    mxPatterns: ['google', 'gmail'],
                    spfPatterns: ['include:_spf.google.com', 'include:spf.google.com'],
                    description: 'Email hosting and productivity suite'
                },
                'Microsoft 365': {
                    patterns: ['outlook.com', 'hotmail.com', 'microsoft.com'],
                    mxPatterns: ['outlook', 'hotmail', 'microsoft'],
                    spfPatterns: ['include:spf.protection.outlook.com', 'include:outlook.com'],
                    description: 'Email hosting and productivity suite'
                },
                'Zoho Mail': {
                    patterns: ['zoho.com'],
                    mxPatterns: ['zoho'],
                    spfPatterns: ['include:zoho.com', 'include:spf.zoho.com'],
                    description: 'Business email hosting'
                },
                'ProtonMail': {
                    patterns: ['protonmail.ch'],
                    mxPatterns: ['protonmail'],
                    spfPatterns: ['include:_spf.protonmail.ch'],
                    description: 'Secure email service'
                },
                'SendGrid': {
                    patterns: ['sendgrid.net'],
                    spfPatterns: ['include:sendgrid.net'],
                    description: 'Email delivery service'
                },
                'Mailgun': {
                    patterns: ['mailgun.org'],
                    spfPatterns: ['include:mailgun.org'],
                    description: 'Email API service'
                },
                'Amazon SES': {
                    patterns: ['amazonses.com'],
                    spfPatterns: ['include:amazonses.com'],
                    description: 'Email sending service'
                },
                'Proofpoint': {
                    patterns: ['pphosted.com', 'proofpoint.com'],
                    spfPatterns: ['include:pphosted.com', 'include:spf.pphosted.com'],
                    description: 'Email security and protection service'
                },
                'Mimecast': {
                    patterns: ['mimecast.com'],
                    spfPatterns: ['include:spf.mimecast.com'],
                    description: 'Email security and archiving service'
                },
                'Barracuda': {
                    patterns: ['barracuda.com', 'barracudacentral.org'],
                    spfPatterns: ['include:spf.barracuda.com'],
                    description: 'Email security and filtering service'
                },
                'Sophos': {
                    patterns: ['sophos.com'],
                    spfPatterns: ['include:spf.sophos.com'],
                    description: 'Email security and anti-spam service'
                }
            },
            cloud: {
                'Amazon AWS': {
                    patterns: ['amazonaws.com', 'aws.amazon.com', 'cloudfront.net', 'awsapprunner.com'],
                    cnamePatterns: ['amazonaws.com', 'cloudfront.net', 'awsapprunner.com'],
                    txtPatterns: ['amazonses'],
                    description: 'Cloud computing platform'
                },
                'Microsoft Azure': {
                    patterns: ['azurewebsites.net', 'azure.com', 'windows.net'],
                    cnamePatterns: ['azurewebsites.net', 'windows.net'],
                    txtPatterns: ['MS='],
                    description: 'Cloud computing platform'
                },
                'Google Cloud Platform': {
                    patterns: ['googleusercontent.com', 'appspot.com', 'firebaseapp.com', 'web.app'],
                    cnamePatterns: ['googleusercontent.com', 'appspot.com', 'firebaseapp.com', 'web.app'],
                    description: 'Cloud computing platform'
                },
                'Cloudflare': {
                    patterns: ['cloudflare.com', 'pages.dev'],
                    cnamePatterns: ['pages.dev'],
                    nsPatterns: ['cloudflare'],
                    description: 'CDN, security services, and DNS management'
                },
                'Heroku': {
                    patterns: ['herokuapp.com'],
                    cnamePatterns: ['herokuapp.com'],
                    description: 'Application hosting platform'
                },
                'Vercel': {
                    patterns: ['vercel.app', 'vercel.com'],
                    cnamePatterns: ['vercel.app'],
                    description: 'Deployment platform'
                },
                'Netlify': {
                    patterns: ['netlify.app', 'netlify.com'],
                    cnamePatterns: ['netlify.app'],
                    description: 'Site hosting platform'
                },
                'DigitalOcean': {
                    patterns: ['ondigitalocean.app', 'digitalocean.com'],
                    cnamePatterns: ['ondigitalocean.app'],
                    description: 'Cloud infrastructure platform'
                },
                'GitHub Pages': {
                    patterns: ['github.io'],
                    cnamePatterns: ['github.io'],
                    description: 'Static site hosting'
                },
                'GitLab Pages': {
                    patterns: ['gitlab.io'],
                    cnamePatterns: ['gitlab.io'],
                    description: 'Static site hosting'
                },
                'Render': {
                    patterns: ['render.com', 'onrender.com'],
                    cnamePatterns: ['onrender.com'],
                    description: 'Cloud application platform'
                },
                'Fly.io': {
                    patterns: ['fly.dev', 'fly.io'],
                    cnamePatterns: ['fly.dev', 'fly.io'],
                    description: 'Application deployment platform'
                }
            },
            analytics: {
                'Google Analytics': {
                    patterns: ['google-analytics.com', 'googletagmanager.com'],
                    txtPatterns: ['google-site-verification'],
                    description: 'Web analytics tracking'
                },
                'Facebook Pixel': {
                    patterns: ['facebook.com'],
                    txtPatterns: ['facebook-domain-verification'],
                    description: 'Social media tracking'
                }
            },
            security: {
                'Let\'s Encrypt': {
                    patterns: ['letsencrypt.org'],
                    txtPatterns: ['letsencrypt'],
                    description: 'SSL certificate provider'
                }
            },
            dns: {
                'GoDaddy DNS': {
                    patterns: ['godaddy.com'],
                    nsPatterns: ['godaddy.com', 'domaincontrol.com'],
                    description: 'Domain registration and DNS management'
                },
                'Namecheap DNS': {
                    patterns: ['namecheap.com'],
                    nsPatterns: ['namecheap.com'],
                    description: 'Domain registration and DNS management'
                },
                'Google Domains': {
                    patterns: ['domains.google'],
                    nsPatterns: ['domains.google'],
                    description: 'Domain registration and DNS management'
                },
                'AWS Route 53': {
                    patterns: ['amazonaws.com'],
                    nsPatterns: ['awsdns'],
                    description: 'Amazon DNS service'
                }
            }
        };
    }

    // Initialize vendor patterns for ASN classification
    initializeVendorPatterns() {
        return {
            'Amazon AWS': /amazon|aws/i,
            'Microsoft Azure': /microsoft|azure/i,
            'Google Cloud Platform': /google|gcp/i,
            'Cloudflare': /cloudflare/i,
            'DigitalOcean': /digitalocean/i,
            'Linode': /linode/i,
            'Vultr': /vultr/i,
            'OVHcloud': /ovh/i,
            'Hetzner': /hetzner/i
        };
    }

    // Main service detection method - replaces all scattered detection methods
    detectServices(records) {
        const detectedServices = new Map();

        if (!records || typeof records !== 'object') {
            return [];
        }

        // Process each record type for service detection
        this.processRecordType(records.MX, 'mxPatterns', 'MX', detectedServices);
        this.processRecordType(records.SPF, 'spfPatterns', 'SPF', detectedServices);
        this.processRecordType(records.CNAME, 'cnamePatterns', 'CNAME', detectedServices);
        this.processRecordType(records.NS, 'nsPatterns', 'NS', detectedServices);

        // Process TXT records for service detection (but exclude DNS policy records)
        if (records.TXT) {
            const filteredTXT = records.TXT.filter(record => {
                const data = record.data.toLowerCase();
                return !data.includes('v=dmarc1') && !data.includes('v=spf1');
            });
            this.processRecordType(filteredTXT, 'txtPatterns', 'TXT', detectedServices);
        }

        // Note: DMARC and SPF policy records are now handled separately as DNS records

        return Array.from(detectedServices.values());
    }

    // Process DNS policy records (SPF, DMARC, etc.) separately from services
    processDNSRecords(records) {
        const dnsRecords = [];
        
        if (!records || typeof records !== 'object') {
            return dnsRecords;
        }

        // Process SPF records
        if (records.SPF) {
            for (const record of records.SPF) {
                const spfData = record.data;
                if (spfData.toLowerCase().includes('v=spf1')) {
                    dnsRecords.push({
                        type: 'SPF',
                        name: 'Sender Policy Framework',
                        description: 'Email authentication policy to prevent spoofing',
                        data: spfData,
                        record: record,
                        category: 'email-security'
                    });
                }
            }
        }

        // Process DMARC records
        if (records.DMARC) {
            for (const record of records.DMARC) {
                const dmarcData = record.data.toLowerCase();
                if (dmarcData.includes('v=dmarc1')) {
                    const dmarcInfo = this.parseDMARC(dmarcData);
                    dnsRecords.push({
                        type: 'DMARC',
                        name: 'Domain-based Message Authentication, Reporting & Conformance',
                        description: 'Email authentication and reporting policy',
                        data: record.data,
                        record: record,
                        category: 'email-security',
                        parsed: dmarcInfo
                    });
                }
            }
        }

        // Process other important TXT records (excluding SPF and DMARC)
        if (records.TXT) {
            for (const record of records.TXT) {
                const txtData = record.data.toLowerCase();
                
                // Skip SPF and DMARC records (already processed above)
                if (txtData.includes('v=spf1') || txtData.includes('v=dmarc1')) {
                    continue;
                }
                
                // Look for other important DNS records
                if (txtData.includes('v=dkim1')) {
                    dnsRecords.push({
                        type: 'DKIM',
                        name: 'DomainKeys Identified Mail',
                        description: 'Email authentication using cryptographic signatures',
                        data: record.data,
                        record: record,
                        category: 'email-security'
                    });
                } else if (txtData.includes('_domainkey')) {
                    dnsRecords.push({
                        type: 'DKIM-Key',
                        name: 'DKIM Public Key',
                        description: 'Public key for DKIM email authentication',
                        data: record.data,
                        record: record,
                        category: 'email-security'
                    });
                }
            }
        }

        return dnsRecords;
    }

    // Process a specific record type against patterns
    processRecordType(records, patternType, recordType, detectedServices) {
        if (!records || !Array.isArray(records)) return;

        for (const record of records) {
            const recordData = record.data.toLowerCase();
            
            // Check all service categories
            for (const [category, services] of Object.entries(this.servicePatterns)) {
                for (const [serviceName, serviceConfig] of Object.entries(services)) {
                    if (this.matchesPattern(recordData, serviceConfig[patternType])) {
                        this.addOrUpdateService(detectedServices, serviceName, serviceConfig, category, record, recordType);
                    }
                }
            }
        }
    }

    // Check if record data matches any pattern
    matchesPattern(recordData, patterns) {
        if (!patterns || !Array.isArray(patterns)) return false;
        return patterns.some(pattern => recordData.includes(pattern.toLowerCase()));
    }

    // Add or update service in the detected services map
    addOrUpdateService(detectedServices, serviceName, serviceConfig, category, record, recordType) {
        const recordWithSubdomain = {
            ...record,
            subdomain: record.subdomain || record.name || 'unknown'
        };

        if (detectedServices.has(serviceName)) {
            const existingService = detectedServices.get(serviceName);
            existingService.records.push(recordWithSubdomain);
            if (!existingService.recordTypes.includes(recordType)) {
                existingService.recordTypes.push(recordType);
            }
        } else {
            detectedServices.set(serviceName, {
                name: serviceName,
                category: category,
                description: serviceConfig.description,
                records: [recordWithSubdomain],
                recordTypes: [recordType]
            });
        }
    }

    // Process DMARC records with special parsing
    processDMARCRecords(dmarcRecords, detectedServices) {
        for (const record of dmarcRecords) {
            const dmarcData = record.data.toLowerCase();
            if (dmarcData.includes('v=dmarc1')) {
                const dmarcInfo = this.parseDMARC(dmarcData);
                if (dmarcInfo) {
                    this.addOrUpdateService(detectedServices, 'DMARC', dmarcInfo, 'security', record, 'DMARC');
                }
            }
        }
    }

    // Parse DMARC record
    parseDMARC(dmarcData) {
        const policy = this.extractDMARCPolicy(dmarcData);
        const reporting = this.extractDMARCReporting(dmarcData);
        
        return {
            description: `Email authentication policy: ${policy}${reporting ? `, Reporting: ${reporting}` : ''}`,
            policy: policy,
            reporting: reporting,
            raw: dmarcData
        };
    }

    // Extract DMARC policy
    extractDMARCPolicy(dmarcData) {
        const policyMatch = dmarcData.match(/p=([^;]+)/i);
        if (policyMatch) {
            const policy = policyMatch[1].toLowerCase();
            switch (policy) {
                case 'none': return 'Monitor only (none)';
                case 'quarantine': return 'Quarantine suspicious emails';
                case 'reject': return 'Reject unauthorized emails';
                default: return `Policy: ${policy}`;
            }
        }
        return 'No policy specified';
    }

    // Extract DMARC reporting information
    extractDMARCReporting(dmarcData) {
        const reporting = [];
        
        const ruaMatch = dmarcData.match(/rua=mailto:([^;]+)/i);
        if (ruaMatch) reporting.push(`Aggregate reports: ${ruaMatch[1]}`);
        
        const rufMatch = dmarcData.match(/ruf=mailto:([^;]+)/i);
        if (rufMatch) reporting.push(`Forensic reports: ${rufMatch[1]}`);
        
        const pctMatch = dmarcData.match(/pct=([^;]+)/i);
        if (pctMatch) reporting.push(`${pctMatch[1]}% of emails`);
        
        return reporting.length > 0 ? reporting.join(', ') : 'No reporting configured';
    }

    // Classify vendor from ASN information
    classifyVendor(asnInfo) {
        if (!asnInfo || !asnInfo.asn) {
            return { vendor: 'Unknown', category: 'Unknown' };
        }

        const asn = asnInfo.asn.toLowerCase();
        
        for (const [vendor, pattern] of Object.entries(this.vendorPatterns)) {
            if (pattern.test(asn)) {
                return {
                    vendor: vendor,
                    asn: asnInfo.asn,
                    location: asnInfo.location,
                    city: asnInfo.city,
                    category: 'infrastructure'
                };
            }
        }

        return {
            vendor: asnInfo.asn || 'Unknown',
            asn: asnInfo.asn,
            location: asnInfo.location,
            city: asnInfo.city,
            category: 'infrastructure'
        };
    }

    // Security analysis methods
    detectDNSSecurityIssues(records) {
        const issues = [];
        
        if (!records.SPF || records.SPF.length === 0) {
            issues.push({
                type: 'missing_spf',
                risk: 'high',
                description: 'Missing SPF record - vulnerable to email spoofing',
                recommendation: 'Add SPF record to prevent email spoofing'
            });
        }
        
        if (!records.DMARC || records.DMARC.length === 0) {
            issues.push({
                type: 'missing_dmarc',
                risk: 'medium',
                description: 'Missing DMARC record - no email authentication policy',
                recommendation: 'Add DMARC record to protect against email spoofing'
            });
        }
        
        if (records.SPF) {
            for (const spfRecord of records.SPF) {
                const spfData = spfRecord.data.toLowerCase();
                if (spfData.includes('+all') || spfData.includes('?all')) {
                    issues.push({
                        type: 'weak_spf',
                        risk: 'medium',
                        description: 'Weak SPF record - too permissive',
                        recommendation: 'Use more restrictive SPF record (e.g., ~all instead of +all)',
                        record: spfData
                    });
                }
            }
        }
        
        return issues;
    }

    detectEmailSecurityIssues(records) {
        const issues = [];
        
        if (records.DMARC) {
            for (const dmarcRecord of records.DMARC) {
                const dmarcData = dmarcRecord.data.toLowerCase();
                if (dmarcData.includes('p=none')) {
                    issues.push({
                        type: 'weak_dmarc',
                        risk: 'medium',
                        description: 'Weak DMARC policy - monitor only',
                        recommendation: 'Consider stronger DMARC policy (quarantine or reject)',
                        record: dmarcData
                    });
                }
            }
        }
        
        return issues;
    }

    detectInterestingInfrastructureFindings(records, subdomains) {
        const findings = [];
        
        const servicePatterns = ['ftp', 'telnet', 'ssh', 'smtp', 'pop3', 'imap', 'rdp', 'vnc'];
        const interestingPatterns = ['admin', 'login', 'test', 'dev', 'staging', 'backup', 'db', 'database', 'api', 'internal', 'private'];
        
        // Only analyze subdomains that have active IP addresses (not historical records)
        const activeSubdomains = subdomains.filter(subdomain => 
            subdomain.ip || 
            (subdomain.ipAddresses && subdomain.ipAddresses.length > 0)
        );
        
        for (const subdomain of activeSubdomains) {
            // Use standardized ipAddresses array
            const subdomainIP = subdomain.ipAddresses && subdomain.ipAddresses.length > 0 ? 
                subdomain.ipAddresses[0] : null;
            
            // Service-related subdomain detection (only for subdomains with IPs)
            if (subdomainIP) {
                for (const service of servicePatterns) {
                    const serviceRegex = new RegExp(`\\b${service}\\b`, 'i');
                    if (serviceRegex.test(subdomain.subdomain)) {
                        findings.push({
                            type: 'service_subdomain',
                            risk: 'info',
                            description: `Service-related subdomain: ${service.toUpperCase()}`,
                            recommendation: `Explore this subdomain for ${service.toUpperCase()} service insights`,
                            subdomain: subdomain.subdomain,
                            service: service,
                            ip: subdomainIP
                        });
                    }
                }
            }
            
            // Interesting pattern detection (only for active subdomains)
            for (const pattern of interestingPatterns) {
                if (subdomain.subdomain.includes(pattern)) {
                    findings.push({
                        type: 'interesting_subdomain',
                        risk: 'info',
                        description: `Interesting subdomain pattern: ${pattern}`,
                        recommendation: 'Explore this subdomain for potential insights (pattern-based detection only)',
                        subdomain: subdomain.subdomain,
                        pattern: pattern,
                        ip: subdomainIP || 'Active subdomain'
                    });
                }
            }
        }
        
        console.log(`🔍 Interesting findings analysis: ${activeSubdomains.length} active subdomains analyzed, ${findings.length} findings discovered`);
        
        return findings;
    }

    detectCloudSecurityIssues(records, subdomains) {
        const issues = [];
        
        const cloudServices = ['s3', 'bucket', 'storage', 'cdn', 'static', 'assets', 'media', 'backup', 'archive', 'logs', 'temp', 'cache'];
        
        for (const subdomain of subdomains) {
            for (const service of cloudServices) {
                if (subdomain.subdomain.includes(service)) {
                    issues.push({
                        type: 'exposed_cloud_service',
                        risk: 'medium',
                        description: `Potential exposed cloud service: ${service}`,
                        recommendation: `Verify ${service} service security and access controls`,
                        subdomain: subdomain.subdomain
                    });
                }
            }
        }
        
        if (records.CNAME) {
            for (const cnameRecord of records.CNAME) {
                const cnameData = cnameRecord.data.toLowerCase();
                if (cnameData.includes('s3.amazonaws.com')) {
                    issues.push({
                        type: 's3_bucket_detected',
                        risk: 'medium',
                        description: 'S3 bucket detected - verify access controls',
                        recommendation: 'Check S3 bucket permissions and public access',
                        cname: cnameData
                    });
                }
            }
        }
        
        return issues;
    }

    detectTakeoverFromCNAME(cnameRecords) {
        const takeovers = [];
        const vulnerableServices = [
            'github.io', 'herokuapp.com', 'netlify.app', 'vercel.app', 'surge.sh',
            'readme.io', 'unbouncepages.com', 'firebaseapp.com', 'appspot.com',
            'cloudapp.net', 'azurewebsites.net', 'dokkuapp.com', 'bubble.io',
            'webflow.io', 'squarespace.com', 'wixsite.com', 'tumblr.com',
            'wordpress.com', 'blogspot.com'
        ];

        for (const record of cnameRecords) {
            const cnameTarget = record.data;
            for (const service of vulnerableServices) {
                if (cnameTarget.includes(service)) {
                    takeovers.push({
                        subdomain: record.name,
                        cname: cnameTarget,
                        service: service,
                        risk: 'medium',
                        description: `CNAME points to ${service} - potential takeover target`,
                        type: 'subdomain_takeover'
                    });
                }
            }
        }

        return takeovers;
    }
} 