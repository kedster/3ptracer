// Service Patterns for Third-Party Service Detection
class ServiceDetector {
    constructor() {
        this.patterns = {
            email: {
                google: {
                    patterns: ['googlemail.com', 'google.com', 'gmail.com'],
                    mxPatterns: ['google', 'gmail'],
                    spfPatterns: ['include:_spf.google.com', 'include:spf.google.com'],
                    name: 'Google Workspace (Gmail)',
                    category: 'email',
                    description: 'Email hosting and productivity suite'
                },
                microsoft: {
                    patterns: ['outlook.com', 'hotmail.com', 'microsoft.com'],
                    mxPatterns: ['outlook', 'hotmail', 'microsoft'],
                    spfPatterns: ['include:spf.protection.outlook.com', 'include:outlook.com'],
                    name: 'Microsoft 365 (Outlook)',
                    category: 'email',
                    description: 'Email hosting and productivity suite'
                },
                zoho: {
                    patterns: ['zoho.com'],
                    mxPatterns: ['zoho'],
                    spfPatterns: ['include:zoho.com', 'include:spf.zoho.com'],
                    name: 'Zoho Mail',
                    category: 'email',
                    description: 'Business email hosting'
                },
                protonmail: {
                    patterns: ['protonmail.ch'],
                    mxPatterns: ['protonmail'],
                    spfPatterns: ['include:_spf.protonmail.ch'],
                    name: 'ProtonMail',
                    category: 'email',
                    description: 'Secure email service'
                },
                sendgrid: {
                    patterns: ['sendgrid.net'],
                    spfPatterns: ['include:sendgrid.net'],
                    name: 'SendGrid',
                    category: 'email',
                    description: 'Email delivery service'
                },
                mailgun: {
                    patterns: ['mailgun.org'],
                    spfPatterns: ['include:mailgun.org'],
                    name: 'Mailgun',
                    category: 'email',
                    description: 'Email API service'
                },
                amazonses: {
                    patterns: ['amazonses.com'],
                    spfPatterns: ['include:amazonses.com'],
                    name: 'Amazon SES',
                    category: 'email',
                    description: 'Email sending service'
                },
                proofpoint: {
                    patterns: ['pphosted.com', 'proofpoint.com'],
                    spfPatterns: ['include:pphosted.com', 'include:spf.pphosted.com'],
                    name: 'Proofpoint Email Security',
                    category: 'email',
                    description: 'Email security and protection service'
                },
                mimecast: {
                    patterns: ['mimecast.com'],
                    spfPatterns: ['include:spf.mimecast.com'],
                    name: 'Mimecast Email Security',
                    category: 'email',
                    description: 'Email security and archiving service'
                },
                barracuda: {
                    patterns: ['barracuda.com', 'barracudacentral.org'],
                    spfPatterns: ['include:spf.barracuda.com'],
                    name: 'Barracuda Email Security',
                    category: 'email',
                    description: 'Email security and filtering service'
                },
                sophos: {
                    patterns: ['sophos.com'],
                    spfPatterns: ['include:spf.sophos.com'],
                    name: 'Sophos Email Security',
                    category: 'email',
                    description: 'Email security and anti-spam service'
                }
            },
            cloud: {
                aws: {
                    patterns: ['amazonaws.com', 'aws.amazon.com', 'cloudfront.net', 'awsapprunner.com'],
                    cnamePatterns: ['amazonaws.com', 'cloudfront.net', 'awsapprunner.com'],
                    txtPatterns: ['amazonses'],
                    name: 'Amazon AWS',
                    category: 'cloud',
                    description: 'Cloud computing platform'
                },
                azure: {
                    patterns: ['azurewebsites.net', 'azure.com', 'windows.net'],
                    cnamePatterns: ['azurewebsites.net', 'windows.net'],
                    txtPatterns: ['MS='],
                    name: 'Microsoft Azure',
                    category: 'cloud',
                    description: 'Cloud computing platform'
                },
                cloudflare: {
                    patterns: ['cloudflare.com'],
                    nsPatterns: ['cloudflare'],
                    name: 'Cloudflare',
                    category: 'cloud',
                    description: 'CDN and security services'
                },
                heroku: {
                    patterns: ['herokuapp.com'],
                    cnamePatterns: ['herokuapp.com'],
                    name: 'Heroku',
                    category: 'cloud',
                    description: 'Application hosting platform'
                },
                vercel: {
                    patterns: ['vercel.app', 'vercel.com'],
                    cnamePatterns: ['vercel.app'],
                    name: 'Vercel',
                    category: 'cloud',
                    description: 'Deployment platform'
                },
                netlify: {
                    patterns: ['netlify.app', 'netlify.com'],
                    cnamePatterns: ['netlify.app'],
                    name: 'Netlify',
                    category: 'cloud',
                    description: 'Site hosting platform'
                },
                railway: {
                    patterns: ['railway.app'],
                    cnamePatterns: ['railway.app'],
                    name: 'Railway',
                    category: 'cloud',
                    description: 'Application hosting platform'
                },
                digitalocean: {
                    patterns: ['ondigitalocean.app', 'digitalocean.com'],
                    cnamePatterns: ['ondigitalocean.app'],
                    name: 'DigitalOcean',
                    category: 'cloud',
                    description: 'Cloud infrastructure platform'
                },
                firebase: {
                    patterns: ['firebaseapp.com', 'web.app'],
                    cnamePatterns: ['firebaseapp.com', 'web.app'],
                    name: 'Firebase Hosting',
                    category: 'cloud',
                    description: 'Google Firebase web hosting'
                },
                githubpages: {
                    patterns: ['github.io'],
                    cnamePatterns: ['github.io'],
                    name: 'GitHub Pages',
                    category: 'cloud',
                    description: 'Static site hosting'
                },
                gitlabpages: {
                    patterns: ['gitlab.io'],
                    cnamePatterns: ['gitlab.io'],
                    name: 'GitLab Pages',
                    category: 'cloud',
                    description: 'Static site hosting'
                },
                cloudflarepages: {
                    patterns: ['pages.dev'],
                    cnamePatterns: ['pages.dev'],
                    name: 'Cloudflare Pages',
                    category: 'cloud',
                    description: 'Static site hosting'
                },
                render: {
                    patterns: ['render.com', 'onrender.com'],
                    cnamePatterns: ['onrender.com'],
                    name: 'Render',
                    category: 'cloud',
                    description: 'Cloud application platform'
                },
                fly: {
                    patterns: ['fly.dev', 'fly.io'],
                    cnamePatterns: ['fly.dev', 'fly.io'],
                    name: 'Fly.io',
                    category: 'cloud',
                    description: 'Application deployment platform'
                },
                linode: {
                    patterns: ['linode.com'],
                    name: 'Linode',
                    category: 'cloud',
                    description: 'Cloud hosting provider'
                },
                vultr: {
                    patterns: ['vultr.com'],
                    name: 'Vultr',
                    category: 'cloud',
                    description: 'Cloud infrastructure provider'
                },
                hetzner: {
                    patterns: ['hetzner.com'],
                    name: 'Hetzner',
                    category: 'cloud',
                    description: 'Cloud hosting provider'
                },
                fastly: {
                    patterns: ['fastly.com'],
                    name: 'Fastly',
                    category: 'cloud',
                    description: 'CDN and edge computing platform'
                }
            },
            security: {
                letsencrypt: {
                    patterns: ['letsencrypt.org'],
                    txtPatterns: ['letsencrypt'],
                    name: 'Let\'s Encrypt',
                    category: 'security',
                    description: 'SSL certificate provider'
                },
                dmarc: {
                    patterns: ['dmarc'],
                    txtPatterns: ['v=DMARC1'],
                    name: 'DMARC',
                    category: 'security',
                    description: 'Email authentication policy'
                },
                spf: {
                    patterns: ['spf'],
                    txtPatterns: ['v=spf1'],
                    name: 'SPF',
                    category: 'security',
                    description: 'Email sender policy framework'
                }
            },
            dns: {
                godaddy: {
                    patterns: ['godaddy.com'],
                    nsPatterns: ['godaddy.com', 'domaincontrol.com'],
                    name: 'GoDaddy DNS',
                    category: 'dns',
                    description: 'Domain registration and DNS management'
                },
                namecheap: {
                    patterns: ['namecheap.com'],
                    nsPatterns: ['namecheap.com'],
                    name: 'Namecheap DNS',
                    category: 'dns',
                    description: 'Domain registration and DNS management'
                },
                googledomains: {
                    patterns: ['domains.google'],
                    nsPatterns: ['domains.google'],
                    name: 'Google Domains',
                    category: 'dns',
                    description: 'Domain registration and DNS management'
                },
                awsroute53: {
                    patterns: ['amazonaws.com'],
                    nsPatterns: ['awsdns'],
                    name: 'AWS Route 53',
                    category: 'dns',
                    description: 'Amazon DNS service'
                },
                dnsimple: {
                    patterns: ['dnsimple.com'],
                    nsPatterns: ['dnsimple.com'],
                    name: 'DNSimple',
                    category: 'dns',
                    description: 'DNS management service'
                },
                dyn: {
                    patterns: ['dyn.com'],
                    nsPatterns: ['dyn.com'],
                    name: 'Dyn DNS',
                    category: 'dns',
                    description: 'DNS management service'
                },
                easydns: {
                    patterns: ['easy-dns.com'],
                    nsPatterns: ['easy-dns.com'],
                    name: 'EasyDNS',
                    category: 'dns',
                    description: 'DNS management service'
                },
                henet: {
                    patterns: ['he.net'],
                    nsPatterns: ['he.net'],
                    name: 'Hurricane Electric DNS',
                    category: 'dns',
                    description: 'DNS management service'
                },
                ns1: {
                    patterns: ['ns1.com'],
                    nsPatterns: ['ns1.com'],
                    name: 'NS1',
                    category: 'dns',
                    description: 'DNS management service'
                }
            },
            analytics: {
                googleanalytics: {
                    patterns: ['google-analytics.com', 'googletagmanager.com'],
                    txtPatterns: ['google-site-verification'],
                    name: 'Google Analytics',
                    category: 'analytics',
                    description: 'Web analytics tracking'
                },
                facebook: {
                    patterns: ['facebook.com'],
                    txtPatterns: ['facebook-domain-verification'],
                    name: 'Facebook Pixel',
                    category: 'analytics',
                    description: 'Social media tracking'
                }
            },
            dmarc: {
                default: {
                    patterns: ['v=DMARC1'],
                    name: 'DMARC',
                    category: 'security',
                    description: 'Domain-based Message Authentication, Reporting & Conformance'
                }
            }
        };

        this.vendorPatterns = {
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

    // Detect services from DNS records
    detectServices(records) {
        const allServices = new Map(); // Use Map to consolidate ALL services by name

        // Check if records exist and is an object
        if (!records || typeof records !== 'object') {
            return [];
        }

        // Helper function to add service to consolidated map
        const addService = (service, record, recordType) => {
            // Ensure record has subdomain information
            const recordWithSubdomain = {
                ...record,
                subdomain: record.subdomain || record.name || 'unknown'
            };
            
            if (allServices.has(service.name)) {
                // Add record to existing service
                const existingService = allServices.get(service.name);
                existingService.records.push(recordWithSubdomain);
                // Update record types if needed
                if (!existingService.recordTypes) {
                    existingService.recordTypes = [existingService.type];
                }
                if (!existingService.recordTypes.includes(recordType)) {
                    existingService.recordTypes.push(recordType);
                }
            } else {
                // Create new service entry
                allServices.set(service.name, {
                    name: service.name,
                    category: service.category,
                    description: service.description,
                    records: [recordWithSubdomain],
                    type: service.category, // Use category as type
                    recordTypes: [recordType]
                });
            }
        };

        // Check email services from MX and SPF
        if (records.MX) {
            for (const record of records.MX) {
                const mxData = record.data.toLowerCase();
                
                for (const [key, service] of Object.entries(this.patterns.email)) {
                    if (service.mxPatterns && Array.isArray(service.mxPatterns) && 
                        service.mxPatterns.some(pattern => mxData.includes(pattern))) {
                        addService(service, record, 'MX');
                    }
                }
            }
        }

        if (records.SPF) {
            for (const record of records.SPF) {
                const spfData = record.data.toLowerCase();
                
                for (const [key, service] of Object.entries(this.patterns.email)) {
                    if (service.spfPatterns && Array.isArray(service.spfPatterns) && 
                        service.spfPatterns.some(pattern => spfData.includes(pattern))) {
                        addService(service, record, 'SPF');
                    }
                }
            }
        }

        // Check cloud services from CNAME
        if (records.CNAME) {
            for (const record of records.CNAME) {
                const cnameData = record.data.toLowerCase();
                
                for (const [key, service] of Object.entries(this.patterns.cloud)) {
                    if (service.cnamePatterns && Array.isArray(service.cnamePatterns) && 
                        service.cnamePatterns.some(pattern => cnameData.includes(pattern))) {
                        addService(service, record, 'CNAME');
                    }
                }
            }
        }

        // Check security services from TXT
        if (records.TXT) {
            for (const record of records.TXT) {
                const txtData = record.data.toLowerCase();
                
                for (const [key, service] of Object.entries(this.patterns.security)) {
                    if (service.txtPatterns && Array.isArray(service.txtPatterns) && 
                        service.txtPatterns.some(pattern => txtData.includes(pattern))) {
                        addService(service, record, 'TXT');
                    }
                }
            }
        }

        // Check analytics services from TXT
        if (records.TXT) {
            for (const record of records.TXT) {
                const txtData = record.data.toLowerCase();
                
                for (const [key, service] of Object.entries(this.patterns.analytics)) {
                    if (service.txtPatterns && Array.isArray(service.txtPatterns) && 
                        service.txtPatterns.some(pattern => txtData.includes(pattern))) {
                        addService(service, record, 'TXT');
                    }
                }
            }
        }

        // Check DMARC records for email security
        if (records.DMARC) {
            for (const record of records.DMARC) {
                const dmarcData = record.data.toLowerCase();
                
                // Parse DMARC record to extract reporting and policy information
                const dmarcInfo = this.parseDMARC(dmarcData);
                if (dmarcInfo) {
                    addService(dmarcInfo, record, 'DMARC');
                }
            }
        }

        return Array.from(allServices.values());
    }

    // Detect email services from MX records
    detectEmailServices(mxRecords) {
        const services = new Map(); // Use Map to consolidate by service name

        if (!mxRecords || !Array.isArray(mxRecords)) {
            return [];
        }

        for (const record of mxRecords) {
            const mxData = record.data.toLowerCase();
            
            for (const [key, service] of Object.entries(this.patterns.email)) {
                // Check if mxPatterns exists and is an array
                if (service.mxPatterns && Array.isArray(service.mxPatterns) && 
                    service.mxPatterns.some(pattern => mxData.includes(pattern))) {
                    
                    // Consolidate by service name
                    if (services.has(service.name)) {
                        // Add record to existing service
                        services.get(service.name).records.push(record);
                    } else {
                        // Create new service entry
                        services.set(service.name, {
                            name: service.name,
                            category: service.category,
                            description: service.description,
                            records: [record],
                            type: 'MX'
                        });
                    }
                }
            }
        }

        return Array.from(services.values());
    }

    // Detect email services from SPF records
    detectEmailServicesFromSPF(spfRecords) {
        const services = new Map(); // Use Map to consolidate by service name

        if (!spfRecords || !Array.isArray(spfRecords)) {
            return [];
        }

        for (const record of spfRecords) {
            const spfData = record.data.toLowerCase();
            
            for (const [key, service] of Object.entries(this.patterns.email)) {
                if (service.spfPatterns && Array.isArray(service.spfPatterns) && 
                    service.spfPatterns.some(pattern => spfData.includes(pattern))) {
                    
                    // Consolidate by service name
                    if (services.has(service.name)) {
                        // Add record to existing service
                        services.get(service.name).records.push(record);
                    } else {
                        // Create new service entry
                        services.set(service.name, {
                            name: service.name,
                            category: service.category,
                            description: service.description,
                            records: [record],
                            type: 'SPF'
                        });
                    }
                }
            }
        }

        return Array.from(services.values());
    }

    // Detect cloud services from CNAME records
    detectCloudServices(cnameRecords) {
        const services = new Map(); // Use Map to consolidate by service name

        if (!cnameRecords || !Array.isArray(cnameRecords)) {
            return [];
        }

        for (const record of cnameRecords) {
            const cnameData = record.data.toLowerCase();
            
            for (const [key, service] of Object.entries(this.patterns.cloud)) {
                if (service.cnamePatterns && Array.isArray(service.cnamePatterns) && 
                    service.cnamePatterns.some(pattern => cnameData.includes(pattern))) {
                    
                    // Consolidate by service name
                    if (services.has(service.name)) {
                        // Add record to existing service
                        services.get(service.name).records.push(record);
                    } else {
                        // Create new service entry
                        services.set(service.name, {
                            name: service.name,
                            category: service.category,
                            description: service.description,
                            records: [record],
                            type: 'CNAME'
                        });
                    }
                }
            }
        }

        return Array.from(services.values());
    }

    // Detect security services from TXT records
    detectSecurityServices(txtRecords) {
        const services = new Map(); // Use Map to consolidate by service name

        if (!txtRecords || !Array.isArray(txtRecords)) {
            return [];
        }

        for (const record of txtRecords) {
            const txtData = record.data.toLowerCase();
            
            for (const [key, service] of Object.entries(this.patterns.security)) {
                if (service.txtPatterns && Array.isArray(service.txtPatterns) && 
                    service.txtPatterns.some(pattern => txtData.includes(pattern))) {
                    
                    // Consolidate by service name
                    if (services.has(service.name)) {
                        // Add record to existing service
                        services.get(service.name).records.push(record);
                    } else {
                        // Create new service entry
                        services.set(service.name, {
                            name: service.name,
                            category: service.category,
                            description: service.description,
                            records: [record],
                            type: 'TXT'
                        });
                    }
                }
            }
        }

        return Array.from(services.values());
    }

    // Detect analytics services from TXT records
    detectAnalyticsServices(txtRecords) {
        const services = new Map(); // Use Map to consolidate by service name

        if (!txtRecords || !Array.isArray(txtRecords)) {
            return [];
        }

        for (const record of txtRecords) {
            const txtData = record.data.toLowerCase();
            
            for (const [key, service] of Object.entries(this.patterns.analytics)) {
                if (service.txtPatterns && Array.isArray(service.txtPatterns) && 
                    service.txtPatterns.some(pattern => txtData.includes(pattern))) {
                    
                    // Consolidate by service name
                    if (services.has(service.name)) {
                        // Add record to existing service
                        services.get(service.name).records.push(record);
                    } else {
                        // Create new service entry
                        services.set(service.name, {
                            name: service.name,
                            category: service.category,
                            description: service.description,
                            records: [record],
                            type: 'TXT'
                        });
                    }
                }
            }
        }

        return Array.from(services.values());
    }

    // Classify vendor from ASN information
    classifyVendor(asnInfo) {
        const asn = asnInfo.asn || '';
        
        for (const [vendor, pattern] of Object.entries(this.vendorPatterns)) {
            if (pattern.test(asn)) {
                return {
                    vendor: vendor,
                    asn: asnInfo.asn,
                    location: asnInfo.location,
                    city: asnInfo.city
                };
            }
        }

        return {
            vendor: 'Unknown',
            asn: asnInfo.asn,
            location: asnInfo.location,
            city: asnInfo.city
        };
    }

    // Detect subdomain takeover from CNAME records
    detectTakeoverFromCNAME(cnameRecords) {
        const takeovers = [];

        for (const record of cnameRecords) {
            const cnameTarget = record.data;
            
            // Check if CNAME target is a known service that might be vulnerable
            const vulnerableServices = [
                'github.io',
                'herokuapp.com',
                'netlify.app',
                'vercel.app',
                'surge.sh',
                'readme.io',
                'unbouncepages.com',
                'firebaseapp.com',
                'appspot.com',
                'cloudapp.net',
                'azurewebsites.net',
                'herokuapp.com',
                'dokkuapp.com',
                'bubble.io',
                'webflow.io',
                'squarespace.com',
                'wixsite.com',
                'tumblr.com',
                'wordpress.com',
                'blogspot.com'
            ];

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
    
    // Detect DNS security issues
    detectDNSSecurityIssues(records) {
        const issues = [];
        
        // Check for missing SPF record
        if (!records.SPF || records.SPF.length === 0) {
            issues.push({
                type: 'missing_spf',
                risk: 'high',
                description: 'Missing SPF record - vulnerable to email spoofing',
                recommendation: 'Add SPF record to prevent email spoofing'
            });
        }
        
        // Check for missing DMARC record
        if (!records.DMARC || records.DMARC.length === 0) {
            issues.push({
                type: 'missing_dmarc',
                risk: 'medium',
                description: 'Missing DMARC record - no email authentication policy',
                recommendation: 'Add DMARC record to protect against email spoofing'
            });
        }
        
        // Check for weak SPF records
        if (records.SPF) {
            for (const spfRecord of records.SPF) {
                const spfData = spfRecord.data.toLowerCase();
                
                // Check for overly permissive SPF
                if (spfData.includes('+all') || spfData.includes('?all')) {
                    issues.push({
                        type: 'weak_spf',
                        risk: 'medium',
                        description: 'Weak SPF record - too permissive',
                        recommendation: 'Use more restrictive SPF record (e.g., ~all instead of +all)',
                        record: spfData
                    });
                }
                
                // Check for missing mechanisms
                if (!spfData.includes('include:') && !spfData.includes('ip4:') && !spfData.includes('ip6:')) {
                    issues.push({
                        type: 'incomplete_spf',
                        risk: 'medium',
                        description: 'Incomplete SPF record - missing authorized servers',
                        recommendation: 'Add authorized email servers to SPF record',
                        record: spfData
                    });
                }
            }
        }
        
        // Check for wildcard DNS
        if (records.A) {
            for (const aRecord of records.A) {
                if (aRecord.name.includes('*')) {
                    issues.push({
                        type: 'wildcard_dns',
                        risk: 'medium',
                        description: 'Wildcard DNS record detected',
                        recommendation: 'Consider removing wildcard DNS to prevent subdomain enumeration',
                        record: aRecord.name
                    });
                }
            }
        }
        
        // Check for open DNS resolvers (only flag truly problematic cases)
        if (records.NS) {
            for (const nsRecord of records.NS) {
                const nsData = nsRecord.data.toLowerCase();
                
                // Only flag if it's explicitly an open resolver service
                // Skip legitimate CDN/DNS providers like Cloudflare, Google, etc.
                if (nsData.includes('openresolver') || 
                    nsData.includes('publicdns') ||
                    (nsData.includes('open') && !nsData.includes('cloudflare') && !nsData.includes('google') && !nsData.includes('amazon'))) {
                    issues.push({
                        type: 'open_dns_resolver',
                        risk: 'low',
                        description: 'Potential open DNS resolver detected',
                        recommendation: 'Verify DNS resolver security configuration',
                        record: nsData
                    });
                }
            }
        }
        
        return issues;
    }

    // Parse DMARC record to extract policy and reporting information
    parseDMARC(dmarcData) {
        if (!dmarcData || !dmarcData.includes('v=DMARC1')) {
            return null;
        }

        const policy = this.extractDMARCPolicy(dmarcData);
        const reporting = this.extractDMARCReporting(dmarcData);
        
        return {
            name: 'DMARC',
            category: 'security',
            description: `Email authentication policy: ${policy}${reporting ? `, Reporting: ${reporting}` : ''}`,
            policy: policy,
            reporting: reporting,
            raw: dmarcData
        };
    }

    // Extract DMARC policy (p=) from record
    extractDMARCPolicy(dmarcData) {
        const policyMatch = dmarcData.match(/p=([^;]+)/i);
        if (policyMatch) {
            const policy = policyMatch[1].toLowerCase();
            switch (policy) {
                case 'none':
                    return 'Monitor only (none)';
                case 'quarantine':
                    return 'Quarantine suspicious emails';
                case 'reject':
                    return 'Reject unauthorized emails';
                default:
                    return `Policy: ${policy}`;
            }
        }
        return 'No policy specified';
    }

    // Extract DMARC reporting information
    extractDMARCReporting(dmarcData) {
        const reporting = [];
        
        // Check for aggregate reporting (rua=)
        const ruaMatch = dmarcData.match(/rua=mailto:([^;]+)/i);
        if (ruaMatch) {
            reporting.push(`Aggregate reports: ${ruaMatch[1]}`);
        }
        
        // Check for forensic reporting (ruf=)
        const rufMatch = dmarcData.match(/ruf=mailto:([^;]+)/i);
        if (rufMatch) {
            reporting.push(`Forensic reports: ${rufMatch[1]}`);
        }
        
        // Check for percentage (pct=)
        const pctMatch = dmarcData.match(/pct=([^;]+)/i);
        if (pctMatch) {
            reporting.push(`${pctMatch[1]}% of emails`);
        }
        
        return reporting.length > 0 ? reporting.join(', ') : 'No reporting configured';
    }
    
    // Detect email security issues
    detectEmailSecurityIssues(records) {
        const issues = [];
        
        // Check for missing DKIM
        if (!records.DKIM || records.DKIM.length === 0) {
            issues.push({
                type: 'missing_dkim',
                risk: 'medium',
                description: 'Missing DKIM record - no email signing',
                recommendation: 'Add DKIM record to sign outgoing emails'
            });
        }
        
        // Check for weak DMARC policy
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
                
                if (!dmarcData.includes('pct=')) {
                    issues.push({
                        type: 'missing_dmarc_percentage',
                        risk: 'low',
                        description: 'Missing DMARC percentage - applies to all emails',
                        recommendation: 'Add pct=100 to DMARC record'
                    });
                }
            }
        }
        
        // Check for email spoofing vulnerabilities
        if (records.SPF) {
            for (const spfRecord of records.SPF) {
                const spfData = spfRecord.data.toLowerCase();
                
                // Check for hard fail
                if (!spfData.includes('~all') && !spfData.includes('-all')) {
                    issues.push({
                        type: 'spf_no_hard_fail',
                        risk: 'medium',
                        description: 'SPF record missing hard fail mechanism',
                        recommendation: 'Add ~all or -all to SPF record for better protection'
                    });
                }
            }
        }
        
        return issues;
    }
    
    // Detect infrastructure security issues
    detectInterestingInfrastructureFindings(records, subdomains) {
        const findings = [];
        
        // Check for service-related subdomains
        const servicePatterns = [
            'ftp', 'telnet', 'ssh', 'smtp', 'pop3', 'imap', 'rdp', 'vnc'
        ];
        
        for (const subdomain of subdomains) {
            if (subdomain.ip) {
                // Check for common service ports in subdomain names
                for (const service of servicePatterns) {
                    // Use word boundary regex to avoid false positives
                    // This matches the service name as a whole word, not as a substring
                    const serviceRegex = new RegExp(`\\b${service}\\b`, 'i');
                    if (serviceRegex.test(subdomain.subdomain)) {
                        findings.push({
                            type: 'service_subdomain',
                            risk: 'info',
                            description: `Service-related subdomain: ${service.toUpperCase()}`,
                            recommendation: `Explore this subdomain for ${service.toUpperCase()} service insights`,
                            subdomain: subdomain.subdomain,
                            service: service,
                            ip: subdomain.ip
                        });
                    }
                }
            }
        }
        
        // Check for interesting subdomain patterns
        const interestingPatterns = [
            'admin', 'login', 'test', 'dev', 'staging', 'backup', 'db', 'database',
            'api', 'internal', 'private', 'secret', 'password', 'root'
        ];
        
        for (const subdomain of subdomains) {
            for (const pattern of interestingPatterns) {
                if (subdomain.subdomain.includes(pattern)) {
                    findings.push({
                        type: 'interesting_subdomain',
                        risk: 'info',
                        description: `Interesting subdomain pattern: ${pattern}`,
                        recommendation: 'Explore this subdomain for potential insights (pattern-based detection only)',
                        subdomain: subdomain.subdomain,
                        pattern: pattern
                    });
                }
            }
        }
        
        return findings;
    }
    
    // Detect cloud security issues
    detectCloudSecurityIssues(records, subdomains) {
        const issues = [];
        
        // Check for exposed cloud services
        const cloudServices = [
            's3', 'bucket', 'storage', 'cdn', 'static', 'assets', 'media',
            'backup', 'archive', 'logs', 'temp', 'cache'
        ];
        
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
        
        // Check for misconfigured cloud services
        if (records.CNAME) {
            for (const cnameRecord of records.CNAME) {
                const cnameData = cnameRecord.data.toLowerCase();
                
                // Check for S3 buckets
                if (cnameData.includes('s3.amazonaws.com')) {
                    issues.push({
                        type: 's3_bucket_detected',
                        risk: 'medium',
                        description: 'S3 bucket detected - verify access controls',
                        recommendation: 'Check S3 bucket permissions and public access',
                        cname: cnameData
                    });
                }
                
                // Check for CloudFront distributions
                if (cnameData.includes('cloudfront.net')) {
                    issues.push({
                        type: 'cloudfront_detected',
                        risk: 'low',
                        description: 'CloudFront distribution detected',
                        recommendation: 'Verify CloudFront security headers and access controls',
                        cname: cnameData
                    });
                }
            }
        }
        
        return issues;
    }
} 