// UI Rendering Engine
class UIRenderer {
    constructor() {
        this.progressSection = document.getElementById('progressSection');
        this.progressFill = document.getElementById('progressFill');
        this.progressText = document.getElementById('progressText');
        this.resultsDiv = document.getElementById('results');
        this.statsDiv = document.getElementById('stats');
    }

    // Update progress bar
    updateProgress(percentage, text) {
        if (this.progressSection) this.progressSection.style.display = 'block';
        if (this.progressFill) this.progressFill.style.width = percentage + '%';
        if (this.progressText) this.progressText.textContent = text;
    }

    // Show error message
    showError(message) {
        if (this.resultsDiv) {
            this.resultsDiv.style.display = 'block';
            this.resultsDiv.innerHTML = `
                <div class="error-message">
                    <strong>Error:</strong> ${message}
                </div>
            `;
        }
    }

    // Display all results
    displayResults(processedData, securityResults, interestingFindings, apiNotifications, isProgressive = false) {
        if (this.resultsDiv) {
            this.resultsDiv.style.display = 'block';
        }

        // Add progressive status message if this is a progressive update
        if (isProgressive) {
            this.showProgressiveStatus(processedData.stats);
        }

        this.displayStats(processedData.stats, securityResults);
        this.displayAPINotifications(apiNotifications);
        this.displayServicesByVendor(processedData.services);
        this.displaySecurity(securityResults);
        this.displayInterestingFindings(interestingFindings);
        this.displayRedirectsToMain(processedData.redirectsToMain);
        this.displayCNAMEMappings(processedData.subdomains);
        this.displayDNSRecords(processedData.dnsRecords);
        this.displaySubdomains(processedData);
        this.displayHistoricalRecords(processedData.historicalRecords);
    }

    // Display statistics
    displayStats(stats, securityResults) {
        if (!this.statsDiv) return;

        const totalSecurityIssues = this.calculateTotalSecurityIssues(securityResults);

        this.statsDiv.innerHTML = `
            <div class="stat-card">
                <div class="stat-number">${stats.totalServices}</div>
                <div class="stat-label">Services Found</div>
                <div class="tooltip">
                    Third-party services detected from DNS records including email providers (Gmail, Outlook), 
                    cloud platforms (AWS, Cloudflare), analytics tools (Google Analytics), and security services. 
                    Found via MX, CNAME, TXT, and SPF record analysis.
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalSubdomains}</div>
                <div class="stat-label">Subdomains</div>
                <div class="tooltip">
                    Active subdomains discovered from certificate transparency logs and DNS analysis. 
                    Only includes subdomains that currently resolve to IP addresses. 
                    Excludes historical/obsolete subdomains and redirects to main domain.
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalProviders || 0}</div>
                <div class="stat-label">Hosting Providers</div>
                <div class="tooltip">
                    Unique hosting and infrastructure providers identified through service detection and 
                    ASN (Autonomous System Number) lookups. Includes cloud providers, CDNs, email services, 
                    and DNS providers used by this domain.
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${totalSecurityIssues}</div>
                <div class="stat-label">Security Issues</div>
                <div class="tooltip">
                    Potential security concerns including missing SPF/DMARC records, weak email policies, 
                    possible subdomain takeover vulnerabilities, and exposed cloud services. 
                    Requires manual verification - automated detection only.
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalHistoricalRecords || 0}</div>
                <div class="stat-label">Historical Records</div>
                <div class="tooltip">
                    Subdomains found in certificate transparency logs but no longer have active DNS records. 
                    These represent historical infrastructure that may have been decommissioned or moved. 
                    Useful for understanding past domain usage.
                </div>
            </div>
        `;
    }

    // Calculate total security issues
    calculateTotalSecurityIssues(securityResults) {
        return (securityResults.takeovers?.length || 0) +
               (securityResults.dnsIssues?.length || 0) +
               (securityResults.emailIssues?.length || 0) +
               (securityResults.cloudIssues?.length || 0);
    }

    // Display services grouped by vendor
    displayServicesByVendor(servicesMap) {
        const allServices = Array.from(servicesMap.values());
        
        // Hide all vendor sections first
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
        
        // Display each vendor group
        Object.entries(vendorGroups).forEach(([vendor, services]) => {
            if (services.length > 0) {
                this.displayVendorServices(vendor, services);
            }
        });
    }

    // Hide all vendor sections
    hideAllVendorSections() {
        const vendorSections = [
            'microsoftServices', 'awsServices', 'proofpointServices',
            'googleServices', 'cloudflareServices', 'otherServices'
        ];
        
        vendorSections.forEach(containerId => {
            const container = document.getElementById(containerId);
            const section = container?.closest('.service-category');
            if (section) {
                section.style.display = 'none';
            }
        });
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
            html += this.renderService(service);
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
            'DigitalOcean': 'otherServices',
            'Other': 'otherServices'
        };
        
        return vendorMap[vendor] || 'otherServices';
    }

    // Render a single service
    renderService(service) {
        const uniqueSubdomains = new Set();
        for (const record of service.records || []) {
            if (record.subdomain) {
                uniqueSubdomains.add(record.subdomain);
            }
        }
        
        const subdomainCount = uniqueSubdomains.size;
        const recordTypes = service.recordTypes || [];
        const recordTypesText = recordTypes.length > 1 ? 
            ` (${recordTypes.join(', ')} records)` : 
            ` (${subdomainCount} records)`;
        
        let html = `
            <div class="service-card">
                <div class="service-header">
                    <h3>${service.name}${recordTypesText}</h3>
                </div>
                <p class="service-description">${service.description}</p>
        `;
        
        // Show infrastructure information
        if (service.infrastructure) {
            html += `
                <div class="service-infrastructure" style="background: #f8f9fa; padding: 8px; margin: 8px 0; border-radius: 4px; border-left: 3px solid #007bff;">
                    <strong>🏗️ Infrastructure:</strong> ${service.infrastructure.name}<br>
                    <span style="color: #666; font-size: 0.9em;">${service.infrastructure.description}</span>
                </div>
            `;
        }
        
        html += '<div class="service-records">';
        
        // Group records by type
        const groupedRecords = this.groupRecordsByType(service.records || []);
        
        for (const [recordType, records] of Object.entries(groupedRecords)) {
            const uniqueSubdomains = new Set(records.map(r => r.subdomain).filter(Boolean));
            const countText = uniqueSubdomains.size > 1 ? ` (${uniqueSubdomains.size} records)` : '';
            
            html += `<strong>${recordType}${countText}:</strong><br>`;
            
            // Group by subdomain
            const subdomainGroups = this.groupRecordsBySubdomain(records);
            
            for (const [subdomain, subdomainRecords] of Object.entries(subdomainGroups)) {
                if (subdomainRecords.length > 1) {
                    // Only CNAME records should be chained (they represent actual DNS resolution chains)
                    if (recordType === 'CNAME') {
                        const chain = [this.createSubdomainLink(subdomain)];
                        subdomainRecords.forEach(record => {
                            chain.push(record.data);
                        });
                        html += `• ${chain.join(' → ')}<br>`;
                    } else {
                        // All other record types (TXT, MX, NS, etc.) should be separate line items
                        subdomainRecords.forEach(record => {
                            let recordText = `• ${this.createSubdomainLink(subdomain)} → ${record.data}`;
                            if (record.TTL) {
                                recordText += ` (TTL: ${record.TTL}s)`;
                            }
                            if (record.priority !== null && record.priority !== undefined) {
                                recordText += ` (Priority: ${record.priority})`;
                            }
                            html += `${recordText}<br>`;
                        });
                    }
                } else {
                    // Single record
                    const record = subdomainRecords[0];
                    let recordText = `• ${this.createSubdomainLink(subdomain)} → ${record.data}`;
                    if (record.TTL) {
                        recordText += ` (TTL: ${record.TTL}s)`;
                    }
                    if (record.priority !== null && record.priority !== undefined) {
                        recordText += ` (Priority: ${record.priority})`;
                    }
                    html += `${recordText}<br>`;
                }
            }
        }
        
        html += '</div></div>';
        return html;
    }

    // Group records by type
    groupRecordsByType(records) {
        const grouped = {};
        for (const record of records) {
            const recordType = this.getDNSRecordTypeName(record.type) || 'UNKNOWN';
            if (!grouped[recordType]) {
                grouped[recordType] = [];
            }
            grouped[recordType].push(record);
        }
        return grouped;
    }

    // Group records by subdomain
    groupRecordsBySubdomain(records) {
        const grouped = {};
        for (const record of records) {
            const subdomain = record.subdomain || 'unknown';
            if (!grouped[subdomain]) {
                grouped[subdomain] = [];
            }
            grouped[subdomain].push(record);
        }
        return grouped;
    }

    // Create subdomain link
    createSubdomainLink(subdomain) {
        return `<a href="https://${subdomain}" target="_blank" style="color: #2196f3; text-decoration: underline;">${subdomain}</a>`;
    }

    // Get DNS record type name
    getDNSRecordTypeName(typeNumber) {
        const recordTypes = {
            1: 'A', 5: 'CNAME', 6: 'SOA', 15: 'MX', 16: 'TXT', 28: 'AAAA',
            2: 'NS', 12: 'PTR', 33: 'SRV', 46: 'RRSIG', 47: 'NSEC',
            48: 'DNSKEY', 43: 'DS', 44: 'SSHFP', 45: 'IPSECKEY',
            99: 'SPF', 250: 'CAA'
        };
        return recordTypes[typeNumber] || `Type ${typeNumber}`;
    }

    // Display security issues
    displaySecurity(securityResults) {
        const container = document.getElementById('securityServices');
        const section = container?.closest('.service-category');
        
        if (!container) return;
        
        // Collect all security issues
        const allIssues = [
            ...(securityResults.takeovers || []).map(issue => ({ ...issue, category: 'takeover' })),
            ...(securityResults.dnsIssues || []).map(issue => ({ ...issue, category: 'dns' })),
            ...(securityResults.emailIssues || []).map(issue => ({ ...issue, category: 'email' })),
            ...(securityResults.cloudIssues || []).map(issue => ({ ...issue, category: 'cloud' }))
        ];
        
        if (allIssues.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        if (section) section.style.display = 'block';
        
        // Group by risk level
        const riskGroups = {
            high: allIssues.filter(issue => issue.risk === 'high'),
            medium: allIssues.filter(issue => issue.risk === 'medium'),
            low: allIssues.filter(issue => issue.risk === 'low')
        };
        
        let html = '';
        
        if (riskGroups.high.length > 0) {
            html += `<div class="risk-section"><h4>🚨 High Risk Issues (${riskGroups.high.length})</h4>`;
            riskGroups.high.forEach(issue => {
                html += this.formatSecurityIssue(issue);
            });
            html += '</div>';
        }
        
        if (riskGroups.medium.length > 0) {
            html += `<div class="risk-section"><h4>⚠️ Medium Risk Issues (${riskGroups.medium.length})</h4>`;
            riskGroups.medium.forEach(issue => {
                html += this.formatSecurityIssue(issue);
            });
            html += '</div>';
        }
        
        if (riskGroups.low.length > 0) {
            html += `<div class="risk-section"><h4>ℹ️ Low Risk Issues (${riskGroups.low.length})</h4>`;
            riskGroups.low.forEach(issue => {
                html += this.formatSecurityIssue(issue);
            });
            html += '</div>';
        }
        
        container.innerHTML = html;
    }

    // Format security issue
    formatSecurityIssue(issue) {
        const riskColors = {
            critical: '#8B0000', high: '#FF8C00', medium: '#FFD700',
            low: '#0066CC', info: '#FFFFFF'
        };
        
        const categoryIcons = {
            takeover: '🎯', dns: '🌐', email: '📧',
            infrastructure: '🏗️', cloud: '☁️'
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
        
        // Add specific details
        if (issue.subdomain) html += `<div class="service-records"><strong>Subdomain:</strong> ${this.createSubdomainLink(issue.subdomain)}<br>`;
        if (issue.cname) html += `<strong>CNAME:</strong> ${issue.cname}<br>`;
        if (issue.service) html += `<strong>Service:</strong> ${issue.service}<br>`;
        if (issue.ip) html += `<strong>IP:</strong> ${issue.ip}<br>`;
        if (issue.record) html += `<strong>Record:</strong> ${issue.record}<br>`;
        if (issue.pattern) html += `<strong>Pattern:</strong> ${issue.pattern}<br>`;
        
        html += '</div></div>';
        return html;
    }

    // Display interesting findings
    displayInterestingFindings(interestingFindings) {
        const container = document.getElementById('interestingFindings');
        const section = container?.closest('.service-category');
        
        if (!container) return;
        
        if (!interestingFindings || interestingFindings.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        if (section) section.style.display = 'block';
        
        const patternFindings = interestingFindings.filter(f => f.type === 'interesting_subdomain');
        const serviceFindings = interestingFindings.filter(f => f.type === 'service_subdomain');
        
        let html = `<div class="risk-section"><h4>🔍 Interesting Infrastructure Findings (${interestingFindings.length})</h4>`;
        html += '<p style="color: #666; font-size: 0.9rem; margin-bottom: 15px;"><em>⚠️ Note: These findings are based on pattern matching of active subdomains only. Historical/obsolete subdomains are excluded. No actual content verification is performed.</em></p>';
        
        if (serviceFindings.length > 0) {
            html += `<div style="margin-bottom: 20px;"><h5 style="color: #17a2b8; margin-bottom: 10px;">🔧 Service-Related Subdomains (${serviceFindings.length})</h5>`;
            serviceFindings.forEach(finding => {
                html += this.formatInterestingFinding(finding);
            });
            html += '</div>';
        }
        
        if (patternFindings.length > 0) {
            html += `<div style="margin-bottom: 20px;"><h5 style="color: #17a2b8; margin-bottom: 10px;">🔍 Interesting Patterns (${patternFindings.length})</h5>`;
            patternFindings.forEach(finding => {
                html += this.formatInterestingFinding(finding);
            });
            html += '</div>';
        }
        
        html += '</div>';
        container.innerHTML = html;
    }

    // Format interesting finding
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

    // Display redirects to main domain (compact version)
    displayRedirectsToMain(redirects) {
        const container = document.getElementById('redirectsToMain');
        const section = container?.closest('.service-category');
        if (!container) return;
        
        if (!redirects || redirects.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        // Create compact hyperlinked list
        const redirectLinks = redirects.map(redirect => 
            this.createSubdomainLink(redirect.subdomain)
        ).join(', ');
        
        let html = `
            <div class="service-item" style="border-left: 4px solid #28a745;">
                <div class="service-name">🔄 Subdomain Redirects to Main Domain (${redirects.length})</div>
                <div class="service-description">
                    <em>These subdomains redirect to the main domain and serve the same content:</em><br>
                    <div class="redirect-links">${redirectLinks}</div>
                </div>
            </div>
        `;
        
        container.innerHTML = html;
        if (section) section.style.display = 'block';
    }

    // Display CNAME mappings
    displayCNAMEMappings(subdomainsMap) {
        const container = document.getElementById('cnameMappings');
        const section = container?.closest('.service-category');
        if (!container) return;
        
        // Get unclassified CNAME subdomains
        const cnameSubdomains = Array.from(subdomainsMap.values()).filter(subdomain =>
            this.hasSignificantCNAME(subdomain)
        );
        
        if (cnameSubdomains.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        if (section) section.style.display = 'block';
        
        // Group by CNAME target
        const cnameGroups = this.groupCNAMEsByTarget(cnameSubdomains);
        
        let html = '';
        Object.entries(cnameGroups).forEach(([target, subdomains]) => {
            const domainName = this.extractDomainFromCNAME(target);
            
            html += `
                <div class="service-item">
                    <div class="service-name">🎯 ${domainName}</div>
                    <div class="service-description">
                        ${subdomains.length} subdomain${subdomains.length > 1 ? 's' : ''} pointing to this service
                    </div>
                    <div class="service-records">
                        <strong>Subdomains:</strong><br>
                        ${subdomains.map(sub => {
                            let info = sub.ipAddresses[0] || '';
                            if (sub.cnameChain && sub.cnameChain.length > 0) {
                                const chain = [sub.subdomain];
                                sub.cnameChain.forEach(link => chain.push(link.to));
                                if (sub.ipAddresses[0]) chain.push(sub.ipAddresses[0]);
                                info = ` → ${chain.join(' → ')}`;
                            } else if (sub.ipAddresses[0]) {
                                info = ` → ${sub.ipAddresses[0]}`;
                            }
                            return `• ${this.createSubdomainLink(sub.subdomain)}${info}`;
                        }).join('<br>')}
                    </div>
                </div>
            `;
        });
        
        container.innerHTML = html;
    }

    // Check if subdomain has significant CNAME
    hasSignificantCNAME(subdomain) {
        return (subdomain.cnameTarget && subdomain.cnameTarget !== subdomain.subdomain) ||
               (subdomain.cnameChain && subdomain.cnameChain.length > 0);
    }

    // Group CNAMEs by target
    groupCNAMEsByTarget(cnameSubdomains) {
        const groups = {};
        cnameSubdomains.forEach(subdomain => {
            const target = subdomain.cnameTarget || 
                          (subdomain.cnameChain && subdomain.cnameChain.length > 0 ? 
                           subdomain.cnameChain[0].to : null);
            if (target) {
                if (!groups[target]) groups[target] = [];
                groups[target].push(subdomain);
            }
        });
        return groups;
    }

    // Extract domain from CNAME target
    extractDomainFromCNAME(cnameTarget) {
        if (!cnameTarget) return '';
        
        let domain = cnameTarget.replace(/\.$/, '');
        const parts = domain.split('.');
        
        if (parts.length >= 2) {
            const specialTLDs = ['co.uk', 'com.au', 'co.za', 'co.nz'];
            
            for (const specialTLD of specialTLDs) {
                if (domain.endsWith('.' + specialTLD)) {
                    const beforeSpecialTLD = domain.substring(0, domain.length - specialTLD.length - 1);
                    const beforeParts = beforeSpecialTLD.split('.');
                    if (beforeParts.length >= 1) {
                        return beforeParts[beforeParts.length - 1] + '.' + specialTLD;
                    }
                }
            }
            
            return parts.slice(-2).join('.');
        }
        
        return domain;
    }

    // Display subdomains (delegate filtering to DataProcessor)
    displaySubdomains(processedData) {
        const container = document.getElementById('subdomainServices');
        const section = container?.closest('.service-category');
        
        if (!container) return;
        
        // Use DataProcessor to get properly filtered unclassified subdomains
        // This ensures no duplicates with other sections
        const unclassifiedSubdomains = processedData.dataProcessor ? 
            processedData.dataProcessor.getUnclassifiedSubdomains() :
            []; // Fallback to empty array if dataProcessor not available
        
        if (unclassifiedSubdomains.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        if (section) section.style.display = 'block';
        
        // Group by provider (delegate to DataProcessor)
        const providerGroups = processedData.dataProcessor ? 
            processedData.dataProcessor.groupSubdomainsByProvider(unclassifiedSubdomains) :
            [];
        
        let html = '';
        providerGroups.forEach(provider => {
            html += `
                <div class="service-item">
                    <div class="service-name">🏢 ${provider.vendor}</div>
                    <div class="service-description">
                        ${provider.totalSubdomains} subdomains • ${provider.uniqueIPs} unique IPs
                    </div>
                    <div class="service-records">
                        <strong>Subdomains:</strong><br>
                        ${provider.subdomains.map(sub => {
                            let info = sub.ipAddresses[0] || 'no IP';
                            if (sub.cnameChain && sub.cnameChain.length > 0) {
                                const chain = [sub.subdomain];
                                sub.cnameChain.forEach(link => chain.push(link.to));
                                if (sub.ipAddresses[0]) chain.push(sub.ipAddresses[0]);
                                info = chain.join(' → ');
                            } else if (sub.cnameTarget) {
                                if (sub.ipAddresses[0]) {
                                    info = `CNAME → ${sub.cnameTarget} → ${sub.ipAddresses[0]}`;
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
        });
        
        container.innerHTML = html;
    }



    // Display DNS records (SPF, DMARC, etc.)
    displayDNSRecords(dnsRecords) {
        const container = document.getElementById('dnsRecords');
        const section = container?.closest('.service-category');
        if (!container) return;

        if (!dnsRecords || dnsRecords.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }

        if (section) section.style.display = 'block';
        let html = '';

        // Group DNS records by category
        const recordsByCategory = {};
        dnsRecords.forEach(record => {
            const category = record.category || 'other';
            if (!recordsByCategory[category]) {
                recordsByCategory[category] = [];
            }
            recordsByCategory[category].push(record);
        });

        // Display each category
        Object.keys(recordsByCategory).forEach(category => {
            const categoryName = category === 'email-security' ? 'Email Security' : category.toUpperCase();
            html += `<div class="dns-category">
                <h4 class="dns-category-title">${categoryName}</h4>`;

            recordsByCategory[category].forEach(record => {
                html += `<div class="dns-record">
                    <div class="dns-record-header">
                        <span class="dns-record-type">${record.type}</span>
                        <span class="dns-record-name">${record.name}</span>
                    </div>
                    <div class="dns-record-description">${record.description}</div>
                    <div class="dns-record-data">
                        <code>${this.truncateText(record.data, 100)}</code>
                    </div>`;

                // Show parsed DMARC info if available
                if (record.parsed && record.type === 'DMARC') {
                    html += `<div class="dmarc-parsed">
                        <strong>Policy:</strong> ${record.parsed.policy} | 
                        <strong>Reporting:</strong> ${record.parsed.reporting || 'None configured'}
                    </div>`;
                }

                html += `</div>`;
            });

            html += `</div>`;
        });

        container.innerHTML = html;
    }

    // Show progressive status message
    showProgressiveStatus(stats) {
        // Add a temporary status message at the top of results
        let statusDiv = document.getElementById('progressive-status');
        if (!statusDiv) {
            statusDiv = document.createElement('div');
            statusDiv.id = 'progressive-status';
            statusDiv.className = 'progressive-status';
            this.resultsDiv.insertBefore(statusDiv, this.resultsDiv.firstChild);
        }

        const subdomainCount = stats.totalSubdomains || 0;
        const serviceCount = stats.totalServices || 0;

        statusDiv.innerHTML = `
            <div class="status-message">
                <span class="status-icon">⏳</span>
                <span class="status-text">
                    <strong>Analysis in progress...</strong> 
                    Showing ${serviceCount} services and ${subdomainCount} subdomains discovered so far.
                    Additional results will appear as external APIs respond.
                </span>
            </div>
        `;

        // Remove the status message after 10 seconds
        setTimeout(() => {
            if (statusDiv && statusDiv.parentNode) {
                statusDiv.remove();
            }
        }, 10000);
    }

    // Display historical records
    displayHistoricalRecords(historicalRecords) {
        const container = document.getElementById('historicalRecords');
        const section = container?.closest('.service-category');
        if (!container) return;
        
        if (!historicalRecords || historicalRecords.length === 0) {
            if (section) section.style.display = 'none';
            return;
        }
        
        if (section) section.style.display = 'block';
        
        let html = `
            <div class="service-item" style="border-left: 4px solid #6c757d;">
                <div class="service-name">📜 Historical/Obsolete Records</div>
                <div class="service-description">
                    <em>These subdomains were found in certificate transparency logs but have no active DNS records.</em>
                </div>
                <div style="margin-top: 15px;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem;">
                        <thead>
                            <tr style="background: #f8f9fa; border-bottom: 2px solid #dee2e6;">
                                <th style="padding: 8px; text-align: left; font-weight: 600;">📜 Subdomain</th>
                                <th style="padding: 8px; text-align: left; font-weight: 600;">Source</th>
                                <th style="padding: 8px; text-align: left; font-weight: 600;">Discovered</th>
                                <th style="padding: 8px; text-align: left; font-weight: 600;">Issuer</th>
                                <th style="padding: 8px; text-align: left; font-weight: 600;">Expiry</th>
                            </tr>
                        </thead>
                        <tbody>
        `;
        
        historicalRecords.forEach((record, index) => {
            const rowStyle = index % 2 === 0 ? 'background: #f8f9fa;' : '';
            const subdomain = record.subdomain || 'Unknown';
            const source = record.source || 'Unknown';
            const discovered = record.discoveredAt ? new Date(record.discoveredAt).toLocaleDateString() : 'Unknown';
            
            // Extract issuer and expiry from certificate info
            let issuer = 'Unknown';
            let expiry = 'Unknown';
            
            if (record.certificateInfo) {
                if (record.certificateInfo.issuer && record.certificateInfo.issuer !== 'No certificate info available') {
                    if (record.certificateInfo.issuer === 'No certificate info available') {
                        issuer = 'N/A';
                    } else if (record.certificateInfo.issuer.includes("Let's Encrypt")) {
                        issuer = "Let's Encrypt";
                    } else if (record.certificateInfo.issuer.includes('DigiCert')) {
                        issuer = 'DigiCert';
                    } else if (record.certificateInfo.issuer.includes('Amazon')) {
                        issuer = 'Amazon RSA 2048 M03';
                    } else if (record.certificateInfo.issuer.includes('Comodo')) {
                        issuer = 'Comodo';
                    } else if (record.certificateInfo.issuer.includes('GoDaddy')) {
                        issuer = 'GoDaddy';
                    } else if (record.certificateInfo.issuer.includes('GlobalSign')) {
                        issuer = 'GlobalSign';
                    } else {
                        // Try to extract CN from issuer string
                        const cnMatch = record.certificateInfo.issuer.match(/CN=([^,]+)/);
                        issuer = cnMatch ? cnMatch[1] : 'Unknown';
                    }
                }
                
                if (record.certificateInfo.validTo) {
                    expiry = new Date(record.certificateInfo.validTo).toLocaleDateString();
                }
            }
            
            html += `
                <tr style="${rowStyle}">
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6;">
                        ${this.createSubdomainLink(subdomain)}
                    </td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6;">
                        <span class="source-badge" style="background: #6c757d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.8rem;">
                            ${source}
                        </span>
                    </td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: #6c757d;">
                        ${discovered}
                    </td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: #6c757d;">
                        ${issuer}
                    </td>
                    <td style="padding: 8px; border-bottom: 1px solid #dee2e6; color: #6c757d;">
                        ${expiry}
                    </td>
                </tr>
            `;
        });
        
        html += `
                        </tbody>
                    </table>
                </div>
            </div>
        `;
        
        container.innerHTML = html;
    }

    // Display API notifications
    displayAPINotifications(apiNotifications) {
        const container = document.getElementById('apiNotifications');
        const section = document.getElementById('apiStatusSection');
        if (!container || !section) return;
        
        const errorNotifications = apiNotifications.filter(n => n.status === 'error' || n.status === 'warning');
        
        if (errorNotifications.length === 0) {
            section.style.display = 'none';
            return;
        }
        
        section.style.display = 'block';
        
        let html = '';
        errorNotifications.forEach(notification => {
            const statusIcon = notification.status === 'warning' ? '⚠️' : '❌';
            const statusClass = notification.status === 'warning' ? 'warning' : 'error';
            
            html += `
                <div class="api-notification ${statusClass}">
                    <span class="api-name">${statusIcon} ${notification.api}</span>
                    <span class="api-message">${notification.message}</span>
                    <span class="api-time">${notification.timestamp}</span>
                </div>
            `;
        });
        
        container.innerHTML = html;
    }
} 