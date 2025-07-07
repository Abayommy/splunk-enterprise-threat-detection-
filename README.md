# 🛡️ Enterprise Splunk Security Analysis Platform

**Live cybersecurity threat detection platform demonstrating real-world SIEM capabilities**

## 🏗️ Distributed Architecture Overview
**3-Tier Splunk Deployment on AWS:**
- **Search Head** (SplunkSHs) - Web interface, search coordination - `18.118.193.91:8000`
- **Indexer** (SplunkIDX) - Data storage and search processing - `3.143.141.242`
- **Universal Forwarder** (SplunkUF) - Data collection from endpoints - `18.217.152.32`

## 🚨 Live Threat Detection Results
**Successfully detected and analyzed real brute force attack:**
- **Target IP:** `192.168.1.100`
- **Failed Login Attempts:** **6**
- **Risk Assessment:** MEDIUM threat level
- **Detection Method:** Advanced SPL with statistical analysis
- **Response Time:** 5-minute automated monitoring intervals
- **Status:** Active threat identified and classified

## 💻 Advanced SPL Queries Developed

### Enhanced Brute Force Detection (Production)
```spl
index=* sourcetype=*auth* (failed OR Failed OR FAILED) 
| eval src_ip=coalesce(src_ip, client_ip, "unknown") 
| eval user=coalesce(failed_user, invalid_user, user, "unknown") 
| bucket _time span=1m 
| stats count dc(user) as unique_users by _time src_ip 
| where count > 5 
| eval risk_level=case(count>20, "CRITICAL", count>10, "HIGH", count>5, "MEDIUM") 
| sort -count
```

### Working Brute Force Detection (Verified)
```spl
index=* sourcetype=*auth* (failed OR Failed OR FAILED) 
| eval src_ip=coalesce(src_ip, client_ip, "unknown") 
| stats count by src_ip 
| where count > 2 
| sort -count
```

### Lateral Movement Detection
```spl
index=* sourcetype=*auth* (success* OR accept* OR Success* OR Accept*) 
| eval user=coalesce(user, session_user, "unknown") 
| eval host=coalesce(auth_host, host, "unknown") 
| stats dc(host) as unique_hosts values(host) as hosts by user 
| where unique_hosts > 2 
| sort -unique_hosts
```

### Geographic Threat Analysis
```spl
index=* sourcetype=*auth* (failed OR Failed) 
| eval src_ip=coalesce(src_ip, client_ip) 
| iplocation src_ip 
| stats count by Country City src_ip 
| where count > 10 
| sort -count
```

## 🛡️ Security Macros Implemented
- **`auth_events`** - Authentication log aggregation across multiple sources
- **`failed_logins`** - Failed authentication pattern matching
- **`risk_scoring`** - Automated threat level classification (CRITICAL/HIGH/MEDIUM/LOW)
- **`extract_ip`** - Multi-source IP normalization using coalesce functions
- **`privilege_events`** - Privilege escalation monitoring and detection

## 🎯 Enterprise Security Capabilities Demonstrated

### Real-Time Threat Detection
- ✅ **Brute force attack identification** (6 failed attempts detected)
- ✅ **Risk-based threat classification** with automated scoring
- ✅ **Statistical anomaly detection** using advanced SPL
- ✅ **Multi-source log correlation** for comprehensive analysis

### Advanced SIEM Administration
- ✅ **Distributed Splunk architecture** deployed and configured
- ✅ **Custom field extractions** for multiple log formats
- ✅ **Automated alerting** with 5-minute monitoring intervals
- ✅ **Search optimization** for high-performance queries

## 🏆 Professional Skills Showcased

### 🛡️ Security Information and Event Management (SIEM)
- Advanced Splunk administration and configuration
- Multi-tier enterprise architecture deployment
- Real-time threat detection and automated alerting
- Custom correlation rule development and optimization

### 🔍 Threat Hunting and Analysis
- Behavioral analysis for advanced persistent threats
- Statistical anomaly detection and risk scoring
- Multi-source log correlation and analysis
- Incident detection and classification workflows

### ☁️ Cloud Infrastructure Management
- AWS EC2 instance deployment and management
- Security group configuration and network architecture
- Distributed system design and implementation
- High availability and scalability planning

## 📋 Technical Implementation Files
- **`props.conf`** - Advanced field extractions (2,691 bytes)
- **`macros.conf`** - Security analysis macros (802 bytes)
- **`savedsearches.conf`** - Automated detection searches (2,404 bytes)
- **`eventtypes.conf`** - Event classification rules (728 bytes)

## 🎓 Use Cases for Cybersecurity Roles
**This portfolio demonstrates enterprise-ready capabilities for:**
- **SOC Analyst** - Real threat detection and incident response
- **Security Engineer** - SIEM administration and architecture design
- **Threat Hunter** - Advanced query development and behavioral analysis
- **Cybersecurity Specialist** - Multi-platform security monitoring

---
**🔗 Portfolio demonstrates live, production-ready cybersecurity analysis capabilities with verified threat detection results.**
