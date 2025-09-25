# Vulnerability Assessment Report (Redacted)

Generated: 2025-09-25 15:59 UTC

## Executive Summary
This report presents findings from a Nessus Essentials basic network scan. Host identifiers have been redacted to preserve confidentiality. The scan identified several medium-severity issues (notably untrusted SSL certificate and SMB signing not required). No critical severity vulnerabilities were identified in the exported results. Credentialed re-scan is recommended to obtain a complete patch assessment.

## Scope & Methodology
- **Tool**: Nessus Essentials
- **Scan Template**: Basic Network Scan
- **Targets**: [REDACTED]
- **Scan Type**: Non-credentialed (credentialed recommended for patch assessment)
- **Notes**: The original host IPs have been replaced with [REDACTED_HOST] in this report.

## Top Findings (sorted by severity)
### 1. SSL Certificate Cannot Be Trusted
- **Severity**: Medium
- **CVSS**: 6.4
- **Plugin ID**: 51192
- **Description**: The server's X.509 certificate cannot be trusted. This situation can occur in three different ways, in which the chain of trust can be broken, as stated below :

  - First, the top of the certificate chain sent by the     server might not be descended from a known public     certificate authority. This can occur either when the     top of the chain is an unrecognized, self-signed     certificate, or when intermediate certificates are     missing that would connect the top of the certificate     chain to a known public certificate authority.

  - Second, the certificate chain may contain a certificate     that is not valid at the time of the scan. This can     occur either when the scan occurs before one of the     certificate's 'notBefore' dates, or after one of the     certificate's 'notAfter' dates.

  - Third, the certificate chain may contain a signature     that either didn't match the certificate's information     or could not be verified. Bad signatures can be fixed by     getting the certificate with the bad signature to be     re-signed by its issuer. Signatures that could not be     verified are the result of the certificate's issuer     using a signing algorithm that Nessus either does not     support or does not recognize.

If the remote host is a public host in production, any break in the chain makes it more difficult for users to verify the authenticity and identity of the web server. This could make it easier to carry out man-in-the-middle attacks against the remote host.
- **Suggested Remediation**: Purchase or generate a proper SSL certificate for this service.

### 2. SMB Signing not required
- **Severity**: Medium
- **CVSS**: 5.0
- **Plugin ID**: 57608
- **Description**: Signing is not required on the remote SMB server. An unauthenticated, remote attacker can exploit this to conduct man-in-the-middle attacks against the SMB server.
- **Suggested Remediation**: Enforce message signing in the host's configuration. On Windows, this is found in the policy setting 'Microsoft network server: Digitally sign communications (always)'. On Samba, the setting is called 'server signing'. See the 'see also' links for further details.

### 3. OS Security Patch Assessment Not Available
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 117886
- **Description**: OS Security Patch Assessment is not available on the remote host.
This does not necessarily indicate a problem with the scan.
Credentials may not have been provided, OS security patch assessment may not be supported for the target, the target may not have been identified, or another issue may have occurred that prevented OS security patch assessment from being available. See plugin output for details.

This plugin reports non-failure information impacting the availability of OS Security Patch Assessment. Failure information is reported by plugin 21745 : 'OS Security Patch Assessment failed'.  If a target host is not supported for OS Security Patch Assessment, plugin 110695 : 'OS Security Patch Assessment Checks Not Supported' will report concurrently with this plugin.
- **Suggested Remediation**: n/a

### 4. Common Platform Enumeration (CPE)
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 45590
- **Description**: By using information obtained from a Nessus scan, this plugin reports CPE (Common Platform Enumeration) matches for various hardware and software products found on a host. 

Note that if an official CPE is not available for the product, this plugin computes the best possible CPE based on the information available from the scan.
- **Suggested Remediation**: n/a

### 5. Nessus Scan Information
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 19506
- **Description**: This plugin displays, for each tested host, information about the scan itself :

  - The version of the plugin set.
  - The type of scanner (Nessus or Nessus Home).
  - The version of the Nessus Engine.
  - The port scanner(s) used.
  - The port range scanned.
  - The ping round trip time 
  - Whether credentialed or third-party patch management     checks are possible.
  - Whether the display of superseded patches is enabled
  - The date of the scan.
  - The duration of the scan.
  - The number of hosts scanned in parallel.
  - The number of checks done in parallel.
- **Suggested Remediation**: n/a

### 6. Unknown Service Detection: Banner Retrieval
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 11154
- **Description**: Nessus was unable to identify a service on the remote host even though it returned a banner of some type.
- **Suggested Remediation**: n/a

### 7. Target Credential Status by Authentication Protocol - No Credentials Provided
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 110723
- **Description**: Nessus was not able to successfully authenticate directly to the remote target on an available authentication protocol. Nessus was able to connect to the remote port and identify that the service running on the port supports an authentication protocol, but Nessus failed to authenticate to the remote service using the provided credentials. There may have been a protocol failure that prevented authentication from being attempted or all of the provided credentials for the authentication protocol may be invalid. See plugin output for error details.

Please note the following :

- This plugin reports per protocol, so it is possible for   valid credentials to be provided for one protocol and not   another. For example, authentication may succeed via SSH   but fail via SMB, while no credentials were provided for   an available SNMP service.

- Providing valid credentials for all available   authentication protocols may improve scan coverage, but   the value of successful authentication for a given   protocol may vary from target to target depending upon   what data (if any) is gathered from the target via that   protocol. For example, successful authentication via SSH   is more valuable for Linux targets than for Windows   targets, and likewise successful authentication via SMB   is more valuable for Windows targets than for Linux   targets.
- **Suggested Remediation**: n/a

### 8. SSL Certificate Information
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 10863
- **Description**: This plugin connects to every SSL-related port and attempts to extract and dump the X.509 certificate.
- **Suggested Remediation**: n/a

### 9. MySQL Server Detection
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 10719
- **Description**: The remote host is running MySQL, an open source database server.
- **Suggested Remediation**: n/a

### 10. MySQL Server Detection
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 10719
- **Description**: The remote host is running MySQL, an open source database server.
- **Suggested Remediation**: n/a

### 11. MySQL Server Detection
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 10719
- **Description**: The remote host is running MySQL, an open source database server.
- **Suggested Remediation**: n/a

### 12. Device Type
- **Severity**: Info
- **CVSS**: N/A
- **Plugin ID**: 54615
- **Description**: Based on the remote operating system, it is possible to determine what the remote system type is (eg: a printer, router, general-purpose computer, etc).
- **Suggested Remediation**: n/a

## Overall Recommendations
- Replace or reissue untrusted SSL/TLS certificates with ones from a trusted CA.
- Enable SMB message signing to protect against man-in-the-middle attacks (use Group Policy for domain environments).
- Perform a credentialed scan by supplying admin/SSH credentials so the scanner can perform a complete patch assessment.
- Apply outstanding OS and software patches identified by a credentialed scan.
- Repeat vulnerability scans regularly (monthly for personal systems; more often for production services) and after major updates.
- Validate and test remediation in a controlled environment before wide deployment.

**Note**: Host IPs were redacted to `[REDACTED_HOST]` as requested.
