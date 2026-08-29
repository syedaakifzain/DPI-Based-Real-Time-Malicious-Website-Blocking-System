# 🛡️ DPI-Based Real-Time Malicious Website Blocking System

> **A host-based cybersecurity system that uses Deep Packet Inspection (DPI), real-time network traffic analysis, TLS SNI/HTTP domain extraction, threat intelligence, and rule-based filtering to detect and block malicious websites.**

![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Deep Packet Inspection](https://img.shields.io/badge/Network-Deep%20Packet%20Inspection-purple)
![Security](https://img.shields.io/badge/Security-Real--Time-orange)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 📌 Table of Contents

* [Overview](#-overview)
* [Problem Statement](#-problem-statement)
* [Solution](#-solution)
* [Objectives](#-objectives)
* [Key Features](#-key-features)
* [How the System Works](#-how-the-system-works)
* [System Architecture](#-system-architecture)
* [Detection Pipeline](#-detection-pipeline)
* [Deep Packet Inspection](#-deep-packet-inspection)
* [Domain Extraction](#-domain-extraction)
* [Threat Detection](#-threat-detection)
* [Website Blocking](#-website-blocking)
* [Project Structure](#-project-structure)
* [Technology Stack](#-technology-stack)
* [Core Components](#-core-components)
* [Installation](#-installation)
* [Running the Project](#-running-the-project)
* [Testing](#-testing)
* [Example Detection Flow](#-example-detection-flow)
* [Security Use Cases](#-security-use-cases)
* [Advantages](#-advantages)
* [Limitations](#-limitations)
* [Future Enhancements](#-future-enhancements)
* [Learning Outcomes](#-learning-outcomes)
* [Ethical and Legal Disclaimer](#-ethical-and-legal-disclaimer)
* [Author](#-author)

---

# 🔍 Overview

The **DPI-Based Real-Time Malicious Website Blocking System** is a cybersecurity project designed to monitor network traffic at the host level and identify potentially malicious websites before or during a user's connection attempt.

Traditional website-blocking mechanisms often rely only on:

* Domain blacklists
* DNS filtering
* Static firewall rules
* IP-address filtering

These approaches can be limited because modern websites frequently use:

* Dynamic IP addresses
* HTTPS encryption
* Content delivery networks
* Multiple domains and subdomains
* Frequently changing infrastructure

This project explores a more security-focused approach using **Deep Packet Inspection (DPI)**.

The system captures network packets, analyzes their contents and metadata, extracts domain information from protocols such as HTTP and TLS, and compares the extracted domain against security rules or threat intelligence.

When a domain is identified as malicious or suspicious, the system can enforce a blocking decision and record the security event.

---

# 🚨 Problem Statement

The internet contains a constantly changing ecosystem of:

* Phishing websites
* Malware-hosting domains
* Command-and-control infrastructure
* Suspicious redirects
* Malicious landing pages
* Fraudulent websites

A simple DNS blacklist or static firewall rule may not be sufficient to identify all potentially harmful connections.

The challenge is therefore:

> **How can network traffic be inspected in real time to identify potentially malicious website connections and prevent access to them?**

This project addresses that problem by combining:

**Packet Capture → Deep Packet Inspection → Domain Extraction → Threat Intelligence → Rule Evaluation → Blocking**

---

# 💡 Solution

The proposed system operates as a host-based security layer.

When a user attempts to access a website:

1. Network traffic is generated.
2. The endpoint agent captures relevant packets.
3. The DPI engine analyzes packet headers and payload information.
4. The system attempts to extract the destination domain.
5. The extracted domain is evaluated against configured security rules or threat intelligence.
6. If the domain is considered malicious, the connection is blocked.
7. The event can be recorded for monitoring and analysis.

This creates a security pipeline capable of reacting to suspicious network activity in real time.

---

# 🎯 Objectives

The primary objectives of this project are:

* Monitor network traffic in real time.
* Perform Deep Packet Inspection.
* Extract domain information from network traffic.
* Analyze HTTP and TLS-related information.
* Identify potentially malicious domains.
* Apply configurable security rules.
* Block suspicious or malicious connections.
* Track active network connections.
* Provide a foundation for centralized threat intelligence.
* Demonstrate practical endpoint security concepts.

---

# ✨ Key Features

## 🔎 Deep Packet Inspection

The system analyzes network packets beyond basic source and destination information.

It can inspect relevant application-layer information to determine what type of traffic is being generated.

---

## 🌐 Real-Time Traffic Monitoring

Network traffic can be analyzed as packets are captured instead of relying exclusively on previously recorded traffic.

This allows the system to respond to suspicious connections while they are occurring.

---

## 🧠 Malicious Domain Detection

The system extracts domain information from network traffic and evaluates the domain against configured security rules.

Potential detection sources include:

* HTTP Host headers
* TLS Server Name Indication (SNI)
* Network connection metadata
* Configured malicious-domain lists

---

## 🔐 TLS SNI Extraction

Modern websites primarily use HTTPS.

Although HTTPS encrypts the application payload, TLS connection establishment can expose metadata such as the **Server Name Indication (SNI)** in applicable configurations.

The project includes an SNI extraction component that can use this information to identify the intended destination domain.

---

## 🚫 Rule-Based Website Blocking

The system supports rule-based security decisions.

A domain can be evaluated and classified as:

```text
ALLOW
BLOCK
SUSPICIOUS
UNKNOWN
```

This creates an extensible foundation for implementing more advanced security policies.

---

## 📊 Connection Tracking

The connection tracker maintains information about observed network connections.

This can help identify:

* Source addresses
* Destination addresses
* Ports
* Protocols
* Connection state
* Domain information

---

## 🧪 PCAP-Based Testing

The repository contains a `test_dpi.pcap` file that can be used for packet-analysis testing and experimentation.

This allows DPI functionality to be evaluated using recorded network traffic without always requiring live traffic capture.

---

# ⚙️ How the System Works

The high-level workflow is:

```text
                 ┌──────────────────────┐
                 │     User / Browser   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   Network Traffic    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │    Packet Capture    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │  DPI Packet Parser   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │  Domain Extraction   │
                 │    HTTP / TLS SNI    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │    Rule Manager      │
                 └──────────┬───────────┘
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
             ┌─────────┐         ┌─────────┐
             │  ALLOW  │         │  BLOCK  │
             └─────────┘         └────┬────┘
                                      │
                                      ▼
                              ┌──────────────┐
                              │ Security Log │
                              └──────────────┘
```

---

# 🏗️ System Architecture

The system can be divided into several major components:

### 1. Endpoint Security Agent

Runs on the user's machine and captures network traffic.

### 2. DPI Engine

Analyzes captured packets and extracts useful network information.

### 3. Domain Extraction Layer

Attempts to identify the destination domain using HTTP and TLS metadata.

### 4. Rule Engine

Evaluates extracted domains against configured security policies.

### 5. Blocking Layer

Enforces the security decision when a domain is classified as malicious or blocked.

### 6. Threat Intelligence Layer

Provides a centralized source of malicious-domain information and security rules.

---

# 🔄 Detection Pipeline

The complete detection pipeline can be represented as:

```text
Packet Arrival
      │
      ▼
Packet Capture
      │
      ▼
Packet Parsing
      │
      ▼
Protocol Identification
      │
      ├───────────────┐
      │               │
      ▼               ▼
 HTTP Detection    TLS Detection
      │               │
      ▼               ▼
Host Header        SNI Extraction
      │               │
      └───────┬───────┘
              ▼
        Domain Extraction
              │
              ▼
       Rule / Threat Check
              │
       ┌──────┴──────┐
       ▼             ▼
    Trusted       Malicious
       │             │
       ▼             ▼
     ALLOW         BLOCK
                     │
                     ▼
              Security Event
```

---

# 🔬 Deep Packet Inspection

Deep Packet Inspection refers to analyzing network packets beyond their basic routing information.

A traditional firewall may primarily consider:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

DPI attempts to obtain additional information from the packet and protocol structure.

For example:

```text
IP Header
   ↓
TCP Header
   ↓
Application Data
   ↓
Protocol Information
   ↓
Domain / Host Information
```

This allows the security system to make more informed decisions.

---

# 🌐 Domain Extraction

Domain identification is an important part of the project.

## HTTP Traffic

For HTTP traffic, the destination domain may be available through the HTTP `Host` header.

Example:

```http
GET /login HTTP/1.1
Host: suspicious-example.com
```

The DPI engine can extract:

```text
suspicious-example.com
```

and evaluate it against security rules.

---

## HTTPS / TLS Traffic

HTTPS encrypts application data.

However, depending on the TLS configuration, the initial TLS handshake can expose the **Server Name Indication (SNI)**.

Example:

```text
TLS ClientHello
       │
       ▼
SNI
       │
       ▼
example.com
```

The project includes an SNI extraction module to identify such domains.

---

# 🧠 Threat Detection

After extracting a domain, the system evaluates it against security information.

A simplified decision process is:

```python
if domain in malicious_domains:
    action = "BLOCK"
else:
    action = "ALLOW"
```

A production implementation can extend this model with:

* Domain reputation
* Threat scores
* Category-based policies
* IP reputation
* Frequency analysis
* Anomaly detection
* Machine-learning classification
* External threat-intelligence feeds

---

# 🚫 Website Blocking

When the rule engine determines that a connection should be blocked, the system can apply the configured blocking mechanism.

The conceptual flow is:

```text
User requests website
        ↓
Packet captured
        ↓
Domain extracted
        ↓
Threat intelligence lookup
        ↓
Malicious?
   ┌────┴────┐
   │         │
  YES        NO
   │         │
   ▼         ▼
 BLOCK      ALLOW
   │         │
   ▼         ▼
Log event  Continue
```

The exact enforcement mechanism depends on the operating-system networking configuration and the selected execution mode.

---

# 📁 Project Structure

The current repository contains the following major components:

```text
DPI-Based-Real-Time-Malicious-Website-Blocking-System/
│
├── README.md
│
├── main.py
├── main_dpi.py
├── main_simple.py
├── main_working.py
│
├── packet_parser.py
├── pcap_reader.py
├── connection_tracker.py
├── sni_extractor.py
│
├── realtime_dns_blocker.py
├── rule_manager.py
├── platform_utils.py
├── thread_safe_queue.py
├── types_.py
│
└── test_dpi.pcap
```

---

# 🧩 Core Components

## `main.py`

Primary application entry point.

Responsible for coordinating the major components required to execute the system.

---

## `main_dpi.py`

Entry point focused on the Deep Packet Inspection workflow.

It can be used for DPI-specific experimentation and execution.

---

## `main_simple.py`

Provides a simplified execution path that can be useful during development, debugging, or demonstrations.

---

## `main_working.py`

Contains an additional working implementation/entry point used during development and testing.

---

## `packet_parser.py`

Responsible for parsing captured packets and extracting relevant networking information.

Potential information includes:

* IP addresses
* Ports
* Protocols
* Packet payload
* Application-layer information

---

## `pcap_reader.py`

Handles packet data stored in PCAP files.

This is particularly useful for offline DPI testing.

---

## `connection_tracker.py`

Tracks observed network connections and maintains connection-related state.

---

## `sni_extractor.py`

Responsible for extracting Server Name Indication information from TLS traffic where available.

---

## `rule_manager.py`

Handles security rules used to determine whether traffic should be permitted or blocked.

This component provides an abstraction between packet analysis and security decisions.

---

## `realtime_dns_blocker.py`

Provides functionality related to real-time DNS-based website blocking.

It can be integrated into the overall malicious-domain blocking workflow.

---

## `platform_utils.py`

Contains platform-specific helper functionality.

This helps separate operating-system-specific behavior from the main DPI logic.

---

## `thread_safe_queue.py`

Provides a thread-safe queue mechanism for safely passing information between concurrent components.

---

## `types_.py`

Contains shared type definitions and structures used throughout the project.

---

# 🛠️ Technology Stack

| Category             | Technology             |
| -------------------- | ---------------------- |
| Programming Language | Python                 |
| Cybersecurity        | Deep Packet Inspection |
| Network Analysis     | Packet Capture         |
| Traffic Analysis     | HTTP / TLS             |
| Domain Detection     | HTTP Host / TLS SNI    |
| Packet Testing       | PCAP                   |
| Security Model       | Rule-Based Filtering   |
| DNS Security         | DNS Blocking           |
| Concurrency          | Thread-Safe Processing |
| Threat Detection     | Domain-Based Rules     |

---

# 💻 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/syedaakifzain/DPI-Based-Real-Time-Malicious-Website-Blocking-System.git
```

Navigate into the project:

```bash
cd DPI-Based-Real-Time-Malicious-Website-Blocking-System
```

---

## 2. Create a Virtual Environment

It is recommended to isolate the project's Python dependencies.

### Windows

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
```

Activate:

```bash
source venv/bin/activate
```

---

# 📦 Install Dependencies

Install the required Python networking/security libraries used by the implementation.

Depending on the selected execution mode, packet-capture functionality may require additional system-level packet-capture support.

For example:

```bash
pip install scapy
```

If additional dependencies are required by your environment, install them before running the live-capture components.

---

# ▶️ Running the Project

## Run the Main Application

```bash
python main.py
```

---

## Run the DPI Engine

```bash
python main_dpi.py
```

---

## Run the Simplified Version

```bash
python main_simple.py
```

---

## Run the Working Version

```bash
python main_working.py
```

> **Note:** Packet-capture and network-blocking functionality may require administrator/root privileges depending on the operating system.

---

# 🧪 Testing with PCAP

The repository includes:

```text
test_dpi.pcap
```

PCAP files allow captured traffic to be analyzed without requiring the traffic to be generated again.

A typical testing workflow is:

```text
test_dpi.pcap
      │
      ▼
PCAP Reader
      │
      ▼
Packet Parser
      │
      ▼
DPI Engine
      │
      ▼
Domain / Protocol Extraction
      │
      ▼
Rule Manager
      │
      ▼
Detection Result
```

This approach is useful for:

* Debugging packet parsing
* Testing protocol detection
* Validating SNI extraction
* Reproducing security events
* Demonstrating the project safely

---

# 🔎 Example Detection Flow

Suppose a user attempts to access a known malicious domain.

```text
1. User opens a website
             ↓
2. Browser generates network traffic
             ↓
3. Packet is captured
             ↓
4. DPI engine analyzes the packet
             ↓
5. HTTP Host / TLS SNI is extracted
             ↓
6. Domain is identified
             ↓
7. Domain is checked against security rules
             ↓
8. Domain is classified as malicious
             ↓
9. Connection is blocked
             ↓
10. Security event is recorded
```

Example:

```text
Requested Domain:
phishing-example.com

Threat Database:
phishing-example.com → MALICIOUS

Decision:
BLOCK

Security Event:
Malicious domain access attempt detected
```

---

# 🛡️ Security Use Cases

The system can serve as a foundation for several cybersecurity applications.

### 🎣 Phishing Protection

Detect and block known phishing domains.

### 🦠 Malware Protection

Prevent connections to known malware-hosting infrastructure.

### 📡 Network Monitoring

Observe and analyze endpoint network activity.

### 🤖 Command-and-Control Detection

Identify connections to suspicious infrastructure associated with malware activity.

### 🏢 Enterprise Endpoint Security

Provide an endpoint-level security layer for organizational devices.

### 🎓 Cybersecurity Education

Demonstrate:

* Packet inspection
* Network protocols
* DNS security
* TLS
* Threat intelligence
* Rule-based filtering
* Endpoint protection

### 🔬 Security Research

Provide a platform for experimenting with:

* DPI algorithms
* Domain reputation
* Network anomaly detection
* Threat intelligence
* Automated blocking

---

# ⭐ Advantages

## Real-Time Analysis

Traffic can be analyzed while network communication is occurring.

## Application-Level Visibility

The system attempts to obtain information beyond basic IP filtering.

## HTTPS Awareness

TLS SNI extraction provides a mechanism for identifying domains in applicable encrypted connections.

## Modular Architecture

The project separates packet parsing, connection tracking, rule management, and domain extraction into dedicated components.

## Offline Testing

PCAP support allows repeatable analysis without relying exclusively on live network traffic.

## Extensible Security Model

The rule-based architecture can be expanded with additional detection techniques.

---

# ⚠️ Limitations

Deep Packet Inspection has inherent limitations, especially with modern encrypted traffic.

### Encrypted Traffic

Strong encryption can prevent inspection of application payloads.

### TLS Privacy Improvements

Modern TLS deployments may hide or reduce the visibility of domain information.

### Dynamic Infrastructure

Malicious websites may rapidly change IP addresses and infrastructure.

### False Positives

A rule-based system may incorrectly classify legitimate domains.

### False Negatives

A malicious domain that is not present in the threat intelligence source may not be detected.

### Performance

Packet-level inspection introduces computational overhead, particularly on high-bandwidth networks.

### Platform Dependencies

Low-level packet capture and blocking functionality can depend on operating-system permissions and networking capabilities.

---

# 🚀 Future Enhancements

The project can be extended significantly.

## 🤖 AI-Based Anomaly Detection

Introduce machine-learning models to identify unusual network behavior.

Possible features:

```text
Packet frequency
Connection duration
Destination reputation
Domain entropy
Request frequency
Traffic volume
Protocol characteristics
```

---

## 🌐 Automated Threat Intelligence

Integrate continuously updated threat-intelligence feeds.

Potential sources could provide:

* Malicious domains
* Malware indicators
* Phishing URLs
* Malicious IP addresses
* Reputation scores

---

## 📊 Real-Time Security Dashboard

A web dashboard could display:

```text
┌───────────────────────────────────────────────┐
│              SECURITY DASHBOARD               │
├───────────────────────────────────────────────┤
│ Packets Analyzed        125,430               │
│ Connections             4,821                 │
│ Threats Detected        37                    │
│ Domains Blocked         24                    │
├───────────────────────────────────────────────┤
│ Recent Security Events                        │
│                                               │
│ phishing-domain.com      BLOCKED              │
│ suspicious-site.net      BLOCKED              │
│ example.com              ALLOWED              │
└───────────────────────────────────────────────┘
```

---

## 🔥 Firewall Integration

Future versions can integrate directly with operating-system firewall frameworks to provide stronger enforcement.

---

## 🧠 Domain Reputation Scoring

Instead of using only:

```text
ALLOW / BLOCK
```

the system could calculate:

```text
Domain Reputation Score: 92/100
Risk Level: HIGH
Action: BLOCK
```

---

## 🔗 Distributed Threat Detection

Multiple endpoint agents could report suspicious activity to a centralized server.

```text
             Central Threat Server
                  /     |     \
                 /      |      \
                ▼       ▼       ▼
            Agent 1  Agent 2  Agent 3
               │        │        │
               ▼        ▼        ▼
             Device   Device   Device
```

This would enable organization-wide threat intelligence sharing.

---

# 📚 Learning Outcomes

This project provides practical exposure to several cybersecurity and networking concepts.

### Networking

* TCP/IP
* DNS
* HTTP
* HTTPS
* TLS
* IP addressing
* Network ports
* Packet structure

### Cybersecurity

* Deep Packet Inspection
* Threat intelligence
* Domain reputation
* Endpoint security
* Network monitoring
* Malicious-domain detection
* Rule-based filtering

### Python

* Packet processing
* Modular programming
* Exception handling
* Thread-safe programming
* Network programming

### Security Engineering

* Detection pipelines
* Security policies
* Blocking mechanisms
* Security event logging
* Threat classification

---

# 🧑‍💻 Project Goals

The project demonstrates how a host-based security system can combine multiple cybersecurity concepts into a single detection and enforcement pipeline:

```text
                NETWORK TRAFFIC
                       │
                       ▼
                PACKET CAPTURE
                       │
                       ▼
              DEEP PACKET INSPECTION
                       │
                       ▼
              PROTOCOL IDENTIFICATION
                       │
                       ▼
              DOMAIN EXTRACTION
                 ┌─────┴─────┐
                 │           │
                HTTP        TLS
                 │           │
                 └─────┬─────┘
                       ▼
               THREAT ANALYSIS
                       │
                       ▼
                 RULE ENGINE
                       │
              ┌────────┴────────┐
              ▼                 ▼
           ALLOW              BLOCK
              │                 │
              ▼                 ▼
          Continue          Log Event
```

---

# 🔐 Ethical and Legal Disclaimer

This project is intended **strictly for educational, research, and authorized cybersecurity testing purposes**.

Network packet inspection can involve sensitive information.

Do not use this system to:

* Monitor networks without authorization
* Intercept other users' traffic
* Inspect private communications without consent
* Circumvent security controls
* Deploy blocking mechanisms on systems you do not own or administer

Always obtain appropriate authorization before performing network monitoring or packet inspection.

---

# 📈 Project Significance

This project demonstrates the transition from traditional static filtering toward a more dynamic network-security approach.

Instead of simply asking:

> **"Which IP address is this?"**

the system attempts to answer:

> **"What application-level destination is this traffic associated with, and should that destination be trusted?"**

That distinction is important when building modern network-security systems.

---

# 👨‍💻 Author

## Syed Aakif Zain

**Cybersecurity Project**

GitHub:
`https://github.com/syedaakifzain`

---

