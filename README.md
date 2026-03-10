# DPI-Based-Real-Time-Malicious-Website-Blocking-System
Deep Packet Inspection (DPI) based cybersecurity system that analyzes network traffic in real time to detect and block malicious websites. It inspects packet payloads, tracks connections, and applies security rules to prevent access to harmful domains and suspicious network activity.

## Overview

This project implements a **Host-Based Deep Packet Inspection (DPI) Security Platform** capable of monitoring network traffic in real time and blocking connections to malicious websites using a centralized threat intelligence database.

The system analyzes packets at the application level, extracts domain information from encrypted and unencrypted traffic, and applies rule-based filtering to prevent access to harmful domains such as phishing or malware hosting sites.

The goal of this project is to demonstrate how modern cybersecurity systems can combine **packet inspection, threat intelligence, and endpoint protection** to enhance network security.

---

# Key Features

### Deep Packet Inspection

Analyzes network packets beyond basic headers to inspect application-layer data.

### Malicious Domain Detection

Extracts domains from TLS SNI and HTTP headers to detect potentially dangerous websites.

### Real-Time Traffic Monitoring

Captures and analyzes packets in real time using packet capture libraries.

### Rule-Based Filtering

Applies configurable rules to determine whether traffic should be allowed or blocked.

### Centralized Threat Intelligence

A backend server maintains a database of malicious domains and distributes updates to endpoint agents.

### Endpoint Security Agent

Runs locally on user machines to inspect traffic and enforce security policies.

---

# System Architecture

The platform consists of four major components:

1. **Endpoint Security Agent**
2. **Deep Packet Inspection Engine**
3. **Backend Threat Intelligence Server**
4. **Admin Dashboard**

```
User Device
     │
Packet Capture
     │
Deep Packet Inspection Engine
     │
Domain Extraction (SNI / HTTP)
     │
Rule Engine
     │
Allow / Block Decision
```

---

# Technologies Used

## Backend

* Python
* FastAPI / Flask
* PostgreSQL / SQLite

## Packet Inspection

* Scapy
* PyShark
* libpcap

## Frontend Dashboard

* React
* Tailwind CSS

## Networking Concepts

* Deep Packet Inspection
* TLS SNI Extraction
* Packet Capture
* Network Traffic Analysis

---

# Project Structure

```
agent/
    dpi_engine.py
    packet_parser.py
    connection_tracker.py
    rule_manager.py
    sni_extractor.py

backend/
    api_server.py
    threat_database.py

dashboard/
    frontend

docs/
    architecture.md
```

---

# How It Works

1. The endpoint agent captures network packets from the user system.
2. The DPI engine analyzes packets and extracts domain information.
3. Extracted domains are compared against the threat intelligence database.
4. If a domain is flagged as malicious, the connection is blocked.
5. The event is logged and optionally reported to the backend server.

---

# Example Detection Flow

```
User opens website

Browser → DNS Request

Packet Intercepted

Extract Domain → phishing-site.com

Check Threat Database

Match Found → Connection Blocked
```

---

# Use Cases

* Enterprise network monitoring
* Protection against phishing websites
* Malware command-and-control detection
* Educational cybersecurity labs
* Network traffic analysis research

---

# Future Improvements

* AI-based anomaly detection
* Real-time network visualization dashboard
* Automated threat intelligence feeds
* Integration with firewall rules
* Distributed threat detection

---

# Learning Outcomes

This project demonstrates practical concepts in:

* Network security
* Packet inspection
* Intrusion detection techniques
* Cyber threat intelligence
* Endpoint security architecture

---

# Disclaimer

This project is intended for **educational and research purposes only**. It should not be used to monitor networks without proper authorization.

---

# Author

Syed Aakif Zain
Cybersecurity Project
