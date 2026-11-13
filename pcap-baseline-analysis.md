# Wireshark Packet Analysis: Before & After Traffic Baselines

## Overview
This document outlines packet analysis performed in **Wireshark** to establish normal network baselines versus anomalous traffic signatures captured during intrusion simulations.

---

## 1. Normal Traffic Baseline (Pre-Attack)
* **Capture Duration:** 10 minutes on internal interface `eth0`.
* **Observed Protocols:** HTTPS (TLS 1.3), DNS (UDP 53), NTP (UDP 123), and standard internal DHCP handshakes.
* **Baseline Metrics:**
  * Average Packet Size: 580 bytes.
  * TCP Handshake Ratio: Consistent 3-way handshakes (`SYN` -> `SYN-ACK` -> `ACK`) followed by established encrypted data streams.
  * Anomalous Flags: Zero fragmented packets, zero out-of-order retransmissions exceeding normal jitter thresholds.
* **Wireshark Display Filter Used:** `tls.handshake.type == 1 or dns`

---

## 2. Attack Simulation Capture (Post-Attack)
* **Simulated Event:** SQL Injection probe coupled with an outbound port scan and SSH brute-force attempt.
* **Captured Anomalies in Wireshark:**
  * **HTTP URI Anomalies:** Filter `http.uri contains "UNION"` revealed unencoded SQL syntax traversing port 80/443 to the web server application layer.
  * **TCP SYN Flooding / Port Scanning:** Filter `tcp.flags.syn == 1 and tcp.flags.ack == 0` exposed a single external IP address generating rapid connection requests across sequential ports (21, 22, 80, 443, 3306) within a 2-second window.
  * **Payload Inspection:** Extracting TCP stream objects (`Follow > TCP Stream`) on suspicious sessions highlighted plain-text credential probing attempts.

---

## 3. Comparative Summary Table
| Traffic Metric | Normal Baseline | Attack Simulation |
| :--- | :--- | :--- |
| **Top Protocol** | TLS 1.3 (Encrypted Web) | TCP (Unstructured Scans) & HTTP (Malformed URIs) |
| **SYN/ACK Ratio** | Balanced (~1:1) | High SYN ratio with incomplete handshakes |
| **Alert Frequency** | 0 Snort Alerts | Multiple High-Severity Alerts (SIDs 1000001 - 1000003) |
