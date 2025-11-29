# Enhancing Wazuh’s Threat Detection Capabilities

This project focuses on **evaluating and extending the detection capabilities of Wazuh** by integrating Sysmon, simulating attacks, and developing custom detection rules mapped to MITRE ATT&CK.

The work includes three main components:

---

## Technical Documentation  
Located in the `documentation/` directory.

This document provides a **full technical walkthrough** of:

- Virtual testbed setup (Windows 8 victim, Kali attacker, Wazuh OVA)  
- Sysmon deployment & configuration  
- Wazuh agent configuration  
- LLMNR poisoning, SMB brute-force, and phishing-based reverse shell attacks  
- Custom Wazuh rule development  
- Correlation logic (if_sid, if_matched_sid, timeframe, frequency)  
- Trusted host lists and detection tuning  
- Screenshots of attacker activity and Wazuh alerts  

This is the **hands-on implementation** part of the project.

---

## 📄 Academic Report  
Located in the `report/` directory.

The academic report presents a **research-style evaluation** of Wazuh’s detection capabilities based on real attack simulations. It includes:

- **Abstract** — Summary of the research goal and findings.  
- **Introduction** — Why Wazuh matters and what the study evaluates.  
- **Related Work** — Prior studies on Wazuh detection effectiveness.  
- **Methodology** — Wazuh architecture, rule system, and virtual testbed setup.  
- **Simulated Attacks** — LLMNR poisoning, SMB brute-force, PsExec lateral movement, phishing reverse shell, and post-exploitation.  
- **Results & Analysis** — What Wazuh detected, partially detected, or completely missed.  
- **Contributions** — Custom Sysmon-based correlation rules for LLMNR, reverse shells, and unauthorized RDP.  
- **Conclusion** — Summary of strengths, limitations, and improvement directions.

This report provides the **analytical and research-focused** component of the project, complementing the practical technical documentation.


---



