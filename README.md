---

# Python Intrusion Detection System (IDS)

## Overview

This project implements a **Python-based Intrusion Detection System (IDS)** designed to monitor server activity and detect malicious behavior in real time. The current implementation focuses on identifying **SSH brute force attacks** by analyzing system authentication logs and applying threshold-based detection algorithms. Upon detection, the system automatically enforces defensive actions such as **blocking malicious IP addresses at the operating system level**.

The system is developed as part of the **ST5062CEM – Programming and Algorithm 2** coursework and emphasizes algorithm efficiency, secure software design, multi-threading, persistence, and user-friendly interfaces.

---

## Key Features

* Real-time monitoring of SSH authentication logs
* Detection of brute force attacks using efficient log-parsing algorithms
* Automated mitigation through IP blocking (iptables)
* Threshold-based attack detection
* Persistent storage of attack and block records
* Multi-threaded architecture for continuous monitoring
* Graphical User Interface (GUI) for visualization and management
* Modular and extensible design for future attack detection modules

---

## System Architecture

The system is designed as a **distributed security solution** consisting of the following components:

* **Attacker Environment**
  A virtual machine simulating brute force attacks using tools such as Hydra.

* **Victim Environment**
  A Linux server running an SSH service and the IDS application.

* **IDS Core Components**

  * Log monitoring and parsing engine
  * Detection and decision-making logic
  * Automated response and blocking module
  * Persistence layer (database and files)
  * GUI dashboard

The architecture supports future extensions for detecting additional attack vectors such as HTTP or FTP-based attacks.

---

## Technologies Used

* **Programming Language:** Python 3
* **GUI:** Tkinter
* **Persistence:** SQLite, file-based logging
* **Security:** iptables, secure coding principles
* **Concurrency:** Multi-threading
* **Testing:** unittest
* **Version Control:** Git and GitHub
* **Operating System:** Linux

---

## Algorithms and Design Considerations

* **Log Parsing:**
  Regular expression-based parsing with linear time complexity *(O(n))*.

* **Attack Tracking:**
  Hash-based data structures for constant-time lookup *(O(1))*.

* **Detection Strategy:**
  Threshold-based detection inspired by existing IDS tools such as Fail2Ban.

* **Design Patterns:**
  Modular and observer-style separation between detection logic and user interface.

---

## Project Structure

```
python-intrusion-detection-system/
│
├── src/
│   ├── log_parser.py
│   ├── detector.py
│   ├── blocker.py
│   ├── database.py
│   └── gui.py
│
├── tests/
│   ├── test_log_parser.py
│   └── test_detector.py
│
├── docs/
│   └── architecture.md
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

## How It Works

1. The IDS continuously monitors SSH authentication logs.
2. Failed login attempts are extracted and grouped by source IP.
3. When predefined thresholds are exceeded, the IP is classified as malicious.
4. Defensive actions are triggered automatically (e.g., IP blocking).
5. Events are logged and stored persistently.
6. The GUI provides real-time visibility into system activity.

---

## Testing

* **Unit Testing:**
  Individual components such as log parsing and detection logic are tested using Python’s `unittest` framework.

* **Integration Testing:**
  Simulated brute force attacks are performed to verify detection accuracy and response effectiveness.

---

## Limitations

* Current implementation focuses only on SSH brute force attacks
* Polling-based log monitoring instead of event-driven mechanisms
* No machine-learning-based anomaly detection

---

## Future Enhancements

* Support for additional attack types (HTTP, FTP, DoS)
* Event-driven log monitoring
* Machine learning-based anomaly detection
* Distributed deployment across multiple hosts
* Advanced rule configuration via GUI

---

## Academic Context

This project is developed as part of **ST5062CEM – Programming and Algorithm 2** at Softwarica College of IT & E-Commerce, in collaboration with Coventry University.
It addresses the module learning outcomes related to algorithm efficiency, secure software development, multi-threading, distributed systems, and user interface design.

---

## License

This project is developed for academic purposes only.

---
