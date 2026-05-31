# Hellfire

Hellfire is a lightweight, zero-dependency Automated Intrusion Prevention System (IPS) daemon designed for Linux environments. Inspired by the core architecture of Fail2ban, Hellfire monitors system log streams in real-time, detects malicious patterns using dynamic regular expressions, and automatically mitigates threats at the network layer using the system firewall.

## Key Features

* **Zero Dependencies:** Built entirely using Python standard libraries. No external package installations or pip managers required.
* **Real-Time Stream Processing:** Utilizes efficient file pointer seeking to process log lines instantaneously as they are appended to the system daily.
* **State Persistence:** Integrated SQLite database engine to track active restrictions, violation timestamps, and triggered rule profiles.
* **Agnostic Rule Matrix:** Fully configurable via `config.json` to monitor any targeted log stream including SSH, Web WAF logs, or FTP daemons.
* **Clean CLI Architecture:** Built-in command-line interface for managing daemon execution, inspecting active threat registers, and lifting restrictions manually.

## System Architecture

1. **Log Parser:** Continuously monitors the target stream from the end of the file to minimize CPU cycles and resource overhead.
2. **Filter Engine:** Evaluates incoming lines against pre-defined regular expressions specified in the configuration matrix.
3. **Action Executer:** Once the infraction threshold is breached within the configured time window, it directly interacts with the Linux firewall via secure system subprocesses.
4. **State Manager:** Commits the malicious entity's IP, target rule, and chronological timestamp to a local SQLite database for historical logging.

## Deployment & Installation

### Prerequisites

* Linux Operating System (Ubuntu/Debian recommended)
* Uncomplicated Firewall (UFW) enabled and active
* Python 3.x environment

### Step-by-Step Installation

Clone the official repository from GitHub and navigate into the project root directory:

```bash
git clone [https://github.com/yourusername/hellfire.git](https://github.com/yourusername/hellfire.git)
cd hellfire

```

Grant execution privileges to the core engine script so it can run as an independent system binary:

```bash
chmod +x hellfire.py

```

Verify the installation and check the available argument structures by running the help command:

```bash
./hellfire.py --help

```

## Usage and Command Execution

Hellfire operates under different specific modes depending on the argument passed to the binary interface.

### 1. Launching the Live Monitor (Daemon Mode)

To initiate the real-time stream tracking engine and start protecting the system automatically, execute the watch parameter with administrative privileges:

```bash
sudo ./hellfire.py --watch

```

### 2. Checking Active Restriction Status

To retrieve the list of all currently blacklisted IP addresses, their infraction reasons, and ban timestamps from the internal SQLite storage:

```bash
./hellfire.py --status

```

### 3. Lifting a Firewall Restriction (Unban)

To manually remove a specific IP address from the Linux firewall rules and clear its records from the database state tracking system:

```bash
sudo ./hellfire.py --unban <TARGET_IP>

```

## Configuration Matrix Configuration

The tracking behavior of the automated daemon is entirely driven by modifying the `config.json` file:

```json
{
    "target_log": "/var/log/auth.log",
    "firewall_ban_cmd": "sudo ufw insert 1 deny from {ip}",
    "firewall_unban_cmd": "sudo ufw delete deny from {ip}",
    "rules": [
        {
            "name": "SSH_Bruteforce",
            "regex": "Failed password for .* from ({ip}) port",
            "max_attempts": 4,
            "time_window": 120
        }
    ]
}

```

## Disclaimer

This security tool manipulates live system firewall rules and network communication tables. Ensure proper regular expression testing before deploying the daemon to avoid accidental self-lockouts. The developer assumes no responsibility for misconfigurations, accidental system isolation, or service disruption.

```

```