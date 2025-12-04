# CSEC Linux (AIDE) Workshop
s
Detecting unauthorized filesystem changes is one of the most effective defenses against rootkits, backdoors, and configuration tampering. **AIDE (Advanced Intrusion Detection Environment)** creates cryptographic baselines of critical system files and alerts administrators when anything changes—making it an essential tool for Linux hardening. This workshop provides hands-on experience configuring AIDE on Ubuntu VMs, from initial setup through detecting simulated intrusions.

## Workshop environment setup with OSBOXES

Before diving into AIDE, you need an isolated Linux environment. **OSBOXES.org** provides pre-configured Ubuntu virtual machines that eliminate installation delays and ensure consistent lab environments across all participants.

**OSBOXES** is a platform maintained by Umair Riaz offering 30+ pre-installed Linux distributions as ready-to-use VM images. For this workshop, **Ubuntu 24.04 LTS** provides long-term support stability ideal for security training. Images come in VDI format (VirtualBox) and VMDK format (VMware), typically **2.2-2.6GB compressed** as .7z archives.

**Default credentials for all OSBOXES images:**

Username: osboxes

Password: osboxes.org

Root Password: osboxes.org 

### Setting up the workshop VM

Download Ubuntu 24.04 from osboxes.org/ubuntu, then extract using 7-Zip (available for all platforms). In VirtualBox, create a new VM selecting "Use an existing virtual hard disk file" and point to the extracted .vdi file. Allocate at least **4GB RAM and 2 CPU cores** for smooth operation.

Configure networking as **Host-Only** for isolated security exercises or **NAT** for internet access during package installation. Guest additions come pre-installed, enabling clipboard sharing and seamless mouse integration. **Take a snapshot immediately** after first boot—this "Clean Install" baseline lets you reset between exercises without re-downloading.

---

## Installing AIDE on Ubuntu/Debian

AIDE installation on Ubuntu/Debian requires just one command, but understanding the package structure helps with later configuration.

```bash
# Update package lists and install AIDE
sudo apt update
sudo apt install aide
```

This installs two packages: **aide** (the main binary) and **aide-common** (wrapper scripts, configuration files, and cron integration). Dependencies including libmhash2 for hash algorithms and libselinux1 for SELinux support install automatically.

### Package versions across distributions

| Distribution | AIDE Version | Notable Features |
|--------------|--------------|------------------|
| Ubuntu 24.04 | 0.18.x | SHA512, POSIX ACL, SELinux, xattrs |
| Ubuntu 22.04 | 0.17.4 | Full feature set with MMAP, PCRE |
| Debian 12 | 0.18.3 | Latest algorithms including Whirlpool |

Verify installation with `aide -v`, which displays compiled options including supported hash algorithms and extended attribute capabilities.

---

## Understanding configuration file locations

Debian/Ubuntu organizes AIDE configuration across multiple locations, differing from upstream defaults. The **primary configuration file** lives at `/etc/aide/aide.conf`, containing monitoring rules and group definitions. Additional snippets in `/etc/aide/aide.conf.d/` allow modular configuration—useful for adding custom rules without editing the main file.

**Critical files to know:**
- `/etc/default/aide` — Controls cron behavior, email recipients, and verbosity
- `/var/lib/aide/aide.db` — The working database used for comparisons
- `/var/lib/aide/aide.db.new` — Newly generated database from init/update operations

**Tip:** Rather than calling `aide` directly, use wrapper scripts: `aideinit` for database creation, `aide.wrapper` for checks, and `update-aide.conf` to rebuild configuration after changes. Direct invocation without proper parameters produces confusing errors.

---

## AIDE commands and database workflow

AIDE operates on a simple principle: create a baseline database, then compare current filesystem state against that baseline. The workflow requires understanding four core commands.

### The essential command cycle

**Initialization** creates the first database snapshot:
```bash
sudo aideinit
# Or directly: sudo aide --init --config /etc/aide/aide.conf
```

This generates `/var/lib/aide/aide.db.new` containing file attributes and cryptographic hashes. Database creation takes **1-7 minutes** depending on system size—approximately 6 minutes for ~395,000 entries on a typical Ubuntu installation.

**Activation** requires manually renaming the database (a security feature preventing automatic overwrites):
```bash
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**Checking** compares current filesystem against the baseline:
```bash
sudo aide.wrapper --check
# Or: sudo aide --check --config /etc/aide/aide.conf
```

**Updating** after legitimate changes creates a new database while simultaneously checking:
```bash
sudo aide --update --config /etc/aide/aide.conf
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Interpreting AIDE output

When no changes exist, AIDE reports simply: "AIDE found NO differences between database and filesystem."

When changes are detected, output includes a summary and detailed change codes:
```
AIDE found differences between database and filesystem!!
Summary:
  Total number of entries:      55856
  Added entries:                1
  Removed entries:              0
  Changed entries:              3

Changed entries:
f <.>....mc. . : /etc/passwd
```

The change code `f <.>....mc. .` decodes as: **f**=regular file, **<**=size decreased, **m**=mtime changed, **c**=ctime changed. A newly added file shows `f++++++++++++++++` (all attributes are "new"), while deleted files show all `-` characters.

### Exit codes for scripting

AIDE returns mathematically meaningful exit codes: **1**=new files, **2**=removed files, **4**=changed files. These combine additively—exit code **7** means all three change types occurred (1+2+4). Zero indicates no changes and no errors.

---

## Configuring aide.conf for effective monitoring

The configuration file uses three line types: configuration directives, selection rules, and macros. Understanding rule syntax is essential for effective monitoring without alert fatigue.

### Variable definitions and macros

```bash
@@define DBDIR /var/lib/aide
database_in=file:@@{DBDIR}/aide.db.gz
database_out=file:@@{DBDIR}/aide.db.new.gz
```

The `@@define` directive creates variables referenced later with `@@{VARNAME}` syntax. Conditional processing (`@@ifdef`, `@@ifndef`, `@@ifhost`) enables environment-specific configurations.

### Selection rule syntax

Rules specify what to monitor and how. Three rule types exist:

**Regular rules** monitor recursively:
```bash
/etc DATAONLY     # Monitor /etc and ALL subdirectories
/bin NORMAL       # Comprehensive check on /bin tree
```

**Negative rules** exclude paths:
```bash
!/var/log/.*      # Exclude all log file contents
!/tmp             # Exclude entire /tmp directory
!/proc            # Exclude proc filesystem
```

**Equals rules** monitor non-recursively:
```bash
=/var/log/ DIR    # Monitor /var/log/ itself, not contents
```

**Critical syntax note:** Always terminate exact file matches with `$` to prevent partial matching. Without it, `!/var/adm/utmp` also excludes `/var/adm/utmp_rootkit`—a dangerous oversight.

### Predefined rule groups

AIDE includes built-in groups combining common attributes:

| Group | Attributes | Purpose |
|-------|------------|---------|
| **R** | p+ftype+i+l+n+u+g+s+m+c+md5+X | Standard comprehensive |
| **L** | p+ftype+i+l+n+u+g+X | Permissions only (no hash) |
| **>** | p+ftype+l+u+g+i+n+S+X | Growing files (logs) |
| **H** | All compiled hashsums | Maximum hash coverage |

Custom groups combine attributes with `+` and remove with `-`:
```bash
BINARIES = p+i+n+u+g+s+m+c+sha512+selinux
RELAXED = NORMAL-m-c    # Remove mtime/ctime checks
```

### Recommended config

```bash
# Custom rule definitions
NORMAL = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha512
DATAONLY = p+n+u+g+s+acl+selinux+xattrs+sha256
LOG = p+ftype+i+l+n+u+g+S+acl+selinux+xattrs

# Monitor critical system directories
/bin NORMAL
/sbin NORMAL
/usr/bin NORMAL
/usr/sbin NORMAL
/boot NORMAL
/etc DATAONLY

# Critical files with strict monitoring
/etc/passwd$ NORMAL
/etc/shadow$ NORMAL
/etc/sudoers$ NORMAL

# Exclusions for dynamic content
!/dev
!/proc
!/sys
!/run
!/tmp
!/var/log/.*
!/var/cache/.*
```

---

## Hands-on workshop exercises

These exercises demonstrate AIDE's core functionality through practical scenarios you can reproduce!

### Exercise 1: Basic change detection

After installing AIDE and creating the initial database, test detection capability:

```bash
# Create test file
sudo touch /root/suspicious_file.txt

# Run integrity check
sudo aide.wrapper --check
```

AIDE reports the new file as an "Added entry." This demonstrates how AIDE catches unauthorized file creation—a common indicator of malware installation.

### Exercise 2: Simulating binary replacement (rootkit detection)

Rootkits often replace system binaries with trojaned versions. Simulate this safely:

```bash
# Backup and modify a binary (simulating trojan)
sudo cp /usr/bin/sudo /usr/bin/sudo.backup
echo "# test modification" | sudo tee -a /usr/bin/sudo

# Run AIDE check
sudo aide.wrapper --check
# Output: Changed entries detected for /usr/bin/sudo

# Restore original
sudo mv /usr/bin/sudo.backup /usr/bin/sudo
```

You will observe how hash changes immediately reveal binary tampering—even when file size and timestamps could be manipulated.

### Exercise 3: Configuration file monitoring

Monitor `/etc/hosts` for unauthorized modifications:

```bash
# After baseline creation, simulate unauthorized change
echo "192.168.1.100 malicious.example.com" | sudo tee -a /etc/hosts

# Detect the change
sudo aide.wrapper --check
```

The output shows exactly which attributes changed (size, mtime, ctime, SHA256), showing how AIDE provides forensic-quality evidence of tampering =)

### Exercise 4: Update workflow after legitimate changes

After system updates, the database needs refreshing:

```bash
# Perform system update
sudo apt update && sudo apt upgrade -y

# Check shows many "changed" files (expected)
sudo aide.wrapper --check

# After verifying changes are legitimate, update baseline
sudo aide --update --config /etc/aide/aide.conf
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

## Troubleshooting common issues

### "Database not found" errors

The most common beginner error occurs when skipping the database rename step:

```bash
# Error indicates missing working database
# Solution: Copy new database to working location
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Permission denied errors

AIDE must read all monitored files, requiring root privileges. Always run with `sudo`. Additionally, verify database permissions: `chmod 600 /var/lib/aide/aide.db.gz` prevents unauthorized reading of file hashes.

### False positives from normal system operation

Several directories generate constant alerts due to legitimate activity:

- **/var/log** — Log rotation changes files continuously
- **/var/cache** — Package manager caches update frequently  
- **/tmp, /var/tmp** — Temporary files appear and disappear
- **/proc, /sys, /dev** — Virtual filesystems change constantly

**Solution:** Exclude these directories or use the growing-size rule (`>`) for logs. Fine-tuning configuration "may take a few weeks" according to official documentation—start conservative and add exclusions as patterns emerge.

### Configuration syntax deprecation warnings

AIDE 0.16+ changed some directives:
```bash
# Old (deprecated):
database=file:/var/lib/aide/aide.db.gz

# New (preferred):
database_in=file:@@{DBDIR}/aide.db.gz
database_out=file:@@{DBDIR}/aide.db.new.gz
```

---

## Security best practices for production deployment

**Store the baseline database securely.** If attackers can modify the database, they can hide their changes. Copy the database to read-only media or a separate secure server immediately after creation.

**Initialize before network connection.** Create the first database immediately after OS installation, before connecting to any network—this ensures the baseline captures a known-clean state.

**Schedule regular automated checks.** Configure daily cron jobs in `/etc/default/aide` by setting `CRON_DAILY_RUN=yes` and `MAILTO=admin@example.com` for email notifications.

**Protect configuration files.** The aide.conf file reveals what's monitored and excluded. Sophisticated attackers read this to understand detection blind spots. Consider storing configuration on separate infrastructure.
Got it! Here are just the Disclaimer and Additional Resources sections in your format:

---

## Disclaimer

**Educational Purpose**: This workshop teaches file integrity monitoring techniques for authorized environments only. Use these skills exclusively on systems you own or have explicit written permission to test.

**Legal Responsibility**: You are solely responsible for your actions. The instructor and organizers accept no responsibility for:
- System instability, crashes, or data loss from running this code
- Unauthorized access to systems
- Legal consequences of misuse
- Any malicious use of techniques learned

**Ethical Guidelines**:
- Never deploy monitoring tools on systems without authorization
- Report vulnerabilities responsibly
- Use knowledge to improve security, not exploit it

By participating, you acknowledge understanding these terms and agree to use this knowledge ethically and legally.

---

## Additional Resources

### Basic
- [AIDE Official Manual](https://aide.github.io/doc/) - Comprehensive configuration reference
- [Ubuntu AIDE Documentation](https://help.ubuntu.com/community/FileIntegrityAIDE) - Community setup guide
- [Wazuh FIM Documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html) - Enterprise-grade alternative with real-time monitoring and SIEM integration
- [Lynis Security Auditing](https://cisofy.com/lynis/) - Complementary hardening and compliance tool
- [rkhunter Official Site](https://www.rkhunter.dev/) - Rootkit detection to pair with AIDE
- [chkrootkit](https://www.chkrootkit.org/) - Lightweight rootkit scanner
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Industry-standard hardening baselines (free PDF registration required)

### Books
- "Linux Basics for Hackers" by OccupyTheWeb (No Starch Press, 2nd Ed 2025) - Security-focused Linux fundamentals
- "How Linux Works" by Brian Ward (No Starch Press, 3rd Ed 2021) - Deep system internals
- "Mastering Linux Security and Hardening" by Donald Tevault (Packt, 3rd Ed 2023) - Comprehensive hardening guide
- "Linux Kernel Programming" by Kaiwan Billimoria (Packt, 2nd Ed 2024) - Kernel internals for understanding rootkits

### Advanced
- [Awesome Security Hardening](https://github.com/decalage2/awesome-security-hardening) - Curated collection of hardening guides and tools
- [The Practical Linux Hardening Guide](https://github.com/trimstray/the-practical-linux-hardening-guide) - Step-by-step hardening with CIS/STIG compliance
- [DISA STIGs](https://public.cyber.mil/stigs/downloads/) - DoD security configuration standards (free)
- [Wazuh Rootkit Detection](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html) - Behavioral rootkit detection module
- [Linux Foundation LFD441](https://training.linuxfoundation.org/training/security-and-linux-kernel-lfd441/) - Security and the Linux Kernel (paid)
---

Author: Sasha Zyuzin

Good luck! 🔐