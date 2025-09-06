# Snort Remcos RAT Detection

## Overview

This project demonstrates how to use **Snort** (an open-source Intrusion Detection System) to detect malicious activity related to **Remcos RAT** (Remote Access Trojan).  
Using a `.pcapng` file containing captured network traffic, this project walks through:
- Investigation of malicious behavior
- Extraction of **Indicators of Compromise (IOCs)**
- Creation of custom Snort rules
- Running Snort in detection mode
- Generating actionable alerts

---

## Hash of the PCAP Used

| Hash Type | Hash Value |
|-----------|------------|
| MD5       | 196cfb762ace84950bc81d163c6a1d09 |
| SHA-1     | 91a7118fec1013150ce83d74f2f7c41eaff74da7 |
| SHA-256   | 8a2f78583dd52fdb8c7dda66efdbee2e6911c9ffd1e9543ac514932d6d488bf6 |

![PCAP Hash](https://github.com/user-attachments/assets/2a8e5208-b702-46bc-b36d-6288782c0025)

---

## What This Project Includes

1. Investigation of a provided `.pcapng` file using Wireshark  
2. Extraction of IOCs (malicious domains, suspicious file transfers, etc.)  
3. Creation of custom Snort rules based on the IOCs  
4. Running Snort in detection mode on an Ubuntu server  
5. Sample Snort alerts generated during the analysis  

---

## Prerequisites

- Ubuntu Server or Desktop (tested on Ubuntu 20.04)  
- Snort installed  
- Wireshark installed for PCAP analysis   

---


## Step 1 – Investigate the PCAP File

### IOCs Found

1. **Geoplugin.net Query**  
   The malware queries `geoplugin.net` to obtain the victim’s public IP location.  

   ![GeoPlugin IOC](https://github.com/user-attachments/assets/a7b0c283-9e3a-4e8c-879e-a30002367606)

2. **Exfiltrated Email Accounts**  
   Suspicious files contain email account information being exfiltrated.  

   ![Email Exfiltration](https://github.com/user-attachments/assets/dd7d6638-d171-45c7-b825-f05185fe3f0c)

3. **Executable File Header Detected**  
   The malware transfers a PE file starting with `MZ … PE …` sections like `.text`, `.data`, `.rdata`, `.rsrc`.  

   ![Executable Header](https://github.com/user-attachments/assets/ba19ad25-c607-485f-9efe-97efd7249555)

---

## Step 2 – Create Snort Rules
This project includes a custom Snort rules file (`local.rules`) used to detect Remcos RAT for the attached pcap file based on identified IOCs.

### Example Rules in `local.rules`:

```snort
alert tcp any any -> any any (msg:"C2 Traffic to duckdns.org"; content:"duckdns.org"; nocase; sid:100001; rev:1;)
alert tcp any any -> any any (msg:"Suspicious PE file transfer"; content:"MZ"; sid:2000001; rev:2;)
alert tcp any any -> any any (msg:"Credential Theft - Thunderbird Email Dump"; content:"Thunderbird"; nocase; sid:500001; rev:1;)
```

## Step 3 – Run Snort in Detection Mode

1. **Start Snort to monitor the network interface:**

   ```bash
   sudo snort -A console -q -K none -c /etc/snort/snort.conf -i ens33
   ```
2. **Replay the PCAP file in a separate terminal:**
   
   ```bash
   sudo tcpreplay --intf1=ens33 sample.pcapng
   ```

## Step 4 – Alerts and Analysis

<img width="1656" height="345" alt="Screenshot 2025-09-04 143745" src="https://github.com/user-attachments/assets/c7364b6c-0d04-4ac6-b7ff-a3e7f9782cbe" />

## Conclusion

This project provides a systematic and practical demonstration of how to detect Remcos RAT activity using Snort.

### Key Takeaways:
- How to analyze PCAP files to identify IOCs  
- How to write meaningful Snort rules for detection  
- How to replay PCAP traffic to test detection  
- How to generate actionable alerts for security operations  

---

## Future Improvements

- Automate IOC extraction and rule creation  
- Integrate with alert management systems (e.g., ELK Stack)  
- Test against real-time traffic and advanced attacks  

