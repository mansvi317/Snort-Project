****Snort Remcos RAT Detection****

This project demonstrates how to use Snort (an open-source Intrusion Detection System) to detect malicious activity related to Remcos RAT (Remote Access Trojan).
Using a PCAP file containing captured network traffic, this project shows how to investigate malicious behavior, extract Indicators of Compromise (IOCs), create custom Snort rules, and analyze network activity to generate alerts.


_Hash of the pcap used_
1. MD5 196cfb762ace84950bc81d163c6a1d09 
2. SHA-1 91a7118fec1013150ce83d74f2f7c41eaff74da7 
3. SHA-256 8a2f78583dd52fdb8c7dda66efdbee2e6911c9ffd1e9543ac514932d6d488bf6
<img width="1913" height="883" alt="Screenshot 2025-09-04 122225" src="https://github.com/user-attachments/assets/2a8e5208-b702-46bc-b36d-6288782c0025" />



_What This Project Includes :-_
1. Investigation of a provided .pcapng file using Wireshark
2. Extraction of IOCs (malicious domains, suspicious file transfers, etc.)
3. Custom Snort rules written based on the IOCs
4. Demonstration of Snort running in detection mode on an Ubuntu server
5. Sample Snort alerts generated during the analysis



_Prerequisites :-_
1. Ubuntu Server or Desktop (tested on Ubuntu 20.04)
2. Snort installed (Install Snort on Ubuntu)
3. Wireshark installed for PCAP analysis




_Investigate the PCAP File_
   IOC's found are -
   1. Data from geoplugin.net shows the malware is also checking the victim’s public IP location.
<img width="1919" height="1015" alt="Screenshot 2025-09-04 122857" src="https://github.com/user-attachments/assets/a7b0c283-9e3a-4e8c-879e-a30002367606" />


  2. Exfiltrated Email Accounts
<img width="1919" height="1013" alt="Screenshot 2025-09-04 123404" src="https://github.com/user-attachments/assets/dd7d6638-d171-45c7-b825-f05185fe3f0c" />
 
  
  3. Executable Header as it starts with MZ … PE … sections like .text, .data, .rdata, .rsrc.
<img width="1919" height="1013" alt="Screenshot 2025-09-06 161935" src="https://github.com/user-attachments/assets/ba19ad25-c607-485f-9efe-97efd7249555" />





_Create Snort Rules_

Create a custom rule file (e.g., /etc/snort/rules/local.rules)
Example Rules:

alert tcp any any -> any any (msg:"C2 Traffic to duckdns.org"; content:"duckdns.org"; nocase; sid:100001; rev:1;)
alert tcp any any -> any any (msg:"Suspicious PE file transfer"; content:"MZ"; sid:2000001; rev:2;)
alert tcp any any -> any any (msg:"Credential Theft - Thunderbird Email Dump"; content:"Thunderbird"; nocase; sid:500001; rev:1;)


<img width="1571" height="743" alt="Screenshot 2025-09-04 155600" src="https://github.com/user-attachments/assets/f0a15ee1-be26-4a41-8878-3ea1d74ffce6" />


_Run Snort in Detection Mode_
Start Snort to monitor the network interface
sudo snort -A console -q -K none -c /etc/snort/snort.conf -i ens33
In another terminal, replay the PCAP file to generate traffic: sudo tcpreplay --intf1=ens33 sample.pcapng

<img width="1656" height="345" alt="Screenshot 2025-09-04 143745" src="https://github.com/user-attachments/assets/aa2bbc7c-a620-4134-98d8-a48554d2898d" />











_Conclusion_

This project provides a simple yet effective demonstration of detecting Remcos RAT activity using Snort.
It helps in understanding how to:
Analyze PCAP files for IOCs
Write effective Snort rules
Run Snort in a practical detection environment
Generate actionable alerts
