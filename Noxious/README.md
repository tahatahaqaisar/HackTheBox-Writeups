# 🔍 HackTheBox — Noxious Sherlock Writeup

![HackTheBox](https://img.shields.io/badge/HackTheBox-Sherlock-9fef00?style=for-the-badge&logo=hackthebox&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Network%20Forensics-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)

---

## 📋 Table of Contents

- [Scenario](#-scenario)
- [Skills & Tools Used](#-skills--tools-used)
- [Investigation Walkthrough](#-investigation-walkthrough)
  - [Task 1 — Malicious IP Address](#task-1--malicious-ip-address)
  - [Task 2 — Hostname of Rogue Machine](#task-2--hostname-of-rogue-machine)
  - [Task 3 — Captured Username](#task-3--captured-username)
  - [Task 4 — First Hash Capture Timestamp](#task-4--first-hash-capture-timestamp)
  - [Task 5 — Victim's Typo](#task-5--victims-typo)
  - [Task 6 — NTLM Server Challenge Value](#task-6--ntlm-server-challenge-value)
  - [Task 7 — NTProofStr Value](#task-7--ntproofstr-value)
  - [Task 8 — Cracking the Hash](#task-8--cracking-the-hash)
  - [Task 9 — Target File Share](#task-9--target-file-share)
- [Key Findings Summary](#-key-findings-summary)
- [Lessons Learned](#-lessons-learned)

---

## 📖 Scenario

> The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards **Forela-WKstn002**, which has the IP address `172.17.79.136`. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on **LLMNR poisoning**.

---

## 🛠 Skills & Tools Used

| Tool / Concept | Purpose |
|---|---|
| **Wireshark** | Network packet analysis |
| **LLMNR (UDP 5355)** | Identifying poisoning attack traffic |
| **DHCP filtering** | Hostname enumeration of rogue device |
| **SMB2 / NTLMSSP** | Locating captured credential hashes |
| **Hashcat** | Cracking the NTLMv2 hash |
| **Active Directory Concepts** | Understanding the attack context |

---

## 🔬 Investigation Walkthrough

### Task 1 — Malicious IP Address

**Question:** *It's suspected by the security team that there was a rogue device in Forela's internal network running the Responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine.*

**Approach:**

LLMNR (Link-Local Multicast Name Resolution) operates on **UDP port 5355**. By filtering for this in Wireshark:

```
udp.port == 5355
```

We observed that `172.17.79.136` (the victim machine) sent out queries for `DCC01` — a typo for `DC01`. The machine at `172.17.79.135` responded to this broadcast, which is the hallmark behaviour of an LLMNR poisoning attack using Responder.

**Answer:** `172.17.79.135`

---

### Task 2 — Hostname of Rogue Machine

**Question:** *What is the hostname of the rogue machine?*

**Approach:**

When a device joins a network, it typically uses DHCP to obtain an IP address — and the DHCP request contains the device hostname. Filtering for the attacker's IP and DHCP traffic:

```
ip.addr == 172.17.79.135 && dhcp
```

Inspecting the DHCP Request packet reveals the hostname field of the rogue machine.

**Answer:** Found in the DHCP Request hostname field of `172.17.79.135`

---

### Task 3 — Captured Username

**Question:** *Now we need to confirm whether the attacker captured the user's hash and it is crackable! What is the username whose hash was captured?*

**Approach:**

Filter for SMB2 traffic to look for NTLMSSP negotiation:

```
smb2
```

The presence of `NTLMSSP_NEGOTIATE` and `NTLMSSP_AUTH` packets confirms that the hash was captured. Narrow down further with:

```
ntlmssp
```

Expand the `NTLMSSP_AUTH` packet — the **username** field is visible in the NTLM Secure Service Provider section.

**Answer:** Found inside the `NTLMSSP_AUTH` packet details

---

### Task 4 — First Hash Capture Timestamp

**Question:** *In NTLM traffic we can see that the victim credentials were relayed multiple times to the attacker's machine. When were the hashes captured the first time?*

**Approach:**

1. In Wireshark, go to **View → Time Display Format → UTC Date and Time of Day** to enable UTC timestamps.
2. Apply the filter:

```
ntlmssp
```

3. Look at the first sequence: `NTLMSSP_NEGOTIATE` → `NTLMSSP_CHALLENGE` → `NTLMSSP_AUTH`. The timestamp on the first `NTLMSSP_NEGOTIATE` packet is the answer.

**Answer:** Timestamp of the first `NTLMSSP_NEGOTIATE` packet in UTC

---

### Task 5 — Victim's Typo

**Question:** *What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?*

**Approach:**

From the LLMNR traffic analysis in Task 1, the victim's machine queried for `DCC01` instead of `DC01`. The attacker's Responder tool answered this multicast broadcast, impersonating the domain controller. This can be confirmed further using:

```
ip.addr == 172.17.79.136 && llmnr
```

The NTLMSSP packets also show the `netname` value confirming the typo.

**Answer:** `DCC01` (should have been `DC01`)

---

### Task 6 — NTLM Server Challenge Value

**Question:** *To get the actual credentials of the victim user we need to stitch together multiple values from the NTLM negotiation packets. What is the NTLM server challenge value?*

**Approach:**

Filter for:

```
ntlmssp
```

Locate the `NTLMSSP_CHALLENGE` packet and expand the following path:

```
SMB2 → Session Setup Response → Security Blob → GSS-API Generic
→ Simple Protected Negotiation → negTokenTarg
→ NTLM Secure Service Provider → NTLM Server Challenge
```

**Answer:** The hex value shown in the `NTLM Server Challenge` field

---

### Task 7 — NTProofStr Value

**Question:** *Now doing something similar, find the NTProofStr value.*

**Approach:**

Still filtered on `ntlmssp`, locate the `NTLMSSP_AUTH` packet and expand:

```
SMB2 → Session Setup Response → Security Blob → GSS-API Generic
→ Simple Protected Negotiation → negTokenTarg
→ NTLM Secure Service Provider → NTLM Response
→ NTLMv2 Response → NTProofStr
```

**Answer:** The hex value shown in the `NTProofStr` field

---

### Task 8 — Cracking the Hash

**Question:** *To test the password complexity, try recovering the password from the information found from packet capture.*

**Approach:**

Assemble the NTLMv2 hash in the following format:

```
Username::Domain:ServerChallenge:NTProofStr:NTLMv2Response
```

> **Note:** For `NTLMv2Response`, take the full NTLMv2 response blob and **remove the first 32 characters (16 bytes)** — these are the NTProofStr itself, which is already in the field above.

Save this to a file called `hashfile.txt`, then run Hashcat:

```bash
hashcat -a 0 -m 5600 hashfile.txt /usr/share/wordlists/rockyou.txt
```

- `-a 0` = dictionary attack
- `-m 5600` = NTLMv2 hash mode

**Answer:** The plaintext password revealed by Hashcat

---

### Task 9 — Target File Share

**Question:** *Just to get more context surrounding the incident, what is the actual file share that the victim was trying to navigate to?*

**Approach:**

Filter for SMB2 traffic:

```
smb2
```

Scroll through the packets and look for **Tree Connect** requests. Default IPC shares like `\\DC01.forela.local\IPC$` are normal — look for a non-default, custom share name. Given the typo the victim made, also check for `\\DCC01\...` style requests.

**Answer:** `\\DC01\DC-Confidential`

---

## 📊 Key Findings Summary

| # | Finding | Value |
|---|---|---|
| 1 | Attacker IP | `172.17.79.135` |
| 2 | Rogue Machine Hostname | Found via DHCP packet |
| 3 | Compromised Username | Found in `NTLMSSP_AUTH` |
| 4 | First Hash Capture Time | UTC timestamp of first NTLMSSP_NEGOTIATE |
| 5 | Victim's Typo | `DCC01` instead of `DC01` |
| 6 | NTLM Server Challenge | Extracted from `NTLMSSP_CHALLENGE` packet |
| 7 | NTProofStr | Extracted from `NTLMSSP_AUTH` packet |
| 8 | Cracked Password | Via Hashcat with rockyou.txt |
| 9 | Target File Share | `\\DC01\DC-Confidential` |

---

## 📚 Lessons Learned

**LLMNR Poisoning** is a well-known Active Directory attack vector that exploits the fallback name resolution protocol when DNS fails. Key takeaways from this lab:

- **LLMNR should be disabled** in enterprise environments (`Group Policy → Computer Configuration → Administrative Templates → Network → DNS Client → Turn off Multicast Name Resolution`).
- **Simple typos** by users can lead to full credential theft in environments where LLMNR is enabled.
- The **Responder tool** is commonly used by attackers to perform this attack — blue teams should monitor for LLMNR responses from unexpected hosts.
- **NTLMv2 hashes** are crackable offline if the password is weak — enforcing strong password policies is critical.
- **Wireshark filters** like `udp.port==5355`, `ntlmssp`, and `smb2` are essential for forensic investigation of this attack type.

---

> **Disclaimer:** This writeup is for educational purposes only. All work was performed in an authorized lab environment provided by Hack The Box.
