## 🕵️‍♂️ The Great Admin Heist: Shadows in the System
A simulated cyber threat hunting report involving a fictional breach at ACME Corp by an APT group known as The Phantom Hackers.
Executive Summary
This report details the findings of a simulated cyber threat hunting scenario involving a fictional breach at ACME Corp by an APT group known as The Phantom Hackers. The attackers targeted the privileged IT admin account of Bubba Rockerfeatherman III, deploying a fake antivirus program named BitSentinelCore.exe as their initial foothold. The investigation involved analyzing telemetry from Microsoft Defender for Endpoint (MDE) and using KQL to uncover suspicious activity. Ten key flags representing stages of the attack were identified and mapped to MITRE ATT&CK. Recommendations for remediation steps are provided.
## 🎯 Tasks
As a cyber threat hunter, mission is to:
1.	Analyse telemetry from Microsoft Defender for Endpoint (MDE).
2.	Use KQL (Kusto Query Language) to investigate suspicious activities.
3.	Identify and document 10 key flags, each representing a stage in the attack chain.
4.	Correlate events to build a timeline of the intrusion.
5.	Uncover attacker tactics, techniques, and procedures (TTPs).
6.	Report findings with evidence, including file names, registry paths, process chains, and timestamps.
7.	Map findings to MITRE ATT&CK to understand the adversary’s behavior.
8.	Recommend defensive actions to contain and remediate the threat.
To investigate the incident, I used Advanced Hunting in Microsoft Defender, which allowed me to query and analyze endpoint telemetry data to uncover the attacker’s activity.
Detailed Findings
 ## Flag 1: Fake Antivirus Identified

 ![image](https://github.com/user-attachments/assets/0d9d8e7b-841b-4569-b990-244b4b89af61)

________________________________________
  ## 🧠 Interpretation
These results show that:
-	A PowerShell script named portscan.ps1 was downloaded from a GitHub repository.
-	It was then executed using cmd.exe with execution policy bypassed — a common evasion technique.
 - The script likely performs network scanning, based on its name.
- However, these are not antivirus binaries. They are part of the attacker’s post-exploitation activity, possibly for reconnaissance.
- To initiate the investigation, I focused on identifying the suspicious binary that masqueraded as a legitimate antivirus. Using Advanced Hunting in Microsoft Defender, I analysed process creation events to discover executable named BitSentinelCore.exe. This file, although appearing to be a security tool, was the root artifact responsible for launching the malicious activity chain.

![image](https://github.com/user-attachments/assets/f71297b0-a348-4e7b-b6b2-0e335a92435a)
![image](https://github.com/user-attachments/assets/10b42455-816d-42d3-9a68-38262ce2db7a)

   
  ## Key Events:
  - 11:57:36 AM – powershell.exe (parent process) initiated the chain.
  - 12:00:36 PM – BitSentinelCore.exe was created in C:\ProgramData.

## Flag 2: Malicious File Written  Somewhere

To confirm that the fake antivirus binary was written to disk, I queried file creation events on the device anthony-001. The telemetry revealed that BitSentinelCore.exe was created in the C:\ProgramData directory — a common location used by malware to evade detection.
The task was to determine whether the fake antivirus binary (BitSentinelCore.exe) was written to disk and identify the process responsible for dropping it. This helps validate the delivery mechanism and supports detection of similar behaviors in future incidents.
 
  ## 🧠 Interpretation
-	At 12:00:36 PM on May 7, 2025, a file named BitSentinelCore.exe was created or modified on the device anthony-001.
-	The file was placed in the C:\ProgramData\ directory, which is often used by applications to store data accessible to all users.
-	The process that initiated this action was csc.exe, which is the C# compiler from the .NET Framework.
-	The command line used suggests that a script or program compiled a C# file using a command file located in a temporary user directory:
@"C:\Users\4nth0ny!\AppData\Local\Temp\c5gy0jzg\c5gy0jzg.cmdline"
## Potential Security Implications
- csc.exe being used from a temp directory to compile and drop an executable in ProgramData is suspicious.
- This behaviour is often associated with fileless malware, living-off-the-land binaries (LOLBins), or malicious scripts compiling payloads on the fly.
  - The file name BitSentinelCore.exe could be masquerading as a legitimate security tool, or it could be part of a malware campaign.
## 	Key Events
- 11:57:36 AM – powershell.exe initiated the execution chain.
-	12:00:36 PM – csc.exe (Microsoft .NET compiler) was executed.
-	12:00:36 PM – BitSentinelCore.exe was created in C:\ProgramData.
This timeline clearly illustrates the dropper mechanism and supports attribution of the file creation to a legitimate but abused system binary.

## Flag 3: Execution of Malware

 Next task is to determine if the malicious file was executed manually. need to execute the logs to confirm that .exe file was initiated by user interaction.
 
●	The file BitSentinelCore.exe was executed multiple times on May 7, 2025, starting at 12:02:14 PM.
●	Evidence:
●	ProcessCommandLine: BitSentinelCore.exe
●	InitiatingProcess: explorer.exe (indicates manual execution via GUI)
●	AccountName: 4nth0ny!
●	Command Used to Start the Program:
BitSentinelCore.exe
●	Conclusion: The process was initiated by explorer.exe, strongly suggesting that the user Anthony manually executed the file by double-clicking it in the Windows Explorer interface.

## Flag 4: Keylogger Artifact

●	Identify whether any artifact was dropped that indicates keylogger behavior.
●	Finding: A suspicious file named   was written to disk, suggesting keylogging functionality.
 

I was thoroughly analyzing telemetry data to uncover potential keylogger artifacts. Although .log, .txt, and .dat files are common indicators of keylogging activity, the actual keylogger file did not appear in those results. After taking a long break, I shifted my focus and began investigating alternative file types—such as .zip, .rar, or .lnk—in case the keylogger was disguised in a different format.

 

●	Evidence:
●	File Name: systemreport.lnk
●	File Type: Windows shortcut (.lnk)
●	Initiating Process: Likely tied to BitSentinelCore.exe
●	Interpretation:
The .lnk file systemreport.lnk is a disguised keylogger component. Attackers often use .lnk files to execute hidden payloads or scripts. In this case, it likely points to or launches the actual keylogging executable, possibly NewsLogger.exe, under the guise of a system report.
●	Conclusion:
This artifact confirms the presence of surveillance behavior and supports the hypothesis of credential harvesting or user activity monitoring.
Key Events
1.	11:57:36 AM – powershell.exe initiated the execution chain.
2.	12:00:36 PM – BitSentinelCore.exe created in C:\ProgramData by csc.exe.
3.	12:02:14 PM – BitSentinelCore.exe executed manually by explorer.exe (1st time).
4.	12:03:16 PM – Executed again manually (2nd time).
5.	12:03:20 PM – Executed again manually (3rd time).
6.	12:06:51 PM – Keylogger artifact systemreport.lnk created in AppData\Roaming\Microsoft\Windows\Recent.

## Flag 5: Registry Persistence

Determine if the malware established persistence via the Windows Registry. next task to find if tThe malware created a registry key to ensure it runs automatically upon user login.
 
●	The malware created a registry key to ensure it runs automatically upon user login.
●	Evidence:
○	Registry Path:
HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
●	Interpretation:
 The malware used a common persistence technique by modifying the Run key in the current user’s registry hive. This ensures that BitSentinelCore.exe is executed every time the user logs in, maintaining access across reboots.
●	Conclusion:
 This registry modification confirms the attacker’s intent to maintain long-term access to the compromised system using stealthy persistence.
  	Key Events
1.	11:57:36 AM – powershell.exe initiated the execution chain.
2.	12:0 0:36 PM – BitSentinelCore.exe created in C:\ProgramData by csc.exe.
3.	12:02:14 PM – BitSentinelCore.exe executed manually by explorer.exe (1st time).
4.	12:02:14 PM – Registry persistence entry added:
 HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\BitSecSvc → "C:\ProgramData\BitSentinelCore.exe"
5.	12:03:16 PM – Executed again manually (2nd time).
6.	12:03:20 PM – Executed again manually (3rd time).
7.	12:06:51 PM – Keylogger artifact systemreport.lnk created in AppData\Roaming\Microsoft\Windows\Recent.

## Flag 6: Scheduled Task for Persistence
Identify evidence that the attacker intended to maintain long-term access to the system. 

●	Evidence:
○	Parent Process: explorer.exe (user-initiated)
○	Child Process: BitSentinelCore.exe (malicious dropper)
○	Grandchild Process: cmd.exe executing schtasks to create the scheduled task UpdateHealthTelemetry
○	Timestamp: May 7, 2025, 12:02:14 PM
●	Interpretation:
 This process chain illustrates how the attacker leveraged legitimate system processes to establish persistence. The use of cmd.exe and schtasks via a malicious binary launched from explorer.exe shows a clear execution flow designed to evade detection.
●	Conclusion:
 Mapping the process lineage reveals the attacker’s methodical approach to persistence, highlighting the importance of tracing parent-child relationships in endpoint telemetry.

## Flag 7: Process Spawn Chain

Understand the full chain of process relationships that led to the creation of the scheduled task. task is to find if tThe attacker used a multi-step process chain to execute the scheduled task creation stealthily.
●	Kill Chain:
BitSentinelCore.exe -> cmd.exe -> schtasks.exe  
●	Evidence:
○	Parent Process: explorer.exe (user-initiated)
○	Child Process: BitSentinelCore.exe (malicious dropper)
○	Grandchild Process: cmd.exe executing schtasks to create the scheduled task UpdateHealthTelemetry
○	Timestamp: May 7, 2025, 12:02:14 PM
●	Interpretation:
 This process chain illustrates how the attacker leveraged legitimate system processes to establish persistence. The use of cmd.exe and schtasks via a malicious binary launched from explorer.exe shows a clear execution flow designed to evade detection.
●	Conclusion:
 Mapping the process lineage reveals the attacker’s methodical approach to persistence, highlighting the importance of tracing parent-child relationships in endpoint telemetry.
🕒 Updated Timeline Summary:
1.	11:57:36 AM – powershell.exe initiated the execution chain.
2.	12:00:36 PM – BitSentinelCore.exe created in C:\ProgramData by csc.exe.
3.	12:02:14 PM – BitSentinelCore.exe executed manually by explorer.exe (1st time).
4.	12:02:14 PM – Registry persistence entry added:
 HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\BitSecSvc → "C:\ProgramData\BitSentinelCore.exe"
5.	12:02:14 PM – Process Spawn Chain:
 explorer.exe → BitSentinelCore.exe → cmd.exe (schtasks)
6.	12:02:15 PM – Scheduled task UpdateHealthTelemetry created to run BitSentinelCore.exe daily.
7.	12:03:16 PM – Executed again manually (2nd time).
8.	12:03:20 PM – Executed again manually (3rd time).
9.	12:06:51 PM – Keylogger artifact systemreport.lnk created in AppData\Roaming\Microsoft\Windows\Recent.

Flag 8: Timestamp Correlation

Correlate all observed behaviors to a single initiating event. To find all malicious activities — including file creation, registry modification, scheduled task creation, and keylogger deployment — trace back to a single initiating event
All malicious actions trace back to 12:02:14 PM, May 7, 2025.
Leading Event Timestamp: May 7, 2025, 12:02:14 PM
Initiating Process: BitSentinelCore.exe executed manually by the user via explorer.exe
Correlated Actions: Registry persistence entry added, Scheduled task UpdateHealthTelemetry created, Process chain initiated (explorer.exe → BitSentinelCore.exe → cmd.exe)
Attack Timeline




MITRE ATT&CK; Mapping

Attacker Behavior Analysis
 The Phantom Hackers demonstrated a stealthy, multi-stage intrusion with the following behavioral patterns: 
1. Initial Access & Execution
 
●	Technique: Social engineering or phishing likely led to the user executing a fake antivirus (BitSentinelCore.exe). 
●	Tactic: Execution (TA0002) Technique: User Execution (T1204.002) 
2. Defense Evasion 
●	Technique: Use of csc.exe (a LOLBin) to compile malware on the fly. 
●	Tactic: Defense Evasion (TA0005) 
●	Technique: Signed Binary Proxy Execution (T1218.005) 
3. Persistence
●	Technique: Registry Run key and Scheduled Task (UpdateHealthTelemetry) 
●	Tactic: Persistence (TA0003) 
●	Techniques: Registry Run Key (T1547.001), Scheduled Task/Job (T1053.005) 
4. Credential Access / Surveillance 
●	Technique: Keylogger artifact (systemreport.lnk) 
●	Tactic: Credential Access (TA0006) or Collection (TA0009)
●	Technique: Input Capture (T1056.001) 
5. Execution Chain Obfuscation 
●	Technique: Multi-layered process spawning (explorer → BitSentinelCore → cmd → schtasks) 
●	Tactic: Execution / Defense Evasion Technique: Command and Scripting Interpreter (T1059.003) 

Recommendations 

1. Immediate Containment: 
●	Terminate all instances of BitSentinelCore.exe. 
●	Remove the registry persistence entry and scheduled task.
●	Delete the keylogger artifact systemreport.lnk. 
2. System Hardening:
●	 Implement stricter execution policies for PowerShell scripts
●	Monitor and restrict the use of csc.exe and other LOLBins. 
●	Regularly audit scheduled tasks and registry keys for suspicious entries.
 3. User Awareness Training: 
●	Educate users on the risks of executing unknown files. 
●	Promote best practices for verifying the legitimacy of software. 
4. Advanced Threat Detection: 
●	Enhance endpoint monitoring to detect similar attack patterns. 
●	Utilize behavioral analytics to identify anomalous process chains. 
5. Incident Response Plan: 
●	Develop and rehearse a comprehensive incident response plan.
●	Ensure rapid communication and coordination during an attack.

