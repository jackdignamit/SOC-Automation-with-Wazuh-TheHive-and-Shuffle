# (WIP) SOC Automation with Wazuh, TheHive, and Shuffle
*Completed: November 1, 2025*

**This project demonstrates a fully integrated security operations center (SOC) automation workflow using Wazuh, TheHive, and Shuffle for *security orchestration, automation, and response* (SOAR). 
The goal was to build an end‑to‑end incident response pipeline that detects suspicious activity, performs automated triage, provides event data, and informs analysts.**

Tutorial by [MyDFIR](https://www.youtube.com/@MyDFIR).  
All implementation, exploration, and documentation performed independently as part of my cybersecurity learning journey.

- - - 

# Project Overview
In this project, I created a **fully automated, modern SOC workflow** that is designed to eliminate **human error** and **tedious tasks** in security operations. By utilizing open-source tools like **Wazuh (SIEM)**, **Shuffle (SOAR)**, and **TheHive (incident response and case management)**, my workflow detects threats, analyzes them, and informs analysts via emails without any human intervention. 

Cloud-based virtual machines are utilized to host Wazuh and TheHive. A Virtualbox Windows 11 VM is used as a vulnerable endpoint with credential-stealing malware **(Mimikatz)** that notifies Wazuh agents using Sysmon logs. Wazuh's *detect and response* (D&R) rules are flagged and trigger the automated workflow in Shuffle via a webhook. The data is then enriched with threat intelligence using **VirusTotal**, a **SHA256 hash** is captured, emails are sent, and creates a structured incident in TheHive for SOC analysts to investigate.

<img width="1228" height="530" alt="Screenshot 2025-11-01 162511" src="https://github.com/user-attachments/assets/dd1c6b16-713b-45cc-83fc-2562a0ef6193" />

## Tech Stack
| Tools & Technology | Purpose | Links |
|------------------|-----------------|-----------------|
| Wazuh       | SIEM/EDR platform for log collection, monitoring, and alerting | [https://wazuh.com/](https://wazuh.com/) |
| TheHive             | Incident response platform for case tracking | [https://strangebee.com/thehive/](https://strangebee.com/thehive/) |
| Shuffle             | SOAR platform for automated workflows  | [https://shuffler.io/](https://shuffler.io/) |
| Sysmon            | Endpoint telemetry for Windows  | [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Mimikatz           | Open-source credential-extracting tool used to simulate malicious activity | [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) |
| MITRE ATT&CK            | Knowledge base of adversary tactics, techniques, and procedures (TTP)  | [https://attack.mitre.org/](https://attack.mitre.org/) |
| VirusTotal            | Malware analysis and file reputation checker  | [https://www.virustotal.com/gui/](https://www.virustotal.com/gui/) |
| Virtual Machines        | Endpoint environment to run Mimikatz and test Wazuh EDR detection | [https://www.vultr.com/](https://www.vultr.com/), [https://www.virtualbox.org/](https://www.virtualbox.org/) |

- - -

# Architecture Diagram

<img width="1510" height="847" alt="Screenshot 2025-12-06 124107" src="https://github.com/user-attachments/assets/b7873087-d643-477c-a858-b45039c126df" />

1. **Collect Endpoint Telemetry**   
   A Windows VM with Sysmon installed generates logs for potentially malicious activity.
   A credential theft tool called Mimikatz is run, which triggers Wazuh agents on the endpoint to forward the detections to the Wazuh manager.
2. **Detection and Alerting (Wazuh)**  
   Wazuh acts as the central SIEM platform, ingesting logs from the endpoint and matching them to detection rules set to alert suspicious behavior. Alerts are generated when Mimikatz execution rules are flagged.
3. **Shuffle (SOAR) Orchestration**  
   Wazuh then forwards alerts via a webhook to Shuffle.
   In Shuffle, a workflow parses relevant details such as SHA256 hashes to then be queried using external threat investigation tools such as Virustotal for reputation scoring.
   Additional workflow steps are conducted like sending email notifications to a SOC team, ensuring analysts are up to date and able to investigate in TheHive.
5. **TheHive Case Creation and Management**  
   Shuffle uses TheHive's API to create alerts or cases in TheHive for structured incident tracking. This makes sure that all incidents are cataloged and assigned to analysts for investigations.

- - - 
# 🔢 Step-by-Step Walkthrough 🔢
## 1️⃣ Setup Virtualbox VM with Sysmon
To start, create a virtual machine, either using your own VM or a cloud-based service such as [Vultr](https://www.vultr.com/).  
For my lab, I used a [Virtualbox](https://www.virtualbox.org/) Windows 11 virtual machine.

**1.** To install a VirtualBox Windows 11 virtual machine, install the latest version from here: [https://www.virtualbox.org/](https://www.virtualbox.org/).  

**2.** Download a Windows 11 **.iso** file from [https://www.microsoft.com/en-us/software-download/windows11](https://www.microsoft.com/en-us/software-download/windows11).  

**3.** Add the `**.iso**` file to Virtualbox by navigating to "**New**" at the top of the screen, adding your `.iso` image, setting the version to Windows 11, and using all default settings.  
   - I recommend **8192 MB of base memory**, **2 processors**, and **80 GB** of hard disk storage space but it all depends on your setup.

**4.** Start up your VM and follow the Microsoft setup. When it asks for product key, say you don't have one, and use Windows 11 Pro.  

**5.** Now let's set up Sysmon which can be installed from here: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

*Sysmon is a free tool created by Microsoft that provides detailed information about system activities on Windows by capturing and logging events. For this particular project, it will be used to flag our credential stealer called Mimikatz.*

**6.** From there, we will need a config to tell Sysmon what to ignore and what to log. Let's use **sysmonconfig.xml** from here: [https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig.xml)
   - I saved it in my downloaded Sysmon directory.
  
**7.** In an **Administrative PowerShell** window, use ```cd``` to change directories to your Sysmon folder. It should be located in your **downloads** folder. Then, run it using `\.Sysmon64.exe -i sysmonconfig.xml`.

**You now have a functional VirtualBox virtual machine with Sysmon installed!**  
I recommend taking a snapshot of your virtual machine in this state so you can revert back to it if need be.

- - - 

## 2️⃣ Setup TheHive and Wazuh Virtual Machines
Let's use a cloud provider called [Vultr](https://www.vultr.com/) to create virtual machines to download Wazuh and TheHive.

**1.** Create an account on Vultr to create a cloud-based virtual machine. You don't need to use Vultr but it is what I will be using for this lab.  

**2.** Create two virtual machines for TheHive and Wazuh. I recommend naming them appropiately.

<img width="2078" height="397" alt="Screenshot 2025-11-01 125428" src="https://github.com/user-attachments/assets/1472914f-b043-4a83-b6d7-3246ef8927ac" />

**The virtual machine settings I used for each VM are:**
- Cloud Compute (Shared CPU)
- Ubuntu 24.04 x64
- Disabled Auto backups & IPv6 address (only need IPv4)
- **Wazuh VM:** 165 GB SSD, 4 vCPU, 8 GB Memory, 4 TB bandwidth ($40/month)
- **TheHive VM:** 320 GB SSD, 6 vCPUs, 16 GB Memory, 5 TB bandwidth ($80/month)

- - - 

## 3️⃣ Install Wazuh
Wazuh is an open-source security platform that provides threat detection, monitoring, and incident response all in one platform.

1. Secure Shell (SSH) connect into the Wazuh virtual machine using its public IP address listed on the Vultr dashboard.
   - `ssh root@[Wazuh public ip]`

2. To install Wazuh, download and run the Wazuh installation assistant. The latest version can be located here: [https://documentation.wazuh.com/current/quickstart.html](https://documentation.wazuh.com/current/quickstart.html)
   - This process may take a couple of minutes.
   
<img width="1463" height="792" alt="Screenshot 2025-12-07 125015" src="https://github.com/user-attachments/assets/f4036a4c-b8ca-45d7-a817-acafd1a4af0b" />
<img width="1481" height="176" alt="Screenshot 2025-11-01 125706" src="https://github.com/user-attachments/assets/0837eb85-bc97-4c89-9ec6-e9acae0c08e1" />

3. Once Wazuh has finished installing, **copy the provided username and password** needed to access the Wazuh dashboard. I HIGHLY recommend writing these down in a notepad file in case you forget.
   
4. We must first permit inbound traffic on TCP port 443 on the Wazuh server. Use the command **`ufw allow 443`** in the SSH session to enable this firewall rule.

5. Open up a web browser and navigate to the Wazuh dashboard using its public IP address. For example: **`https://172.168.53.146`**. **Sign in using your obtained login information.**
   - If accessing the dashboard fails, make sure that the server is up. You can check the server status using `systemctl status wazuh-manager.service`.

<img width="2483" height="1278" alt="Screenshot 2025-11-01 130713" src="https://github.com/user-attachments/assets/4a62cade-971b-42f4-9536-a168c59603d5" />

- - - 

## 4️⃣ Configure Wazuh
On the Wazuh dashboard, we will be creating a new agent to install on our Virtualbox VM.

1. Open the Wazuh dashboard on your Virtualbox VM. Deploy a new agent and configure it as a Windows agent with the Wazuh public IP address.

2. Open an **administrative PowerShell window** and paste the commands provided by Wazuh to install the agent. Once entered, run `net start wazuhsvc` to start the Wazuh service.
- If the agent fails to appear on the dashboard, permit its associated ports using `ufw allow 443`, `ufw allow 1514`, and `ufw allow 1515` commands **in the SSH session**.

<img width="955" height="296" alt="Screenshot 2025-12-13 122231" src="https://github.com/user-attachments/assets/26abad7b-164b-425f-ae98-a55d093f6aa2" />

<img width="471" height="100" alt="Screenshot 2025-11-01 135148" src="https://github.com/user-attachments/assets/b57191a5-1c0f-4946-bf46-6c0ad4422a1b" />

<img width="667" height="392" alt="Screenshot 2025-11-01 135140" src="https://github.com/user-attachments/assets/8d91e711-5b58-4038-ab38-9017e7979ffb" />

- - - 

## 5️⃣ Install & Configure TheHive
TheHive is an open-source **Security Orchestration, Automation, and Response (SOAR)** platform designed to help security teams collaborate, investigate incidents, and manage cases efficiently.

1. Secure Shell (SSH) connect into TheHive virtual machine using its public IP address listed on the Vultr dashboard.
   - `ssh root@[TheHive public ip]`
  
2. Open TheHive's website and follow the **step-by-step instructions** for setting up TheHive: [https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/](https://docs.strangebee.com/thehive/installation/installation-guide-linux-standalone-server/)

<img width="1366" height="1110" alt="Screenshot 2025-12-07 124900" src="https://github.com/user-attachments/assets/655473f2-bd3d-40ec-93c4-2d18aa9b0eda" />

3. Verify that **Java Virtual Machine**, **Elasticsearch**, **TheHive**, and **Apache Cassandra** are running. TheHive version I am using for this project is **5.5.7**.
      - `java -version` to verify Java is installed and up to date.

**Cassandra** is the **primary distributed NoSQL database** used by TheHive which stores all cases, alerts, tasks, and permissions.
**Elasticsearch** is a **search and indexing engine** used by TheHive as a search accelerator.

4. For Cassandra, we'll have to configured its default settings. Navigate to its configuration file using **`nano /etc/cassandra/cassandra.yaml`** and changing the following values:
  ```
   cluster_name: {VM name}
   listen_address: [THEHIVE PUBLIC IP ADDRESS]
   rpc_address: [THEHIVE PUBLIC IP ADDRESS]
   seed_provider: "{THEHIVE PUBLIC IP ADDRESS}:7000"
   ```
*Save the configurations by using CTRL+X, Y, and then enter key.*

5. Restart the Cassandra service (systemctl stop/start cassandra.service) and remove all extra files under its directory using **`rm -rf /var/lib/cassandra/*`**

      > Warning: This command deletes all Cassandra data and should only be run during initial setup.

<img width="1047" height="264" alt="Screenshot 2025-12-07 165202" src="https://github.com/user-attachments/assets/446bd4db-fd22-4768-a969-df8d15cc546b" />

6. For Elasticsearch, we'll have to configured its default settings. Navigate to its configuration file using **`nano /etc/elasticsearch/elasticsearch.yml`** and changing the following values:
```
cluster_name: {VM name}
node.name: node-1
network.host: [THEHIVE PUBLIC IP ADDRESS]
http.port: 9200
cluster.initial_master_nodes: ["node-1"]
```
   
*Save the configurations by using CTRL+X, Y, and then enter key.*

8. Restart the Elasticsearch service using **`systemctl stop elasticsearch`** and **`systemctl start elasticsearch`**.

<img width="1122" height="243" alt="Screenshot 2025-12-07 165747" src="https://github.com/user-attachments/assets/06dcc022-39e1-43a0-84cb-7c4a9df58f88" />

8. Before we can change TheHive's configuration file, we must change the directory TheHive uses from root to TheHive with `chown -R thehive:thehive /opt/thp`.

9. Navigate to TheHive's configuration file using **`nano /etc/thehive/application.conf`** and change the following values:
  
  **db.janusgraph:**
  ```
   cluster_name: '{VM name}'
   hostname: ["THEHIVE PUBLIC IP ADDRESS"]
   ```
 **index.search:**
   ```
   hostname: ["THEHIVE PUBLIC IP ADDRESS"]
   ```
 **Service Configuration:**
  ```
   application.baseUrl = "http://'{THEHIVE PUBLIC IP ADDRESS}:9000"
   ```
*Save the configurations by using CTRL+X, Y, and then enter key.*

10. Restart TheHive and enable it using **`systemctl start thehive`** and **`systemctl enable thehive`**.

<img width="1149" height="269" alt="Screenshot 2025-12-07 171748" src="https://github.com/user-attachments/assets/770e933f-c158-44da-8c36-2a9acc8c811d" />

11. Once TheHive is properly installed and running, you can navigate to its dashboard by using the public IP address you configured it with. "`http://YOUR_SERVER_ADDRESS:9000/`"
    **The default admin credentials are:**
    - Username: `admin@thehive.local`
    - Password: `secret`

If you cannot connect to the server, permit its port using **`ufw allow 9000`**.

- - - 

## 6️⃣ Configure ossec.conf configuration file
When the Wazuh agent was installed earlier, it installed an OSSEC-agent directory in your VM's `Program Files (x86)` folder.  
OSSEC agent is a host-based intrusion detection system (HIDS) component that runs on endpoints (such as your VM) to monitor and protect that host.

1. Navigate to your `Program Files (x86)\ossec-agent` directory on your Virtualbox VM and open the **ossec.conf** file in notepad.

2. Scroll down to the log analysis section and delete the following event channel exclusion section:

<img width="639" height="238" alt="Screenshot 2025-12-13 124229" src="https://github.com/user-attachments/assets/82ae42e2-2ebc-4410-9da0-cf8c1505e48f" />

3. Change the application location to **`Microsoft-Windows-Sysmon/Operational/location`** and save.

<img width="618" height="568" alt="Screenshot 2025-11-01 135615" src="https://github.com/user-attachments/assets/1202b2f6-8f97-45ff-8442-4e671167a7de" />

4. Restart the Wazuh agent service. You can confirm that the configuration works as expected by searching for "sysmon" on the Wazuh alerts dashboard:

<img width="1415" height="1163" alt="Screenshot 2025-11-01 135748" src="https://github.com/user-attachments/assets/fed6fc44-5b2d-44b5-9196-fe2324f928ae" />

We configured the Wazuh service on the Virtualbox VM, now we must do the same for the VM hosting our Wazuh dashboard using its SSH session. 

5. Use the command `nano /var/ossec/etc/ossec` to open the **ossec.conf** file on the Wazuh VM. Change the `<logall>` and `<logall_json>` values from no to yes.

*Save the configurations by using CTRL+X, Y, and then enter key.*

<img width="905" height="626" alt="Screenshot 2025-11-01 140951" src="https://github.com/user-attachments/assets/58094ac6-80ed-4c13-93dc-121338480859" />

6. Let's do the same for **filebeat.yml**. Use the command `nano /etc/filebeat/filebeat.yml` and change the "archives" enabled value from false to true under `filebeat.modules`.

<img width="320" height="183" alt="Screenshot 2025-12-13 141136" src="https://github.com/user-attachments/assets/ba95c332-e929-4d67-8b24-33184e0dec67" />

*Save the configurations by using CTRL+X, Y, and then enter key.*

Now, all detections and events will be logged.

- - - 

## 7️⃣ Install Mimikatz on your Virtualbox VM
Mimikatz is a post-exploitation security tool that demonstrates how credentials can be stolen from a system after an attacker has gained access. 
It is a form of malware, but since we are using a VM with nothing personal on it, it will just be used to flag our detection rule on Wazuh.

1. Before installing Mimikatz, Windows Defender must be disabled on the VM. You can also create an exclusion rule for either your downloads folder or the entire drive itself.

2. Navigate to this link and download the latest version of Mimikatz onto **YOUR VIRTUAL MACHINE**. **Review Source Code / Download here:** [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

3. Extract the file and open a PowerShell window to execute the file.
<img width="1012" height="389" alt="Screenshot 2025-11-01 140746" src="https://github.com/user-attachments/assets/f857ba67-cee9-4298-a96e-09e05452de82" />

4. If we search for 'Mimikatz' on the Wazuh dashboard, we should be able to see its execution history.

<img width="2474" height="802" alt="Screenshot 2025-11-01 141533" src="https://github.com/user-attachments/assets/3ef3d2ac-160b-4b58-964c-6d7155179e62" />

- - - 

## 8️⃣ Create a custom detection rule on Wazuh
Custom rules ensure that alerts are triggered only for relevant, high-value events, such as a Mimikatz execution. This helps reduce noise and false positives, enabling more accurate and timely automated response actions.

1. On the Wazuh dashboard, under the server management tab, click on "rules" and then the custom rules button in the top right.

2. Edit the **local_rules.xml** file and copy the formatting of the rule with an ID of 100002. Use it as a template to create your own Mimikatz detection rule like such:

<img width="1110" height="806" alt="Screenshot 2025-11-01 142721" src="https://github.com/user-attachments/assets/fc132d95-4d0d-48f3-9f16-8f470935b0f2" />

### This rule searches for original file names of "mimikatz.exe" under `sysmon_event1`, aka process creations. If found, it triggers the rule and labels it with a description, a level of 15 (the highest), and a [MITRE ATT&CK](https://attack.mitre.org/) framework ID of T1003.

<img width="2367" height="885" alt="Screenshot 2025-12-13 150029" src="https://github.com/user-attachments/assets/b831a66f-476d-482f-970c-f5f6b2667acd" />

### If you save and then rerun Mimikatz, it should immediately detect the file execution.

<img width="2479" height="796" alt="Screenshot 2025-11-01 151417" src="https://github.com/user-attachments/assets/4b509552-bd80-412d-aacf-9df541d954ef" />

<img width="622" height="488" alt="Screenshot 2025-11-01 151522" src="https://github.com/user-attachments/assets/ef7c0e8e-b484-4222-b46b-b9aeacc76a1a" />

- - -

## 9️⃣ Setup Shuffle
Shuffle is an open-source security orchestration, automation, and response (SOAR) platform used to help SOC teams automate and coordinate incident responses and manage everyday security tasks. We will utilize it to receive alerts from our Wazuh manager, inform analysts and stakeholders, and perform responsive actions.

1. To start, create a [Shuffle](https://shuffler.io/) account. Then, create a new workflow.

2.  Add a webhook to the workflow and copy its webhook URI. Then update the Wazuh Manager's `ossec.conf` file in the SSH session by using the `nano /var/ossec/etc/ossec.conf` command.
    Insert the following code between the <global> and <alerts> section:
      
    ```
    <integration>
       <name>shuffle</name>
       <hook_url>YOUR_WEBHOOK_URI>
       <rule_id>100002</rule_id>
       <alert_format>json</alert_format>
    </integration>
    ```
    
    <img width="1605" height="736" alt="image" src="https://github.com/user-attachments/assets/f16aec99-dbba-448f-ad35-8caf1d74a0ec" />

   *(Replace the "**YOUR_WEBHOOK_URI**" text with the URI you copied from Shuffle earlier.)*
   *Save the configurations by using CTRL+X, Y, and then enter key.*

3. Start the Webhook and rerun Mimikatz. This should trigger another alert in Wazuh which will be funneled into Shuffle.

  <img width="581" height="280" alt="Screenshot 2025-11-01 151611" src="https://github.com/user-attachments/assets/6b257ed9-9ef6-4bd1-aac4-afcf97de4d57" />
  <img width="580" height="837" alt="Screenshot 2025-11-01 151618" src="https://github.com/user-attachments/assets/a2a2fdab-a026-465f-b0fb-9817061fba8a" />

### Now that the webhook is setup, let's have it extract a SHA256 hash and run it through VirusTotal. 

4. Drag the "Shuffle Tools" app to the workflow and set the "**Find actions**" field to **Regex capture group** with the regex being `SHA256=([0-9A-Fa-f]{64})`. Lastly, set **hashes** as the input data. 

<img width="392" height="493" alt="Screenshot 2025-11-01 152049" src="https://github.com/user-attachments/assets/0a6db843-971c-472b-9fc1-2e735c338bb4" />

5. Add a [VirusTotal](https://www.virustotal.com/gui/) app, create an account, and set your API key to authenticate the app. Configure VirusTotal to use only group_0 from the SHA-256 Hash app.
   
<img width="1179" height="492" alt="Screenshot 2025-11-01 152642" src="https://github.com/user-attachments/assets/c5a9a658-113c-4c2e-9084-1de97fd83277" />
<img width="412" height="1000" alt="Screenshot 2025-11-01 153421" src="https://github.com/user-attachments/assets/107e473e-1030-470b-ad8f-050f1f3d0813" />

### If you rerun Mimikatz, the alert should be funneled into the webhook and into VirusTotal and the SHA256 Hasher.

<img width="582" height="436" alt="Screenshot 2025-11-01 152756" src="https://github.com/user-attachments/assets/b8bb3bb0-896b-4a03-a2c3-89e7b46f055a" />
<img width="560" height="1027" alt="Screenshot 2025-11-01 153520" src="https://github.com/user-attachments/assets/4e07d731-c92a-4284-ac5e-2df2a1b1c240" />

- - -

## 🔟 Configure TheHive and Detection Emails in Shuffle

1. In Shuffle, add **TheHive** app to the workflow. Before we can attach it to the rest of our workflow, we need to create a Hive organization and user accounts.

2. On TheHive dashboard, sign in and add a new organization.

<img width="521" height="542" alt="Screenshot 2025-11-01 154106" src="https://github.com/user-attachments/assets/85f808d7-6549-4138-8bf9-e5b9783ca8fb" />

3. Add two new users to the organization, a normal type account in the analyst profile and the other as a service type in the analyst profile.

4. Create an API key for the service account and paste it in **TheHive** app in Shuffle. Set the url as your public IP and include the port.

<img width="510" height="650" alt="Screenshot 2025-11-01 154342" src="https://github.com/user-attachments/assets/9ef2e5b6-ac62-450d-8efb-7cac35d16e09" />

5. In Shuffle, set TheHive app to create an alert. Configure the body section with whatever information you want. I used the advanced tab to configure mine, with the settings found below:

<img width="2052" height="852" alt="Screenshot 2025-11-01 161136" src="https://github.com/user-attachments/assets/3e019978-e880-4bd0-beca-474083514526" />

```
{
  "description": "$exec.title",
  "externallink": "${externallink}",
  "flag": false,
  "pap": 2,
  "severity": "3",
  "source": "$exec.pretext",
  "sourceRef": "$exec.rule_id",
  "status": "New",
  "summary": "Mimikatz activity detected on host: $exec.text.win.system.computer",
  "tags": ["T1003"],
  "title": "$exec.title",
  "tlp": "2",
  "type": "internal"
}
```

### When a Mimikatz instance is detected, TheHive will be notified and all its associated users.

<img width="572" height="445" alt="Screenshot 2025-11-01 161119" src="https://github.com/user-attachments/assets/79740c0d-b78d-4daa-beea-113ae6299262" />
<img width="2421" height="260" alt="Screenshot 2025-11-01 161353" src="https://github.com/user-attachments/assets/716a08c9-6fbb-47e0-b697-d0a9c6f4b8ac" />
<img width="1127" height="740" alt="Screenshot 2025-11-01 162913" src="https://github.com/user-attachments/assets/e72403b9-21f4-4332-b7b2-56593f033fc7" />

The last thing to setup for our SOAR workflow is an email notification about Wazuh alerts. 

6. Drag an **email app** to the Shuffle workflow and connect it to the VirusTotal app.

7. Specify recipients, a subject line, and a body.
   
<img width="590" height="305" alt="Screenshot 2025-11-01 162450" src="https://github.com/user-attachments/assets/44b4aaf4-cf1b-4392-ac7b-6f609d8edd12" />
<img width="1964" height="50" alt="Screenshot 2025-11-01 162409" src="https://github.com/user-attachments/assets/59f74b9a-f935-4ab2-8d9d-dcf6618daec9" />
<img width="1379" height="414" alt="Screenshot 2025-11-01 162422" src="https://github.com/user-attachments/assets/48d8074b-5b36-448c-8fec-e7deff49b2d1" />

### Now our Wazuh, Shuffle, and TheHive automated workflow is complete!

<img width="1228" height="530" alt="Screenshot 2025-11-01 162511" src="https://github.com/user-attachments/assets/89eb77f6-846c-4182-aa30-52b374124b4d" />

- - -

# Key Skills Demonstrated
1. **SIEM Setup & Management**
   - Deploying and configuring Wazuh as a centralized platform for ingesting logs, monitoring, and alerting.
   - Configured detect & response (D&R) rule in Wazuh dashboard to catch malicious process executions (Mimikatz.exe)
2. **SOAR Workflow Development**
   - Building automated workflows in Shuffle to handle alerts, parse data, integrate APIs, and alerting via emails.
   - Reduce manual SOC workloads by automating repetitive tasks
   - Configured email notifications from Shuffle for informing Stakeholders or response teams
3. **API Integration**
   - Using REST APIs for VirusTotal and TheHive incident management and creation
4. **Incident Response & Case Management**
   - Utilizing TheHive for investigations and tracking by properly structuring security incidents
5. **Endpoint Telemetry Configuration**
   - Utilized two Vultr cloud-based virtual machines to host and configure Wazuh and TheHive.
   - Hosted a VirtualBox VM as a Windows 11 endpoint
   - Installed and configured Sysmon to capture log data
   - Installed and configured Wazuh agents to capture Sysmon log data and funnel it to the Wazuh dashboard
   - Using Mimikatz to simulate malicious behavior on a virtual machine

- - - 

# Conclusion
This project successfully demonstrates how to build a robust, end-to-end incident response workflow using Wazuh, Shuffle, and TheHive. It showcases how to simulate a real-world threat using Mimikatz on a virtual machine, detecting its presence, and funneling security details from Sysmon into a Wazuh agent and then a dashboard. From there, it is enriched by Shuffle's automated response workflow which informs analysts and stakeholders via email about the detection. Lastly, the case is added to TheHive's case management platform which are then acted upon by analysts.

This lab stands out as a learning platform and proof of concept for SIEM, SOAR, and case management. It clearly demonstrates the importance of automation in Cybersecurity due to its acceleration of detection and response times. This increase in efficiency reduces analyst fatigue and improves overall SOC productivity. From configuring endpoints and SIEM rules to designing a SOAR workflow with API connections, it showcases the practical integration challenges and processes needed to build such a system.
