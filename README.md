# (WIP) SOC-Automation with Wazuh, Cortex, and Shuffle
*Completed: November 1, 2025*

**description**

Tutorial by [MyDFIR](https://www.youtube.com/@MyDFIR).  
All implementation, exploration, and documentation performed independently as part of my cybersecurity learning journey.

- - - 

# Project Overview
description

## Tech Stack
| Tool & Technology | Purpose | Links |
|------------------|-----------------|-----------------|
| Wazuh       | SIEM/EDR platform for log collection, monitoring, and alerting | [https://wazuh.com/](https://wazuh.com/) |
| TheHive             | Incident response platform for case tracking | [https://strangebee.com/thehive/](https://strangebee.com/thehive/) |
| Shuffle             | SOAR platform for automated workflows  | [https://shuffler.io/](https://shuffler.io/) |
| Sysmon            | Endpoint telemtry for Windows  | [https://shuffler.io/](https://shuffler.io/) |
| Mimikatz           | Open-source credential-extracting tool used to simulate malicious activity | [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) |
| Virtual Machines        | Endpoint environment to run Mimikatz and test Wazuh EDR detection | [https://www.vultr.com/](https://www.vultr.com/) [https://www.virtualbox.org/](https://www.virtualbox.org/) |

- - -

# Architecture Diagram

<img width="1510" height="847" alt="Screenshot 2025-12-06 124107" src="https://github.com/user-attachments/assets/b7873087-d643-477c-a858-b45039c126df" />

1. Collect endpoint events of malicious behavior:
   
2. Wazuh Manager triggers alerts:
   
3. Shuffle receives Wazuh Alerts & sends responsive actions:

4. 

- - - 
# 🔢 Step-by-Step Walkthrough 🔢
## 1️⃣ Setup Virtualbox VM with Sysmon
To start, create a virtual machine, either using your own VM or a cloud-based service such as [Vultr](https://www.vultr.com/).  
For my lab, I used a [Virtualbox](https://www.virtualbox.org/) Windows 11 virtual machine.

**1.** To install a VirtualBox Windows 11 virtual machine, install the latest version from here: [https://www.virtualbox.org/](https://www.virtualbox.org/).  

**2.** Download a Windows 11 **.iso** file from [https://www.microsoft.com/en-us/software-download/windows11](https://www.microsoft.com/en-us/software-download/windows11).  

**3.** Add the `**.iso**` file to Virtualbox by navigating to "**New**" at the top of the screen, adding your `.iso` image, setting the version to Windows 11, and using all default settings.  
   - I recommend **8192 MB of base memory**, **2 processors**, and **80 GB** of hard disk storage space but it all depends on your setup.

**4.** Startup your VM and follow the Microsoft setup. When it asks for product key, say you don't have one, and use Windows 11 Pro.  

**5.** Now let's setup Sysmon which can be installed from here: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

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

1. Secure Shell connect into the Wazuh virtual machine using its public IP address listed on the Vultr dashboard.
   - `ssh root@[Wazuh public ip]`

2. To install Wazuh, download and run the Wazuh installation assistent. The latest version can be located here: [https://documentation.wazuh.com/current/quickstart.html](https://documentation.wazuh.com/current/quickstart.html)
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

2. Open an **administrative powershell window** and paste the commands provided by Wazuh to install the agent. Once entered, run `net start wazuhsvc` to start the Wazuh service.
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
**Elasticsearch** is a **search and indexing engine** used by both Cassandra and TheHive as a search accelerator.

4. For Cassandra, we'll have to configured its default settings. Navigate to its configuration file using **`nano /etc/cassandra/cassandra.yaml`** and changing the following values:
  ```
   cluster_name: {VM name}
   listen_address: [THEHIVE PUBLIC IP ADDRESS]
   rpc_address: [THEHIVE PUBLIC IP ADDRESS]
   seed_provider: "{THEHIVE PUBLIC IP ADDRESS}:7000"
   ```
*Save the configurations by using CTRL+X, Y, and then enter key.*

5. Restart the Cassandra service (systemctl stop/start cassandra.service) and remove all extra files under its directory using **`rm -rf /var/lib/cassandra/*`**

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
When the Wazuh service was installed earlier, it installed an OSSEC-agent directory in your VM's `Program Files (x86)` folder.  
OSSEC agent is a host-based intrusion detection system (HIDS) component that runs on endpoints (such as your VM) to monitor and protect that host.

1. Navigate to your `Program Files (x86)\ossec-agent` directory on your Virtualbox VM and open the **ossec.conf** file in notepad.

2. Scroll down to the log analysis section and delete the following eventchannel exclusion section:

<img width="639" height="238" alt="Screenshot 2025-12-13 124229" src="https://github.com/user-attachments/assets/82ae42e2-2ebc-4410-9da0-cf8c1505e48f" />

3. Change the application location to **`Microsoft-Windows-Sysmon/Operational/location`** and save.

<img width="618" height="568" alt="Screenshot 2025-11-01 135615" src="https://github.com/user-attachments/assets/1202b2f6-8f97-45ff-8442-4e671167a7de" />

4. Restart the Wazuh agent service. You can confirm that the configuration works as expected by searching for "sysmon" on the Wazuh alerts dashboard:

<img width="1415" height="1163" alt="Screenshot 2025-11-01 135748" src="https://github.com/user-attachments/assets/fed6fc44-5b2d-44b5-9196-fe2324f928ae" />

We configured the Wazuh service on the Virtualbox VM, now we must do the same for the VM hosting our Wazuh dashboard using its SSH session. 

5. Use the command `nano /var/ossec/etc/ossec` to open the **ossec.conf** file on the Wazuh VM. Change the <logall> and <logall_json> values from `no` to `yes`.

*Save the configurations by using CTRL+X, Y, and then enter key.*

<img width="905" height="626" alt="Screenshot 2025-11-01 140951" src="https://github.com/user-attachments/assets/58094ac6-80ed-4c13-93dc-121338480859" />

Now, all detections and events will be logged.

- - - 

## 7️⃣ Install Mimikatz on your Virtualbox VM
Mimikatz is a post-exploitation security tool that demonstrates how credentials can be stolen from a system after an attacker has gained access. 
It is a form of malware, but since we are using a VM with nothing personable on it, it will just be used to flag our detection rule on Wazuh.

1. Before installing Mimikatz, Windows Defender must be disabled on the VM. You can also create an exclusion rule for either your downloads folder or the entire drive itself.

2. Navigate to this link and download the latest version of Mimikatz onto **YOUR VIRTUAL MACHINE**. **Review Source Code / Download here:** [https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

3. Extract the file and open a PowerShell window to execute the file.
<img width="1012" height="389" alt="Screenshot 2025-11-01 140746" src="https://github.com/user-attachments/assets/f857ba67-cee9-4298-a96e-09e05452de82" />

4. If we search for 'Mimikatz' on the Wazuh dashboard, we should be able to see its execution history.

- - - 

## 8️⃣ 

- - -


## 9️⃣ Create a custom detection rule on Wazuh

- - -

## 1️⃣0️⃣ Create a SOAR Playbook using Shuffle

- - -

# Key Skills Demonstrated

- - - 

# Conclusion
