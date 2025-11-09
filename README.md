# 🛠️ Cybersecurity Project: SOAR EDR Integration Lab

This document is the complete project outline for the **SOAR EDR Project (Parts 1–5)**.  
It demonstrates building **detection and response rules** in an EDR platform (**LimaCharlie**), creating **automated playbooks** in a SOAR platform (**Tines**), and integrating **Slack** for real-time incident response workflows.

---

## 🔍 Project Overview

Build a hands-on cybersecurity lab that demonstrates an end-to-end **Detection → Automation → Response** workflow:

| Component | Description |
|------------|--------------|
| **Infrastructure** | Cloud-hosted Windows VM (Vultr recommended) or local Windows machine with internet connectivity |
| **EDR Platform** | LimaCharlie for endpoint detection and response capabilities |
| **SOAR Platform** | Tines for security orchestration, automation, and response |
| **Detection Target** | Lazagne credential recovery tool (simulates adversary behavior) |
| **Automation Workflow** | Detection → Slack alert → Email notification → User prompt → Automated isolation |
| **Learning Outcomes** | EDR configuration, custom detection rule creation, SOAR playbook design, Slack/email integration, and automated incident response |

---

## 📂 Project Parts

1. **Part 1 — Playbook Workflow Design** *(draw.io diagram)*  
2. **Part 2 — LimaCharlie Setup & Agent Deployment** *(EDR configuration)*  
3. **Part 3 — Detection Rule Creation** *(Lazagne detection + telemetry generation)*  
4. **Part 4 — Tines Integration** *(webhook configuration + Slack setup)*  
5. **Part 5 — SOAR Automation** *(complete playbook/story build)*  

---

## ✅ Part 1 — Playbook Workflow Design

### 🧰 Tools

- [draw.io](https://app.diagrams.net) (free online diagramming tool)

### 🎯 Objective

Create a visual workflow that maps out the automated response process **before** building it in Tines.

---

### 🔄 Workflow Components

#### Detection Phase

- LimaCharlie EDR detects **Lazagne hack tool** execution.  
- Generates alert with event metadata.

#### Automation Phase (Tines Story)

- **Webhook Trigger:** Receives detection alert from LimaCharlie  
- **Slack Notification:** Posts alert to `#alerts` channel with key details  
- **Email Notification:** Sends detailed alert to SOC analyst  

**Alert Details Include:**

- Timestamp  
- Computer name  
- Source IP address  
- Process
- Command line  
- File path  
- Sensor ID  
- Link to detection (if applicable)

#### Decision Phase

- **User Prompt:** “Does the user want to isolate the machine?”

**YES (Blue path):**

- LimaCharlie automatically isolates the infected machine  
- Slack message posted: *“Computer [hostname] has been isolated”*  
- Includes isolation status confirmation  

**NO (Pink path):**

- No isolation action taken  
- Slack message posted: *“Computer [hostname] was not isolated. Please investigate”*  

---

### 🧠 Playbook Logic (Decision Tree)

```text
Hack Tool Detected (Lazagne)
          ↓
    LimaCharlie Detection
          ↓
    Send Alert to Tines
          ↓
    ┌─────────────────────┐
    │  Slack Notification │
    │  Email Notification │
    └─────────────────────┘
          ↓
    User Prompt: Isolate Machine?
          ↓
    ┌─────┴─────┐
   YES         NO
    ↓           ↓
Isolate     Do Nothing
Machine        
    ↓           ↓
Confirm in  Send Message
  Slack       to Slack
```

---

### 🧱 Architectural Diagram

<p align="center">
<img src="assets/screenshots/1.Network Diagram.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-1: Screenshot of Network diagram</em>
</p>

---

## 💻 Part 2 — LimaCharlie Setup & Agent Deployment

### 🎯Objective

Install and configure LimaCharlie EDR, deploy the sensor agent to a Windows machine, and verify telemetry collection.

---

### 🖥️ Infrastructure Setup

#### Option 1 — Cloud VM (Vultr Recommended)

#### Sign up for Vultr

- Create account + verify email (referral credits optional)

#### Deploy Windows Server VM

1. *Deploy → New Server*  
2. **Server Type:** Cloud Compute – Shared CPU  
3. **Region:** Closest to you (e.g., Toronto)  
4. **OS:** Windows Server 2022 (Standard)  
5. **Plan:** $24 / month (2 vCPU | 4 GB RAM | 80 GB SSD)  
6. **Disable:** Auto Backups & IPv6  
7. **Hostname:** `MyDFIR-SOAR-EDR`  
8. **Deploy Now** (~15 min setup)

<p align="center">
<img src="assets/screenshots/2.vm-properties.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-2: Screenshot of VM Architecture</em>
</p>

#### Firewall Configuration

- **Allow RDP (3389):** TCP | Source: My IP  
- **Default Deny:** Drop all other traffic  
- **Attach Firewall Group to the VM:** `MyDFIR-SOAR-EDR`

<p align="center">
<img src="assets/screenshots/3.vm-firewall-configuration.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-3: Firewall Rules</em>
</p>

#### Access VM

- Wait until status = “Running”  
- Retrieve password from VM details  
- Connect via RDP (`mstsc`) using public IP  
- Login as Administrator  

<p align="center">
<img src="assets/screenshots/4.rdp-connection-success.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-4: Successful RDP</em>
</p>

---

### 🛡️ LimaCharlie Setup

#### 1️⃣ Create Account

- Visit [limacharlie.io](https://limacharlie.io) → **Sign Up**
- Options: Email (Recommended) | Google | GitHub | Microsoft  
- Verify email → Login

#### 2️⃣ Initial Configuration

- Click **Create Organization**
  - Name: `mydfir-soar-edr`  
  - Region: Closest data center (e.g., Canada / US)  
- Wait ~30 seconds for provisioning

<p align="center">
<img src="assets/screenshots/5.LCA-Organization.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-5: LimaCharlie Organization</em>
</p>

#### 3️⃣ Generate Installation Key

1. Navigate → **Sensors → Installation Keys**
2. Click **Create Installation Key**
   - Description: `mydfir-soar-edr-project`
   - Tags: optional  
3. Click **Create**
4. Delete default keys: `atomic-red-team`, `yara`, `demo-sensor`, `reliable-tasking`

<p align="center">
<img src="assets/screenshots/6.LCA-Installation-Keys.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-6: LimaCharlie Installation Keys</em>
</p>

---

#### 4️⃣ Install LimaCharlie Agent on Windows

##### In LimaCharlie Web UI**

- Go → *Installation Keys → Sensor Downloads*
- Copy link for **Windows 64-bit EDR**

##### On Windows VM**

1. Paste download link in browser  
2. Save `hcp_win_x64_release.exe` to Downloads  

##### Disable Defender (temporary)**

```Text
Settings → Virus & Threat Protection → Manage Settings → Real-time Protection = Off
```

If SmartScreen blocks: *Keep → Keep anyway*

##### Install Agent via PowerShell**

```powershell
cd Downloads
dir
.\hcp_win_x64_release.exe -i <INSTALLATION_KEY>
```

Example:

```powershell
.\hcp_win_x64_release.exe -i a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Wait for message → `Success: Agent installed successfully`

##### Verify Service**

- `services.msc` → Locate *LimaCharlie*  
- Status = Running | Startup = Automatic

<p align="center">
<img src="assets/screenshots/7.LCA-Successful-Installation.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-7: LimaCharlie Successful Installation</em>
</p>

---

#### 5️⃣ Verify Sensor in LimaCharlie

- Navigate → **Sensors → Sensor List**
- Confirm:
  - Hostname = machine name  
  - Status = 🟢 Online  
  - Platform = Windows  
  - “Last Seen” recent  

<p align="center">
<img src="assets/screenshots/8.LCA-Sensor-List.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-8: LimaCharlie Sensors List</em>
</p>

<p align="center">
<img src="assets/screenshots/9.LCA-Sensor-Details.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-9: LimaCharlie Sensor Details</em>
</p>

---

### 🔍 Exploring LimaCharlie Capabilities

#### 🕒 Timeline Analysis

- View all endpoint events chronologically  
- Filter by event type, time, or keyword  

#### ⚙️ Processes View

- Real-time process listing with command-line args  
- Actions: Kill, Suspend, Download memory, View strings/map  

#### 🌐 Network Connections

- Live netstat output with PID/IP/Port  
- Identify C2 activity quickly  

#### 📁 File System Browser

- Remote file access without RDP  
- Metadata: Created/Modified/Accessed times, Hashes  
- Actions: Download, Delete, Hash, VirusTotal lookup  

#### 💻 Console (Remote Commands)

Examples:

```bash
netstat
processes
network_connections
file_get
reg_query
```

#### 🔁 Auto Runs (Persistence)

Lists persistence mechanisms like registry keys, scheduled tasks, startup items.

<p align="center">
<img src="assets/screenshots/10.LCA-Capabilities.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-10: LimaCharlie Capabilities</em>
</p>

---

### 🧪 Example Investigation Workflow

**Scenario:** User reports slow computer + mouse movement.  

1. **Processes:** Check for suspicious processes (e.g., Excel spawning PowerShell).  
2. **Network:** Inspect outbound connections → unknown IPs.  
3. **Auto Runs:** Check for persistence entries.  
4. **File System:** Locate suspicious executables (temp/public/recycle).  
5. **Timeline:** Rebuild event timeline around incident window (± 5 min).  

---

## Part 3 — Detection Rule Creation & Telemetry Generation

**Objective**: Generate telemetry by executing Lazagne password recovery tool, analyze events in LimaCharlie, and create a custom detection and response (D&R) rule.

### 🎯 Lazagne Overview

**What is Lazagne?**

- Open-source password recovery tool
- Extracts credentials from multiple sources:
  - Web browsers (Chrome, Firefox, Edge, etc.)
  - Email clients
  - Databases
  - Chat applications (Discord, Skype, etc.)
  - Git credentials
  - WiFi passwords
  - And more

**Why Use It?**

- Commonly used by both red teams and real attackers
- Demonstrates credential theft tactics
- Provides realistic telemetry for detection engineering

### 📥 Download and Execute Lazagne

#### 1) Download Lazagne

**On Windows machine**:

1. Navigate to [Lazagne GitHub](https://github.com/AlessandroZ/LaZagne/releases)
2. Click **Releases** tab
3. Download **lazagne.exe** (latest release)
4. **If Windows Defender blocks**:
   - Click notifications → **lazagne.exe was blocked as unsafe**
   - Click three dots → **Keep** → **Keep anyway**
5. File saves to `Downloads` folder

#### 2) Execute Lazagne (Initial Test)

**Generate baseline telemetry**:

1. Open **File Explorer** → Navigate to **Downloads**
2. Hold **Shift** + **Right-click** in Downloads folder
3. Select **Open PowerShell window here**
4. Test execution:

    ```powershell
        .\lazagne.exe
    ```

5. **Expected output**: Help menu showing available commands

#### 3) Generate Detection Telemetry

**Execute with 'all' parameter** (extracts all credential types):

```powershell
.\lazagne.exe all
```

**Expected output**:

- Scans multiple credential sources
- Displays recovered passwords (if any exist)
- Process completes and returns to prompt

**Note**: This execution will trigger the detection we're about to build.

### 🔍 Analyze Lazagne Telemetry in LimaCharlie

#### 1) Locate Process Creation Event

**In LimaCharlie Web Interface**:

1. Navigate to **Sensors** → **Sensors List**
2. Click on your sensor
3. Select **Timeline** tab (left sidebar)
4. **Search for Lazagne**:
   - Use search box: `lazagne`
   - Or filter by event type: **NEW_PROCESS**

#### 2) Identify Key Event Fields

**Click on the NEW_PROCESS event** for `lazagne.exe`:

**Critical fields for detection**:

| Field | Value | Notes |
|-------|-------|-------|
| **Event Type** | `NEW_PROCESS` | Process creation event |
| **FILE_PATH** | `C:\Users\Administrator\Downloads\lazagne.exe` | Full executable path |
| **COMMAND_LINE** | `lazagne.exe` (or `lazagne.exe all`) | Command-line arguments |
| **HASH** | `<SHA256_hash>` | File hash for IOC matching |
| **PARENT** | PowerShell.exe | Parent process (shows execution method) |
| **USER** | Administrator | User who executed the tool |
| **PROCESS_ID** | `<PID>` | Process identifier |

**Additional context from event details**:

- Timestamp
- Internal IP
- Sensor ID
- File signed: No (unsigned executable)

<p align="center">
<img src="assets/screenshots/11.Lazagne-execution-proof.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-11: Lazagne Execution Proof in LimaCharlie</em>
</p>

### 🛠️ Create Detection and Response Rule

#### Understanding D&R Rules

**LimaCharlie D&R Rules consist of two blocks**:

1. **Detect Block**: Defines the conditions that trigger the rule
2. **Respond Block**: Defines the actions taken when conditions are met

#### Rule Building Strategy

**Don't build from scratch**—leverage existing rules!

1. Navigate to **Automation** → **D&R Rules** (left sidebar)
2. Browse existing rules for similar detections
3. **Search for credential-related rules**: Type `credential` in search
4. **Locate process creation rules**: Look for rules monitoring `NEW_PROCESS` or `EXISTING_PROCESS`
5. **Example template**: "Windows Process Creation" rule
6. Click **View the content of this rule in the GitHub repository**

##### 1) Copy Template Rule

**From GitHub**:

1. Click **Raw** button (top-right of rule content)
2. **Select all** and **Copy** the YAML content
3. Return to LimaCharlie

**In LimaCharlie**:

1. **D&R Rules** → Click **New Rule** (top-right)
2. Click **pencil icon** (edit mode) on the rule editor
3. **Paste** the copied template
4. **Delete** the existing placeholder content first

##### 2) Modify the Detect Block

**Original template structure**:

```yaml
detect:
  events:
    - NEW_PROCESS
    - EXISTING_PROCESS
  op: and
  rules:
    - op: is windows
    - case sensitive: false
      op: ends with
      path: event/FILE_PATH
      value: DeviceCredentialDeployment.exe
```

**Modify for Lazagne detection**:

```yaml
detect:
  events:
    - NEW_PROCESS
    - EXISTING_PROCESS
  op: and
  rules:
    - op: is windows
    - op: or
      rules:
        # Detection method 1: File path ends with lazagne.exe
        - case sensitive: false
          op: ends with
          path: event/FILE_PATH
          value: lazagne.exe
        
        # Detection method 2: Command line ends with 'all'
        - case sensitive: false
          op: ends with
          path: event/COMMAND_LINE
          value: all
        
        # Detection method 3: Command line contains 'lazagne'
        - case sensitive: false
          op: contains
          path: event/COMMAND_LINE
          value: lazagne
        
        # Detection method 4: Hash matches known Lazagne hash
        - case sensitive: false
          op: is
          path: event/HASH
          value: '<LAZAGNE_HASH_HERE>'
```

**Explanation of logic**:

- **Event types**: Monitor both `NEW_PROCESS` and `EXISTING_PROCESS`
- **Platform check**: `op: is windows` (only trigger on Windows systems)
- **OR operator**: Any one of the four detection methods will trigger the rule:
  1. **File path ends with `lazagne.exe`**: Catches renamed files in different directories
  2. **Command line ends with `all`**: Detects the specific `lazagne.exe all` command (may cause false positives with other tools using "all" parameter)
  3. **Command line contains `lazagne`**: Catches any Lazagne execution regardless of parameters
  4. **Hash matches**: IOC-based detection (survives file renames, bypassed if hash changes)

**Obtain Lazagne hash**:

- In LimaCharlie Timeline → Click Lazagne NEW_PROCESS event
- Copy the **HASH** field value
- Paste into the `value:` field in detection method 4

##### 3) Understanding Operators

**Available operators** (LimaCharlie documentation):

| Operator | Description | Example |
|----------|-------------|---------|
| `is` | Exact match (case-insensitive if specified) | `value: lazagne.exe` |
| `contains` | String contains substring | `value: lazagne` |
| `starts with` | String starts with value | `value: C:\Users\` |
| `ends with` | String ends with value | `value: .exe` |
| `exists` | Field exists in event | `path: event/HASH` |
| `and` | All conditions must be true | Nested rules |
| `or` | Any condition must be true | Nested rules |
| `>` / `<` | Greater/less than (numeric) | Event counts |

**Case sensitivity**: Set `case sensitive: false` to ignore capitalization differences (e.g., `LAZAGNE.exe`, `lazagne.exe`, `LaZagne.exe` all match).

##### 4) Configure the Respond Block

**Remove template response actions** and replace with:

```yaml
respond:
  - action: report
    metadata:
      author: sjain
      description: TEST - Detects Lazagne Usage
      falsepositives: Unknown
      level: medium
      tags:
        - attack.credential_access
    name: sjain - HackTool - Lazagne  
```

**Field explanations**:

- **action: report**: Generate detection alert (visible in Detections tab)
- **metadata**: Descriptive information about the rule
  - **author**: Rule creator (your identifier)
  - **description**: What the rule detects and project context
  - **falsepositives**: Known scenarios that may trigger false alerts
  - **level**: Severity (low/medium/high/critical)
  - **tags**: MITRE ATT&CK technique or custom categorization
- **name**: Unique rule identifier (use descriptive naming convention)

<p align="center">
<img src="assets/screenshots/12.Lazagne-D&R-Rule-Detailed.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-12: Lazagne D&R Rule in Detail</em>
</p>

##### 5) Save the Rule

1. **Rule name**: `sjain-lazagne-SOAR-EDR`
2. Click **Save** (bottom-right)
3. Rule appears in **D&R Rules** list

<p align="center">
<img src="assets/screenshots/13.Lazagne-D&R-Rule.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-13: Lazagne D&R Rule Created in LimaCharlie</em>
</p>

### ✅ Test the Detection Rule

#### 1) Test Event Functionality

**LimaCharlie built-in testing**:

1. In the D&R rule editor, click **Target Event** tab
2. **Obtain test event**:
   - Navigate to **Sensors** → **Sensors List** → Your sensor → **Timeline**
   - Search for `lazagne`
   - Click the **NEW_PROCESS** event
   - Click **Copy** (copies entire JSON event)
3. Return to D&R rule → **Target Event** tab
4. **Paste** the JSON event
5. Click **Test Event** (bottom)

**Expected result**:

```text
✓ Four operations were evaluated with the following results:
  ✓ true
  ✓ true
  ✓ true
  ✓ true
All conditions passed (green checkmarks)
```

**Interpretation**:

- Each detection method (file path, command line with "all", command line contains "lazagne", hash match) evaluated successfully
- Rule logic is correct and will trigger on matching events

#### 2) Generate Live Detection

**On Windows machine**:

1. Open PowerShell in Downloads folder
2. Execute Lazagne again:

   ```powershell
     .\lazagne.exe all
   ```

3. Wait ~10-30 seconds for event processing

**Verify detection in LimaCharlie**:

1. Navigate to **Detections** tab (left sidebar)
2. **If detections exist from previous testing**:
   - Click **Delete All** (top-right) → Confirm
3. Refresh page
4. **Expected result**: New detection appears
   - **Rule name**: `mydfir-hack-tool-lazagne-soar-edr`
   - **Timestamp**: Recent (within last minute)
   - **Severity**: Medium
   - **Host**: Your machine name

5. **Click detection** to view details:
   - **Event metadata**:
     - Command line: `lazagne.exe all`
     - File path: `C:\Users\Administrator\Downloads\lazagne.exe`
     - Hash: `<SHA256>`
     - Hostname: Your machine
     - External IP address: Your public IP
     - Internal IP address: Private IP (if applicable)
     - Sensor ID: LimaCharlie sensor identifier
   - **Link to detection**: Direct link to event in Timeline

<p align="center">
<img src="assets/screenshots/14.Alerts-generated-in-LCA.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-14: Alert generated in LimaCharlie</em>
</p>

---

## Part 4 — Slack Setup & Tines Integration

**Objective**: Set up Slack workspace and Tines SOAR platform, configure webhook integration between LimaCharlie and Tines, and verify detection data flow.

### 🎯 Overview

In this part, we will:

- Create and configure a Slack workspace with dedicated alerts channel
- Set up Tines SOAR platform account
- Establish webhook connection between LimaCharlie and Tines
- Verify that detections from LimaCharlie appear in Tines
- Prepare foundation for automation playbook (Part 5)

### 💬 Slack Setup

#### 1) Create Slack Account

**Sign Up Process**:

1. Navigate to [slack.com](https://slack.com)
2. Click **Get Started for Free** button
3. **Enter email address**:
   - Use valid email (confirmation code will be sent)
   - Work email recommended but not required for lab
4. **Check email** for confirmation code
5. Enter confirmation code
6. Click **Create an Account**

#### 2) Create Workspace

**Workspace Configuration**:

1. **Workspace Name**:
   - Enter: `sjain-projects`
   - Or custom name of your choice
   - Click **Next**

2. **Your Name**:
   - Enter your display name
   - Example: `SOC Analyst` or your actual name
   - Click **Next**

3. **Invite Team Members**:
   - Click **Skip this step** (not needed for lab)
   - Confirm: **Skip without inviting**

4. **What's your team working on?**:
   - Enter: `The best project` (or any description)
   - Click **Next**

5. **Choose Plan**:
   - Select **Start with Free**
   - Free plan is sufficient for this lab

**Workspace Created**:

- You're now in your Slack workspace
- Default channel: `#general` already exists

#### 3) Create Alerts Channel

**Purpose**: Dedicated channel for receiving automated security alerts from Tines.

**Create Channel**:

1. In Slack workspace, locate left sidebar
2. Click **Add channels** (or **+** next to Channels)
3. Select **Create a new channel**
4. **Channel Configuration**:
   - **Name**: `alerts_tines`
   - **Description** (optional): `Automated security alerts from SOAR platform`
   - **Visibility**:
     - ☑️ **Public** (recommended for lab)
     - Team members can find and join
5. Click **Create**
6. **Add people**:
   - Click **Skip for now** (not needed for single-user lab)

**Channel Created**:

- New channel `#alerts_tines` appears in left sidebar
- This will be the destination for automated notifications

**Why a Dedicated Channel?**

- Separates automated alerts from general communication
- Easier to monitor and track security events
- Mimics real SOC operational structure
- Prevents alert fatigue in main channels

#### 4) Create Slack Bot App

**Purpose**: Slack bot allows Tines to post messages to channels programmatically via API.

**Create Bot App**:

1. Navigate to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App**
3. **Choose creation method**:
   - Select **From scratch**
4. **App Configuration**:
   - **App Name**: `Tines-LMC-Alerts`
   - **Pick a workspace**: Select `sjain-projects` (your workspace)
5. Click **Create App**

**Configure Bot Permissions**:

1. In app settings, navigate to **OAuth & Permissions** (left sidebar)
2. Scroll to **Scopes** section
3. Under **Bot Token Scopes**, click **Add an OAuth Scope**
4. **Add required scopes**:
   - `chat:write` - Allows bot to post messages
   - `chat:write.public` - Allows posting to public channels without being invited
   - `channels:read` - Allows bot to view channel information
5. Scopes added confirmation

**Install Bot to Workspace**:

1. Scroll to top of **OAuth & Permissions** page
2. Click **Install to Workspace** button
3. **Review permissions**: Confirm bot will have access to:
   - Post messages to channels
   - View public channel information
4. Click **Allow**
5. **Bot User OAuth Token** generated
   - Format: `xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX`
   - Click **Copy** to save token (needed for Tines integration in Part 5)
   - ⚠️ **Store securely**: Treat like a password

**Add Bot to Alerts Channel**:

1. Return to Slack workspace
2. Navigate to `#alerts_tines` channel
3. In channel, type: `/invite @Tines-LMC-Alerts`
4. Press Enter
5. **Confirmation**: Bot appears in channel member list
6. Alternative method:
   - Click channel name → **Integrations** tab
   - Click **Add apps** → Search `Tines-LMC-Alerts` → **Add**

**Bot Configuration Summary**:

| Setting | Value |
|---------|-------|
| **Bot Name** | `Tines-LMC-Alerts` |
| **Workspace** | `sjain-projects` |
| **Scopes** | `chat:write`, `chat:write.public`, `channels:read` |
| **Installed In** | `#alerts_tines` channel |
| **OAuth Token** | `xoxb-...` (saved securely) |

<p align="center">
<img src="assets/screenshots/15.tines-lmc-alerts-app.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-15: Tines LMC Alerts Bots App</em>
</p>
  
<p align="center">
<img src="assets/screenshots/16.slack-setup.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-16: Bot added in the workspace and in channel</em>
</p>

### 🔧 Tines Setup

#### 1) Create Tines Account

**Sign Up Process**:

1. Navigate to [tines.com](https://www.tines.com)
2. Click **Sign Up Now**
3. **Sign-up options**:
   - **Work email** (enter email address)
   - Or: **Sign up with Google**
   - Or: **Sign up with Microsoft**
4. **Email verification**:
   - Check inbox for confirmation email
   - Click verification link
   - Return to Tines login page
5. **Login** with your credentials

**Note**: Use valid email address as Tines requires email verification for account activation.

#### 2) Initial Dashboard Tour

**Welcome Screen**:

Upon first login, you'll see:

- **Example story/workflow** (sample automation)
- **Dashboard** with navigation
- **Tour guide** (optional walkthrough)

**Close Tutorial** (if desired):

1. Click **X** to exit example workflow
2. Click **End Tour** to skip guided tutorial

**Result**: Clean workspace ready for building custom automation.

#### 3) Explore Tines Interface

**Left Sidebar - Actions**:

Available building blocks for automation:

| Action Type | Description | Use Case |
|-------------|-------------|----------|
| **Webhook** | Receive HTTP requests | Trigger from external systems (LimaCharlie) |
| **HTTP Request** | Make API calls | Interact with external services |
| **Email** | Send/receive emails | Notify analysts |
| **Trigger** | Schedule or event-based start | Periodic checks or external events |
| **Event Transform** | Manipulate data | Parse JSON, extract fields |
| **Send to Story** | Chain workflows | Modular automation design |

**Using Actions**:

1. **Drag and drop** actions from left sidebar to canvas (storyboard)
2. **Click action** to configure on right panel
3. **Connect actions** by clicking and dragging between nodes
4. **Delete actions** by selecting and pressing Delete key

**Templates Section**:

Pre-built integrations available:

**Example**: VirusTotal Integration

1. Click **Templates** (left sidebar)
2. Search: `virustotal`
3. Drag **VirusTotal** template to canvas
4. **Available actions**:
   - Search for file hash
   - Get file behavior report
   - Submit URL for scanning
5. **Configuration**: Right panel shows required inputs (API key, hash value, etc.)

**Story Libraries**:

Community-contributed automation workflows:

**Example**: Block Domain in Zscaler

1. Click **Story Libraries** (left sidebar)
2. Browse available stories
3. **Example**: "Add domain to block list in Zscaler"
4. Click story → **Import**
5. Pre-built workflow loads into your workspace
6. Customize as needed

**Tools Section**:

- **Page**: Organize complex workflows across multiple pages
- **Group**: Visually group related actions
- **Note**: Add documentation and comments to workflows

**Navigation**:

- **Tines icon** (top-left): Return to main dashboard
- **Settings icon**: Account preferences
- **User menu**: Profile settings, dark mode, logout

#### 4) Configure Dark Mode (Optional)

**Enable Dark Mode** (easier on eyes for extended use):

1. Click **your name/profile icon** (top-right)
2. Select **Dark Mode** from dropdown
3. Interface switches to dark theme

**Return to Story**:

- Click **Tines icon** (top-left) to return to dashboard
- Select your story to continue building

### 🔗 Establish LimaCharlie → Tines Connection

### Understanding the Integration

**Data Flow**:

```text
LimaCharlie Detection
        ↓
    (Webhook)
        ↓
  Tines Receives
        ↓
Automation Begins
```

**Purpose**:

- LimaCharlie generates detection when Lazagne executes
- Detection data sent to Tines via webhook
- Tines triggers automated response playbook

### 1) Create Webhook in Tines

**Start with Clean Canvas**:

1. In your Tines story, **delete any existing actions**:
   - Select example weather app → Press Delete
   - Select send email action → Press Delete
   - Confirm: Canvas is empty

**Add Webhook Action**:

1. From left sidebar, drag **Webhook** action to canvas
2. Click webhook action to configure (right panel opens)
3. **Configuration**:
   - **Name**: `Retrieve Detections`
   - **Description**: `Retrieve LimaCharlie detections`
   - Leave other settings as default
4. **Webhook URL** (generated automatically):
   - Displays as: `https://TENANT.tines.com/webhook/UNIQUE_ID/WEBHOOK_NAME`
5. **Copy webhook URL** (click copy icon or select and copy)

**Webhook Created**:

- This URL will receive HTTP POST requests from LimaCharlie
- Each detection triggers a new event in this webhook

### 2) Configure LimaCharlie Output

**Purpose**: Send detections from LimaCharlie to Tines webhook.

**Navigate to Outputs**:

1. Open LimaCharlie web interface in new tab
2. Navigate to your organization dashboard
3. Click **Outputs** (left sidebar)
4. Click **Add Output** (top-right button)

**Select Output Type**:

Available output types:

- **Events**: All sensor events (high volume)
- **Detections**: Only detection rule alerts (⭐ what we need)
- **Deployments**: Sensor deployment events
- **Audit Logs**: Administrative actions
- **Artifacts**: Collected forensic data
- **Tailored**: Custom filtered events

**Choose Detections**:

1. Click **Detections** tile
2. Description: "A stream of detections reported by the rule engine"
3. Click **Select**

**Choose Destination**:

Available destinations:

- Amazon S3
- CrowdStrike Falcon
- Azure
- Datadog
- Elastic
- **Tines** ⭐
- Webhook (generic)
- Slack
- And many others

**Select Tines**:

1. Scroll through destinations
2. Click **Tines**
3. **Configuration**:
   - **Name**: `sjain-SOAR-EDR`
   - **Destination Host**: Paste Tines webhook URL
     - Example: `https://mydfir.tines.com/webhook/a1b2c3d4e5f6/retrieve_detections`
4. Click **Save Output**

**Output Created**:

- Confirmation message: "Configuration saved"
- Warning: "We couldn't detect any recent samples moving through this output"
  - This is expected - no detections have occurred yet

<p align="center">
<img src="assets/screenshots/17.LMC-outputs.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-17: Output created in Limacharlie</em>
</p>

<p align="center">
<img src="assets/screenshots/18.LMC-outputs-detailed.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-18: Link to Tines webhook pasted in Limacharlie</em>
</p>

### 3) Test the Connection

**Generate Detection Event**:

**On Windows machine**:

1. Open PowerShell in Downloads folder
2. Execute Lazagne:

   ```powershell
     .\lazagne.exe all
   ```

3. Wait 10-30 seconds for detection processing

**Verify in LimaCharlie**:

1. Navigate to **Outputs** page
2. Click **Refresh** button (top-right)
3. **Expected result**: Recent sample detected
   - Shows detection event that was sent to Tines
   - Displays: `mydfir-hack-tool-lazagne` (or your detection rule name)
   - Timestamp: Recent (within last minute)

**Detection Sent Confirmation**:

- LimaCharlie successfully forwarded detection to Tines
- Output shows recent activity

<p align="center">
<img src="assets/screenshots/19.alert-generated.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-19: Alert generated in Limacharlie</em>
</p>

### 4) Verify in Tines

**Check Webhook Events**:

1. Return to Tines browser tab
2. Click on **Retrieve Detections** webhook action
3. Right panel displays **Events** tab
4. **Recent Events** section shows received data

**View Detection Data**:

1. **Events list**: Most recent event appears first
2. Click **first event** (top of list) to expand
3. **Body section**: Contains full detection JSON payload

**Example Detection Data**:

```json
{
  "routing": {
    "hostname": "mydfir-soar-edr",
    "sid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "ext_ip": "203.0.113.45",
    "int_ip": "192.168.1.100"
  },
  "detect": {
    "event_time": 1234567890,
    "detect_id": "detection-uuid",
    "cat": "attack.credential_access",
    "detect_mtd": {
      "name": "mydfir-hack-tool-lazagne-soar-edr",
      "author": "mydfir",
      "description": "Detects Lazagne (SOAR-EDR tool)",
      "level": "medium"
    }
  },
  "event": {
    "FILE_PATH": "C:\\Users\\Administrator\\Downloads\\lazagne.exe",
    "COMMAND_LINE": "lazagne.exe all",
    "HASH": "abc123def456...",
    "USER_NAME": "Administrator"
  }
}
```

**Key Fields Available**:

| Field Path | Description | Use in Playbook |
|------------|-------------|-----------------|
| `routing.hostname` | Computer name | Identify affected machine |
| `routing.ext_ip` | External IP | Geolocation/threat intel |
| `routing.sid` | Sensor ID | API calls to LimaCharlie |
| `detect.event_time` | Detection timestamp | Alert timing |
| `detect.detect_mtd.name` | Rule name | Alert identification |
| `event.FILE_PATH` | Executable path | Forensic analysis |
| `event.COMMAND_LINE` | Command executed | TTPs identification |
| `event.HASH` | File hash | IOC enrichment |
| `event.USER_NAME` | User account | Identity context |

**Expand Detection Details**:

1. Click **Body** to expand JSON
2. Click **detect** → **event** to see full event details
3. Verify all expected fields are present:
   - ✅ Command line
   - ✅ File path
   - ✅ Hash
   - ✅ Username

**Success Confirmation**:

- Detection data flows correctly from LimaCharlie → Tines
- All required fields available for automation
- Ready to build playbook in Part 5

<p align="center">
<img src="assets/screenshots/20.webhook-receiving-alerts.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-20: Webhook in Tines receiving the Alert from Limacharlie</em>
</p>

---

## Part 5 — SOAR Playbook Automation & Endpoint Isolation

**Objective:**  
Build the final automation playbook in **Tines** that connects **LimaCharlie (EDR)** with **Slack** and **Email**, prompts the analyst for a decision, and automatically isolates an endpoint if approved.

---

### Overview

In this final part, we will:

- Review the previously created workflow  
- Connect **Tines ↔ Slack** for automated messaging  
- Configure **Email** notifications inside Tines  
- Add a **User Prompt** (Yes/No Isolation)  
- Automate **machine isolation** via **LimaCharlie API**  
- Validate end-to-end automation with testing  

---

### 🧩 1. Workflow Review

The existing setup already detects a hack-tool execution using LimaCharlie.  
Detection events are sent to **Tines** via webhook, which now must:

1. Send alert details to **Slack #alerts** channel  
2. Email the same details to the analyst  
3. Ask whether to isolate the host  
4. If “Yes,” instruct LimaCharlie to isolate the endpoint  
5. If “No,” post a “not isolated” notification in Slack  

---

### 💬 2. Connect Tines and Slack

#### Steps

1. In Tines Dashboard → **Team → Credentials → New Credential → Slack**  
2. Approve connection  
3. Confirm Slack credential appears  

#### Test integration

- In Tines Story, drag **Slack → Send Message** action  
- Paste your channel ID (`#alerts`) under *Channel / User ID*  
- **Message:**

```json
{
  "Title": "<<retrieve_detections.body.cat>>",
  "Time": "<<retrieve_detections.body.detect.routing.event_time>>",
  "Computer": "<<retrieve_detections.body.detect.routing.hostname>>",
  "Source IP": "<<retrieve_detections.body.detect.routing.int_ip>>",
  "Username": "<<retrieve_detections.body.detect.event.USER_NAME>>",
  "File Path": "<<retrieve_detections.body.detect.event.FILE_PATH>>",
  "Command Line": "<<retrieve_detections.body.detect.event.COMMAND_LINE>>",
  "Sensor ID": "<<retrieve_detections.body.detect.routing.sid>>",
  "Detection Link": "<<retrieve_detections.body.link>>"
}
```

- Click **Run → Test**  

✅ Message appears instantly in Slack → integration confirmed  

<p align="center">
<img src="assets/screenshots/21.slack-confirmation.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-21: Slack message confirmation</em>
</p>

---

### ✉️ 3. Configure Email Notifications in Tines

1. Add **Send Email** action to storyboard  
2. Description: `Send Detection Email`  
3. Example configuration:  
   - **To:** temporary test email (e.g., `squirrelx@temp.com`)  
   - **From Name:** `Alerts`  
   - **Subject:** `New Detection Event`  
   - **Body:**

```html
<br> Title : <<retrieve_detections.body.cat>>
<br> Time : <<retrieve_detections.body.detect.routing.event_time>>
<br> Computer : <<retrieve_detections.body.detect.routing.hostname>>
<br> Source IP : <<retrieve_detections.body.detect.routing.int_ip>>
<br> Username : <<retrieve_detections.body.detect.event.USER_NAME>>
<br> File Path : <<retrieve_detections.body.detect.event.FILE_PATH>>
<br> Command Line : <<retrieve_detections.body.detect.event.COMMAND_LINE>>
<br> Sensor ID : <<retrieve_detections.body.detect.routing.sid>>
<br>
<br> Detection Link : <<retrieve_detections.body.link>>
```

4. Click **Run → Test** to validate  

✅ Email received → notification system operational  

<p align="center">
<img src="assets/screenshots/22.email-confirmation.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-22: Email Confirmation</em>
</p>

---

### 🧭 4. Create User Prompt (Analyst Decision)

Use **Page** tool to prompt the analyst for action.

Steps

1. Drag **Page** into Story → Name: `User Prompt`  
2. Description: `Isolate Computer (Yes/No)`  
3. Behavior: "Show Success Message" → `Thank you, you can close this window.`  
4. Add a Boolean Field: `isolate`  
5. Prepend alert details for context (Time, Computer, Source IP, User, File Path, Command Line, Sensor ID, Detection Link)  

When triggered, analyst sees alert summary and chooses **Yes** or **No**.  

  <p align="center">
  <img src="assets/screenshots/23.user-prompt.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-23: User Prompt Confirmation</em>
  </p>

### ⚙️ 5. Conditional Logic – “No” Path

**Scenario:** The analyst decides **not** to isolate the endpoint.

Steps

1. Add a **Trigger** action → Condition:

   ```text
        user_prompt.body.do_you_want_to_isolate_the_machine
    ```

2. Connect this trigger to a **Slack → Send Message** action.
3. Configure the Slack message as:

   ```text
        The Computer <<retrieve_detections.body.detect.routing.hostname>> was not isolated, please investigate.
   ```

4. Save and test the flow.

✅ When the analyst selects **No**, a Slack message immediately appears confirming the endpoint was *not* isolated and further investigation is required.

---

### 🔒 6. Conditional Logic – “Yes” Path + Isolation Action

**Scenario:** The analyst selects **Yes** to isolate the compromised machine.

Steps

1. Add a **Trigger** action → Condition:

   ```text
        user_prompt.body.do_you_want_to_isolate_the_machine
    ```

2. Drag in a **LimaCharlie → Isolate Sensor** action.
3. In the **URL** field, input:

    ```text
        https://api.limacharlie.io/v1/<<retrieve_detections.body.detect.routing.sid>>/isolation
    ```

4. Configure **LimaCharlie API Credentials**:
   - In LimaCharlie: navigate to **Access Management → REST API → Organization API Key** and copy the JWT key.
   - In Tines: **Credentials → New → Text**

     ```text
         Name: LimaCharlie API
         Domain: *.limacharlie.io
         Value: <your JWT API key>
     ```

     Connect this credential to the **Isolate Sensor** action.

5. Test by running the playbook.

✅ Result: HTTP Status **200 OK** confirms successful isolation of the endpoint. LimaCharlie dashboard shows **Isolated: True**.

<p align="center">
<img src="assets/screenshots/24.successful-isolation.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-24: Successful Isolation</em>
</p>

---

### 🧪 7. Validation Test

#### Step-by-Step Validation

**Before Isolation:**

- Run `ping <hostname>` → The endpoint responds normally.

**After Isolation:**

- Run `ping <hostname>` → Returns:

   ```text
        General failure.
    ```

- Same as before, in LimaCharlie, refresh the **Sensors** tab — the endpoint appears as **Isolated True**.

✅ Validation confirms that the automation performed endpoint isolation successfully.

<p align="center">
<img src="assets/screenshots/25.ping-failure.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-25: Ping Failure</em>
</p>

<p align="center">
<img src="assets/screenshots/26.connection-lost.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-26: RDP Connection Lost</em>
</p>

---

### 📡 8. Post-Isolation Notification

Once the machine is isolated, notify the analyst.

Steps

1. Add **Get Isolation Status** (LimaCharlie template).
2. Chain a **Slack → Send Message** action.
3. Message format:

    ```text
        Isolation Status: <<get_isolation_status.body.is_isolated>> 
        The Computer <<retrieve_detections.body.detect.routing.hostname>>has been isolated.
    ```

4. Test with a recent isolation event.

✅ Slack notification confirms the isolation status (e.g., `true`).

<p align="center">
<img src="assets/screenshots/27.slack-isolation-message.png" alt="Network Diagram" width="700"/><br>
<em>📸 Figure-27: Slack Isolation Status</em>
</p>

---

### 🔁 9. Final Playbook Flow

```yaml
    LimaCharlie Detection
           ↓
    Tines Webhook (Receive Event)
           ↓
    Send to Slack + Send Email
           ↓
    User Prompt (Yes/No Isolation)
           ↓
    If No → Slack ‘Not Isolated’ Message
    If Yes → LimaCharlie Isolate → Get Status → Slack ‘Isolation Success’
```

✅ All automation stages tested and verified successfully.

  <p align="center">
  <img src="assets/screenshots/28.tines-workflow.png" alt="Network Diagram" width="700"/><br>
  <em>📸 Figure-28: Tines Workflow</em>
  </p>

---

## ⚠️ Troubleshooting Log (issues encountered & resolutions)

### ⚠️ Issue 1: No Events Appearing in Tines Webhook

**Symptoms:**

- Tines webhook shows “No events”
- LimaCharlie output shows no recent samples  

**Cause:**

- Detection not generated in LimaCharlie  
- Webhook URL misconfigured  
- Network connectivity issue  

**Fix:**

1. Verify output configuration  
   - LimaCharlie → Outputs → Check if Tines output exists  
   - Confirm webhook URL is correct  
2. Regenerate detection:

   ```powershell
   cd Downloads
   .\lazagne.exe all

3. Check detection rule in LimaCharlie → Detections → Verify rule triggered

4. Ensure Windows machine and sensor have internet access

### ⚠️ Issue 2: Webhook URL Not Working

**Symptoms:**

- Error: “Invalid webhook URL”

**Cause:**

- Missing `https://` or extra spaces  
- Unverified Tines account  

**Fix:**

1. Copy URL again from **Tines → Webhook → Copy URL**  
2. Paste into a text editor and remove spaces  
3. Ensure Tines account is verified  

---

### ⚠️ Issue 3: Incomplete Detection Data in Tines

**Symptoms:**

- Missing fields or null values  

**Cause:**

- Rule not capturing all fields  
- Event type mismatch  

**Fix:**

1. Review detection in **LimaCharlie → Detections → Confirm full JSON**  
2. Update D&R rule:

   ```yaml
   detect:
     events:
       - NEW_PROCESS
       - EXISTING_PROCESS
3. Regenerate detection:

    ```powershell
        .\lazagne.exe all
    ```

### ⚠️ Issue 4: Slack Workspace Setup Issues

**Symptoms:**

- Confirmation email not received  
- Workspace creation error  

**Fix:**

1. Check spam folder for Slack confirmation email  
2. Use a different email provider (e.g., Gmail or Outlook)  
3. Clear browser cache or use **Incognito mode**  

---

### ⚠️ Issue 5: Tines Credential Not Appearing in Dropdown

**Symptoms:**

- “No credentials available” message in action configuration  

**Fix:**

1. Refresh browser or log out and back in  
2. If not visible → Create a new story and recreate webhook  
3. Verify credential scope — ensure **Domains include `slack.com`**

### ⚠️ Issue 6: LimaCharlie Isolation API 401 Error

**Symptoms:**

- “Invalid JWT” error in Tines but works in Python  

**Cause:**

- Hidden control characters (`\x05`) in token  
- Typo in domain (e.g., `limacharlio.io`)  

**Fix:**

1. **Clean JWT token:**

   ```python
   import requests

   JWT_TOKEN = """PASTE_TOKEN_HERE"""
   clean_token = JWT_TOKEN.strip().replace('\n', '').replace(' ', '')
   print(clean_token)

2. Fix domain:

    - Change from *.limacharlio.io →*.limacharlie.io

3. Recreate credential with clean token (Text type):

    - Paste the cleaned token
    - Update workflow to use the new credential

4. Alternative method:

    - Use direct HTTP POST action with Bearer token

5. Check token expiry:

    - Navigate to Access Management → REST API
    - Verify if token is expired and refresh if necessary

### ⚠️ Issue 7: Email Formatting Issue

**Symptoms:**

- Email body appears as a single line

**Cause:**

- HTML rendering without `<br>` tags

**Fix (HTML Format):**

```html
Title: {{retrieve_detections.body.detect.cat}}<br>
Time: {{retrieve_detections.body.detect.event_time}}<br>
Computer: {{retrieve_detections.body.routing.hostname}}<br>
Source IP: {{retrieve_detections.body.routing.int_ip}}<br>
Username: {{retrieve_detections.body.event.USER_NAME}}<br>
File Path: {{retrieve_detections.body.event.FILE_PATH}}<br>
Command Line: {{retrieve_detections.body.event.COMMAND_LINE}}<br>
Sensor ID: {{retrieve_detections.body.routing.sid}}<br><br>
Detection Link: {{retrieve_detections.body.detect.link}}
```

---

## 🧠 Key Learnings

1. **EDR Configuration and Management**  
   Gained hands-on experience deploying LimaCharlie EDR sensors, building and validating YAML-based D&R rules, and analyzing endpoint telemetry.  
   *Practical Application:* Tuned detections, investigated command-line behaviors, and executed remote containment actions efficiently.

2. **SOAR Platform Implementation**  
   Designed automated workflows in Tines integrating LimaCharlie, Slack, and Email using webhooks, triggers, and conditional logic.  
   *Practical Application:* Built end-to-end playbooks with analyst approval steps to streamline alert triage and response.

3. **Detection & Response Automation**  
   Implemented Slack and Email alert automation with approval gates, enabling seamless analyst-driven isolation of compromised systems.  
   *Practical Application:* Reduced mean time to respond (MTTR) through near real-time automated containment.

4. **Security Tool Integration**  
   Established interoperability across LimaCharlie, Tines, and Slack through secure API authentication and JSON data mapping.  
   *Practical Application:* Built scalable, vendor-agnostic automation pipelines for cohesive SOC operations.

5. **Incident Response Procedures**  
   Followed a structured workflow from detection to notification and isolation while preserving critical evidence.  
   *Practical Application:* Executed incident response playbooks end-to-end, ensuring timely communication and documentation.

6. **Technical Troubleshooting**  
   Diagnosed complex API and authentication errors, including JWT token corruption and 401 issues, and validated data flow integrity.  
   *Practical Application:* Demonstrated the ability to independently debug, test, and fix real-world SOAR/EDR integration problems.

7. **Detection Engineering**  
   Simulated attacker activity using LaZagne to craft behavioral process-based detections aligned with MITRE ATT&CK techniques.  
   *Practical Application:* Authored and tuned detection logic to balance precision and false positive reduction.

---

## 🔗 References & Resources

- [YouTube Series Part 1](https://youtu.be/OirFGI-34Ko?si=bWwyP2o1-xXAWkIP) – Creating a Logical Diagram
- [YouTube Series Part 2](https://youtu.be/WPyJR7Y3qb4?si=1cBFQF1eGW7GhaAg) – Install and configure LimaCharlie on a Windows VM, enroll the sensor, verify telemetry, and explore console features to prepare for building detection-and-response rules.
- [YouTube Series Part 3](https://youtu.be/sLNYileYwD8?si=qZJCtnBDXUKWem0y) – Generate telemetry using the LaZagne password recovery tool and create a custom LimaCharlie Detection and Response rule to identify its activity, preparing for automation with Tines in the next phase.
- [YouTube Series Part 4](https://youtu.be/uI-ueDf_3hg?si=4lKWM-Tw7uSafBu2) - Sets up Slack and Tines, links LimaCharlie detections to Tines via a webhook, verifies real-time alert ingestion, and prepares for automated SOAR playbook creation in the final part.
- [YouTube Series Part 5](https://www.youtube.com/watch?v=RR4tfMMkIPY&list=PLGrcVHQv6mp_w5zrB18h2jY44skXnzxSh&index=6) - SOAR-EDR Playbook—sending alerts to Slack and email, prompting isolation approval, and automatically isolating the endpoint via LimaCharlie, completing the end-to-end detection-to-response automation.
