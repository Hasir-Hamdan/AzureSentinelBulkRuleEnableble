# 🚀 Bulk Enable Microsoft Sentinel Analytics Rules with Python

This script allows you to **automate enabling all analytics rules** in Microsoft Sentinel by content pack (solution name) instead of clicking them one-by-one in the Azure portal.

## 📌 Overview

Manually enabling rules from the Content Hub in Sentinel can be repetitive and time-consuming — especially for packs like "Network Session Essentials" or "Azure Activity" that contain dozens of rules.

This Python script takes care of that by:
- Authenticating to Azure using `DefaultAzureCredential`
- Identifying and deploying all Analytics Rules associated with a given solution name
- Enabling those rules automatically

## 🖼️ Screenshots

![Sentinel Bulk Rule Enable Screenshot](https://github.com/Hasir-Hamdan/AzureSentinelBulkRuleEnableble/blob/main/assets/1.png?raw=true)

---

## 💻 Setting Up the Environment (Windows)

### Step 1: Install Azure CLI

Download and install Azure CLI from Microsoft’s official site:  
👉 [Install Azure CLI on Windows](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows)

### Step 2: Install Python (if not already installed)

Download from: [https://www.python.org/downloads/windows](https://www.python.org/downloads/windows)  
Ensure `pip` is installed (it usually is by default in recent versions of Python).

### Step 3: Install Required Python Modules

Open a terminal (Command Prompt or PowerShell) and run:

```bash
pip install azure-identity azure-mgmt-securityinsight azure-mgmt-resource requests
```

## 🔐 Authenticate to Azure
Login to your Azure account using:
```
az login
```
📥 Get Azure Metadata
Use these commands to retrieve essential information:

🔑 Get Subscription ID:
```
az account show --query id --output tsv
```
📦 List Resource Groups:
```
az group list --output table
```
🧠 List Log Analytics Workspaces
```
az monitor log-analytics workspace list --output table
```

## ▶️ Script Usage
```
python RuleAll.py -sub <SUBSCRIPTION_ID> -rg <RESOURCE_GROUP> -ws <WORKSPACE_NAME> -sn <SOLUTION_NAME> -e
```
✅ Example:
```
python RuleAll.py -sub 12345678-90ab-cdef-1234-567890abcdef -rg MyResourceGroup -ws MySentinelWorkspace -sn "Azure Activity -e"
```
![Sentinel Bulk Rule Enable Screenshot](https://github.com/Hasir-Hamdan/AzureSentinelBulkRuleEnableble/blob/main/assets/2.png?raw=true)

![Sentinel Bulk Rule Enable Screenshot](https://github.com/Hasir-Hamdan/AzureSentinelBulkRuleEnableble/blob/main/assets/3.png?raw=true)


### Credits:

Huge thanks to @FJMDR for the original version.
https://github.com/FJMDR/SentinelBulkRuleEnable/tree/main?tab=readme-ov-file
This is a slightly modified version with better CLI support and user feedback improvements.
