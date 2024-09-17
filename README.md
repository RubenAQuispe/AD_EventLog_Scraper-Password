# Active Directory Event Log Scraper

This PowerShell script retrieves account lockout, password change, and password reset events from all domain controllers in the Active Directory domain. It then exports the collected data to a CSV file for review.

## Features

- Collects the following event types from domain controllers:
  - **4723**: An attempt to change an account's password
  - **4724**: An attempt to reset an account's password
  - **4740**: A user account was locked out
- Gathers event data from all domain controllers in the domain
- Exports the results to a CSV file located at `C:\Temp\AccountEvents_AllDCs.csv`
  
## Requirements

- PowerShell with the **Active Directory** module installed
- Administrative privileges to run the script

## How to Install

1. Ensure that the **Active Directory** module is installed. If it's not, run the following command to install it:
   ```powershell
   Install-WindowsFeature -Name "RSAT-AD-PowerShell"
