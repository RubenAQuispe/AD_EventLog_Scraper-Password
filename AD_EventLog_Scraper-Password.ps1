# Import the Active Directory module
Import-Module ActiveDirectory

# Get a list of all domain controllers in the domain
$DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

# Define the event IDs for account lockouts and password changes/resets
$EventIDs = @(4723, 4724, 4740)

# Calculate the time 24 hours ago from now
$StartTime = (Get-Date).AddHours(-24)

# Initialize an array to store the extracted information
$Output = @()

foreach ($DC in $DomainControllers) {
    Write-Host "Processing Domain Controller: $DC"

    try {
        # Retrieve events from the Security log of the current domain controller
        $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
            LogName   = 'Security';
            ID        = $EventIDs;
            StartTime = $StartTime
        }

        foreach ($Event in $Events) {
            # Parse the event XML to extract detailed information
            $EventXml = [xml]$Event.ToXml()

            # Extract common fields
            $TimeCreated = $Event.TimeCreated
            $EventID     = $Event.Id
            $Message     = $Event.FormatDescription()

            # Initialize variables for additional fields
            $SubjectSecurityID     = ''
            $SubjectAccountName    = ''
            $SubjectAccountDomain  = ''
            $SubjectLogonID        = ''
            $TargetSecurityID      = ''
            $TargetAccountName     = ''
            $TargetAccountDomain   = ''
            $CallerComputerName    = ''
            $Privileges            = ''

            # For debugging: Get all data fields and their names
            $EventDataFields = @{}
            foreach ($DataItem in $EventXml.Event.EventData.Data) {
                $EventDataFields[$DataItem.Name] = $DataItem.'#text'
            }

            # Extract data based on Event ID
            if ($EventID -eq 4723 -or $EventID -eq 4724) {
                # An attempt was made to change or reset an account's password
                $SubjectSecurityID    = $EventDataFields['SubjectUserSid']
                $SubjectAccountName   = $EventDataFields['SubjectUserName']
                $SubjectAccountDomain = $EventDataFields['SubjectDomainName']
                $SubjectLogonID       = $EventDataFields['SubjectLogonId']
                $TargetSecurityID     = $EventDataFields['TargetUserSid']
                $TargetAccountName    = $EventDataFields['TargetUserName']
                $TargetAccountDomain  = $EventDataFields['TargetDomainName']
                $Privileges           = $EventDataFields['PrivilegeList']
            }
            elseif ($EventID -eq 4740) {
                # A user account was locked out
                $SubjectSecurityID    = $EventDataFields['SubjectUserSid']
                $SubjectAccountName   = $EventDataFields['SubjectUserName']
                $SubjectAccountDomain = $EventDataFields['SubjectDomainName']
                $SubjectLogonID       = $EventDataFields['SubjectLogonId']
                $TargetSecurityID     = $EventDataFields['TargetUserSid']
                $TargetAccountName    = $EventDataFields['TargetUserName']
                $CallerComputerName   = $EventDataFields['CallerComputerName']

                # 'TargetDomainName' may not be present; use 'SubjectAccountDomain' if missing
                if ($EventDataFields.ContainsKey('TargetDomainName')) {
                    $TargetAccountDomain = $EventDataFields['TargetDomainName']
                }
                else {
                    $TargetAccountDomain = $SubjectAccountDomain
                }
            }

            # Create a custom object with all the extracted information
            $Record = [PSCustomObject]@{
                DomainController      = $DC
                TimeCreated           = $TimeCreated
                EventID               = $EventID
                SubjectSecurityID     = $SubjectSecurityID
                SubjectAccountName    = $SubjectAccountName
                SubjectAccountDomain  = $SubjectAccountDomain
                SubjectLogonID        = $SubjectLogonID
                TargetSecurityID      = $TargetSecurityID
                TargetAccountName     = $TargetAccountName
                TargetAccountDomain   = $TargetAccountDomain
                CallerComputerName    = $CallerComputerName
                Privileges            = $Privileges
                Message               = $Message
            }

            # Add the record to the output array
            $Output += $Record
        }
    }
    catch {
        Write-Warning "Failed to process Domain Controller: $DC. Error: $_"
    }
}

# Specify the path where the CSV file will be saved
$CsvPath = 'C:\Temp\AccountEvents_AllDCs.csv'

# Export the data to a CSV file
$Output | Export-Csv -Path $CsvPath -NoTypeInformation

# Notify the user that the export is complete
Write-Host "Export complete. The data has been saved to $CsvPath"
