#Online script - Production mode

#region Changelog
    #DD/MM/YYYY - username - change description
    #07/03/2023 - suchys - Reworked TerminateExecution function to exit immediately after message box is closed, changed log message for incompatible devices to include friendly model name
    #19/07/2023 - suchys - Updated .json version to 5: Added check for Microsoft Intune Autopilot registration - added functions connectGraph, getAutopilotDevices + integration into the main body of the script to verify Autopilot registration based on serial number

#endregion Changelog

#region Set strict mode
Set-StrictMode -Version 3.0
#endregion Strict mode    

#region functions: "GetConfigFile", "connectGraph", "WriteTest", "MessageBoxCustom", "Timestamp", "TimestampSimple", "WriteLog", "TerminateExecution"
function GetConfigFile #connects to the specified Azure blob storage and downloads a file to specified path
{
    param
    (
        [string][parameter(Mandatory = $true)]$path,
        [string][parameter(Mandatory = $true)]$configFileName,
        [string][parameter(Mandatory = $true)]$downloadUri
    )
    $return = $false
    $outputPath = "$path\$configFileName"
    If(-Not (test-path -PathType container $path))
    {
        try
        {
            New-Item -ItemType Directory -Path $path | Out-Null
        } #try
        catch{}
    } #if 

    try
    {
        (New-Object System.Net.WebClient).DownloadFile($downloadUri, $outputPath)
        $return = $true
    } #try
    catch{}
    return $return
}#function GetConfigFile

function connectGraph
{
    param
        (
            [string][parameter(Mandatory = $true)]$tenantID,
            [string][parameter(Mandatory = $true)]$appID,
            [string][parameter(Mandatory = $true)]$clientSecret
        )

    Try
    {
        $uri="https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"    

        $authBody=@{
            client_id=$appID
            client_secret=$clientSecret
            scope="https://graph.microsoft.com/.default"
            grant_type="client_credentials"
            }

        $accessToken=Invoke-WebRequest -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $authBody -Method Post -ErrorAction Stop -UseBasicParsing

        $accessToken=$accessToken.content | ConvertFrom-Json

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $accessToken.access_token
            'ExpiresOn'=$accessToken.expires_in
            }
        return $authHeader
    }
    Catch
    {
        return $false
    }
}#function connectGraph
<#.Synopsis
    get Intune devices
.Description
    returns one or more Devices
.Parameter cName
    Specifies the DeviceName searching for.
.Parameter authHeader
    Specifies the Authentification for Graph.
.Example
    ...
    getIntuneDevices -cName $computerName -authHeader $ms_Auth_Header
#>

function getAutopilotDevices
{
    param
        (
            [string][parameter(Mandatory = $true)]$sNumber,
            [Collections.Hashtable][parameter(Mandatory = $true)]$authHeader
        )

    $serialNumber = $sNumber
    $uri = 'https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$top=25&$filter=contains(serialNumber,' + "'$serialNumber'" + ")"|Get-MSGraphAllPages
    Try
    {
        $response = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get  -ErrorAction Stop
        $devices = $response.Value     
    }
    Catch
    {
        $devices = $false
    }
    return $devices
}#function getAutopilotDevice

function WriteTest #test if selected drive root folder is writable
{   
    param
    (
        [string][parameter(Mandatory = $true)]$drive, 
        [string][parameter(Mandatory = $false)]$test_filename = "test_write.txt"
    ) 

    Try 
    {
        #try to add test file
        $test_path = "$drive\$test_filename"
        [io.file]::OpenWrite($test_path).close()
            
        #remove test file
        Remove-Item -Force $test_path        
        return $true
    } #try

    catch 
    {   
        Write-Host $error[0].Exception         
        return $false           
    } #catch
}#function WriteTest

function MessageBoxCustom
{   
    param
    (
        [string][parameter(Mandatory = $true)]$MessageBoxTitle, 
        [string][parameter(Mandatory = $true)]$MessageBoxText,
        [string][parameter(Mandatory = $true)]$MessageBoxButtons,
        [string][parameter(Mandatory = $true)]$MessageBoxIcon
    ) 

    $self_Icon = [System.Windows.Forms.MessageBoxIcon]::$MessageBoxIcon
    $self_Buttons = [System.Windows.Forms.MessageBoxButtons]::$MessageBoxButtons
    # Show the MessageBox by using the parameters specified above
    $Message = [System.Windows.Forms.MessageBox]::Show($MessageBoxText,$MessageBoxTitle,$self_Buttons,$self_Icon)

}#function MessageBoxCustom

function Timestamp
{
    $self_return = $(Get-Date -Format "dd/MM/yyyy HH:mm:ss") 
    return $self_return
}#function Timestamp

function TimestampSimple
{
    $self_return = $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss") 
    return $self_return.ToString()
}#function TimestampSimple

function WriteLog
{
    param
    (
        [string][parameter(Mandatory = $true)]$message,
        [boolean][parameter(Mandatory = $false)]$verboseHost = $_verboseHost
    )
    $self_stamp = $(Timestamp)
    Write-Output "$self_stamp - $message" >> "$_DataDrive\$_logfileName"
    if ($verboseHost)
    {
        Write-Host "$self_stamp - $message"    
    }#if
}#function WriteLog

function TerminateExecution
{   
    param
    (
        [string][parameter(Mandatory = $false)]$MessageBoxText = "Installation failed. Please refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button.",
        [string][parameter(Mandatory = $false)]$MessageBoxTitle = "Installation failed",
        [string][parameter(Mandatory = $false)]$MessageBoxButtons = "OK",
        [string][parameter(Mandatory = $false)]$MessageBoxIcon = "Stop",
        [int][parameter(Mandatory = $false)]$termination_exitCode = 1

    ) 


    $message = "Last encountered error results in termination of the script. Terminal will exit which will result in reboot."
    WriteLog -message $message

    if ($Error.Count -gt 0)
    {
        if (($Error[0] | Get-Member).name -contains "Exception")
        {
            $message = "Last error or unexpected result from terminal:"
            WriteLog -message $message -verboseHost $false
            $message = $Error[0].Exception
            WriteLog -message $message -verboseHost $false
        }#if
        else 
        {
            $message = $Error[0]
            WriteLog -message $message -verboseHost $false
        }#else
    }#if
    else 
    {
        $message = "No error or unexpected result was found in terminal."
        WriteLog -message $message -verboseHost $false
    }#else    
    
    #termination function message box - uses MessageBoxCustom function, termination can be called with specific message box values to modify the message box
    MessageBoxCustom -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon

    $message = "Script exit code: `"$termination_exitCode`""
    WriteLog -message $message

    exit $termination_exitCode #aborting complete script with specified exit code
}#function TerminateExecution

#endregion Functions

#region Global declaration
    #region Load assemblies
    [void] [reflection.assembly]::LoadWithPartialName("System.Windows.Forms")

    #endregion

    #region permanent variables
    New-Variable -Name _azureUnattendXMLDeveloper -Scope Script -Option ReadOnly -Value ([string] "https://prdglobclients3nfo7st01.blob.core.windows.net/internalresources/unattend_developer.xml")
    New-Variable -Name _azureUnattendXMLProductive -Scope Script -Option ReadOnly -Value ([string] "https://prdglobclients3nfo7st01.blob.core.windows.net/internalresources/unattend_productive.xml")
    New-Variable -Name _azureConfSystemSettingsDeveloper -Scope Script -Option ReadOnly -Value ([string] "https://prdglobclients3nfo7st01.blob.core.windows.net/internalresources/configure_system_settings_developer.bat.txt")
    New-Variable -Name _azureConfSystemSettingsProductive -Scope Script -Option ReadOnly -Value ([string] "https://prdglobclients3nfo7st01.blob.core.windows.net/internalresources/configure_system_settings_productive.bat.txt")
    New-Variable -Name _scriptStartTime -Scope Script -Option ReadOnly -Value (TimestampSimple)
    New-Variable -Name _jsonName -Scope Script -Option ReadOnly -Value ([string] "KB_BareMetalRecovery.json")
    New-Variable -Name _verboseHost -Scope Script -Option ReadOnly -Value ([boolean] $true)
    New-Variable -Name _scriptVersion -Scope Script -Option ReadOnly -Value ([string] "5")
    New-Variable -Name _DataDrive -Scope Script -Option ReadOnly -Value ([string] ("W:"))
    New-Variable -Name _TempDrive -Scope Script -Option ReadOnly -Value ([string] ($env:TEMP))
    New-Variable -Name _TempPath -Scope Script -Option ReadOnly -Value ([string] ("$_TempDrive"))
    New-Variable -Name _CTempPath -Scope Script -Option ReadOnly -Value ([string] ("C:\Windows\Temp"))
    New-Variable -Name _jsonPath -Scope Script -Option ReadOnly -Value ([string] ("$($env:ProgramData)\$($_jsonName)"))
    New-Variable -Name _DisableCMDRequestPath -Scope Script -Option ReadOnly -Value ([string] "C:\Windows\Setup\Scripts")
    New-Variable -Name _defaultTennant_ID -Scope Script -Option ReadOnly -Value ([string] "66f6821e-0a30-4a06-8b8b-901bbfd2bc60")
    New-Variable -Name _defaultApp_ID -Scope Script -Option ReadOnly -Value ([string] "459b3207-5703-4734-8de6-fd61b4d752a0")
    New-Variable -Name _defaultClientSecret -Scope Script -Option ReadOnly -Value ([string] "jh77Q~0M0TH-qAQaC63piwAz2Yf~Kojl62dKE")
    # Declaration of this variable is now used as a readability test in evaluation of Autopil Registration - New-Variable -Name _serialNumber -Scope Script -Option ReadOnly -Value ((get-ciminstance win32_bios).SerialNumber)
    
    #endregion
    
    #region Dynamic variables
        #region Test if KB_BareMetalRecovery.json is found
        if ((Test-Path -Path $_jsonPath) -eq $false)
        {
            $message = "Failed: $_jsonPath not found"
            WriteLog -message $message
            TerminateExecution
        }#if
        else 
        {
            $message = "Success: $_jsonPath has been found"
            WriteLog -message $message
        }#else
        #endregion
        
        #region Get USB Mode from .Json file and save it to $developerMode variable
        try 
        {
            $developerMode = (Get-Content $_jsonPath | ConvertFrom-Json).developer
        }#try
        catch 
        {
            $blobUri = $null
            $message = "Failed: USB developer mode couldn't be recognized. Please make sure that KB_BareMetalRecovery.json is present on USB drive."
            WriteLog -message $message 
            TerminateExecution
        }
        #endregion

    #endregion     

#region Declare and log which mode script is running
if ($developerMode -eq 1)
{
    $message = "Starting execution of downloaded script."
    WriteLog -message $message
    $message = "Script mode: developer"
    WriteLog -message $message
}#if
elseif ($developerMode -eq 0) 
{
    $message = "Starting execution of downloaded script."
    WriteLog -message $message
    $message = "Script mode: production"
    WriteLog -message $message
}#elseif
else
{
    $message = "Failed: USB developer mode settings has incorrect value. PLease make sure that KB_BareMetalRecovery.json is present on USB drive and isn't modified."
    WriteLog -message $message
}#else

#endregion 

#region Versions
    #region Get $USBVersion
    $USBVersion = (Get-Content $_jsonPath | ConvertFrom-Json).version
    #endregion Get $USBVersion

    #region Compare _scriptVersion and $USBVersion
    if ($_scriptVersion -eq $USBVersion) 
    {
        $message = "Success: Versions are equal: USB: $($USBVersion) Azure: $($_scriptVersion)"
        WriteLog -message $message
    }#if 
    elseif ($_scriptVersion -gt $USBVersion) 
    {
        $MessageBoxText = "Failed: Your recovery drive is outdated. Versions: USB: $($USBVersion) Azure: $($_scriptVersion). Please re-image your recovery flash drive from the official source."
        $MessageBoxTitle = "Installation media is outdated"
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        MessageBoxCustom -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon

        $message = "Failed: Your recovery drive is outdated. Versions: USB: $($USBVersion) Azure: $($_scriptVersion). Please re-image your recovery flash drive from official source."
        WriteLog -message $message
        TerminateExecution
    }#elseif 
    elseif ($_scriptVersion -lt $USBVersion) 
    {
        $message = "Success: USB version is higher:  USB: $($USBVersion) Azure: $($_scriptVersion)"
        WriteLog -message $message
    }#elseif
    #endregion Compare _scriptVersion and $USBVersion
#endregion Versions




#region Import PowerShell modules
    $message = "Copying the required PowerShell modules to: `"$($env:ProgramFiles)\WindowsPowerShell\Modules`"..."
    WriteLog -message $message

    try 
    {
        Copy-Item -Path "$($_DataDrive)\`$PSModules\*" -Destination "$($env:ProgramFiles)\WindowsPowerShell\Modules" -Recurse -Force
        $message = "Success. Copying of the required PowerShell modules to `"$($env:ProgramFiles)\WindowsPowerShell\Modules`" completed."
        WriteLog -message $message
    }
    catch
    {
        $message = "Failed. Copying of the required PowerShell modules to `"$($env:ProgramFiles)\WindowsPowerShell\Modules`" was not successful."
        WriteLog -message $message
        TerminateExecution
    }

    try 
    {
        $message = "Importing the required PowerShell modules..."
        WriteLog -message $message
    
        Import-Module PackageManagement -Force -scope Global
        Import-Module -name MSAL.PS -Force -Scope Global
        Import-Module -name Microsoft.Graph.DeviceManagement -Force -Scope Global
        Import-Module -name Microsoft.Graph.Intune -Force -Scope Global 
        
        $message = "Success. Importing the required PowerShell modules was completed successfuly."
        WriteLog -message $message
        
    }
    catch 
    {
        $message = "Failed. Importing the required PowerShell modules was not successful."
        WriteLog -message $message
        TerminateExecution
    }

#endregion Import modules


#region Download unattend.xml based on global declaration link, save to $_TempPath
if ($developerMode -eq 1)
{
    $blobUri = $_azureUnattendXMLDeveloper
}#if
else 
{
    $blobUri = $_azureUnattendXMLProductive
}#else
$sas = '?sp=r&st=2022-07-05T07:25:08Z&se=2027-07-05T15:25:08Z&spr=https&sv=2021-06-08&sr=c&sig=WgZlmtcItGzAVUUdG6eOo9Az7CC0y57tK%2BKnl6k8Kk0%3D'
$filePath = $_TempPath
$configFile = 'unattend.xml'
$fullUri = "$blobUri$sas"

$downloadStatus = $false
$attempts = 0

while (($attempts -lt 5) -and ($downloadStatus -eq $false))
{   
    $attempts++
    $downloadStatus = (GetConfigFile -path $filePath -configFileName $configFile -downloadUri $fullUri)
    if ($downloadStatus -eq $false)
    {
        $message = "Failed: Attempt $attempts - Failed: Execution of download function from $blobUri has failed. Retry in 10 seconds."
        WriteLog -message $message 
        Start-Sleep -Seconds 10
    }#if
    else 
    {
        $message = "Success: Attempt $attempts - Success: Execution of download function from $blobUri was successfull."
        WriteLog -message $message 
    }#else

}#if
if (($attempts -ge 5) -and ($downloadStatus -eq $false))
{
    $message = "Failed: All download attempts failed. Terminating script."
    WriteLog -message $message
    TerminateExecution 
}#elseif

#endregion

#region Check for mandatory files
    $message = "Testing existence of files mandatory for installation:"
    WriteLog -message $message


    if (!(Test-Path "$_DataDrive\sources\Setup.exe"))
    {
        $message = "Failed. Setup.exe not found at path: W:\sources\Setup.exe"
        WriteLog -message $message
        TerminateExecution
    }
    else 
    {
        $message = "Success: Setup.exe was found."
        WriteLog -message $message
    }#else
    if (!(Test-Path "$_TempPath\unattend.xml")) 
    {
        $message = "Failed. Unattend.xml not found"
        WriteLog -message $message
        TerminateExecution
    }
    else 
    {
        $message = "Success. File $_TempPath\unattend.xml was found."
        WriteLog -message $message
    }#else
#endregion

#region Get and evaluate serial number
    try 
    {
        $message = "Trying to read serial number from the computer..."
        WriteLog -message $message

        New-Variable -Name _serialNumber -Scope Script -Option ReadOnly -Value ([string]((get-ciminstance win32_bios).SerialNumber))

        $message = "Success. Serial number was successfuly read from the computer."
    }#try
    catch 
    {
        $message = "Failed. Serial number could not be read."
        WriteLog -message $message

        $MessageBoxText = "The script was not able to determine device serial number. Execution of the script will be terminated.`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "Serial number could not be read"
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon        
    }#catch

    $message = "Checking validity of the serial number..."
    WriteLog -message $message
    $SNValid = $true

    if ($null -eq $_serialNumber) 
    {   
        $SNValid = $false
        $message = "Failed. Serial number is empty."
        WriteLog -message $message

        $MessageBoxText = "The serial number is empty. Execution of the script will be terminated.`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "Serial number is invalid"      
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText
    }#if

    if ([int]::TryParse($_serialNumber, [ref] $null))
    {
        if ([int]$_serialNumber -eq 0)
        {   
            $SNValid = $false
            $message = "Failed. Serial number is invalid and contains only 0."
            WriteLog -message $message
    
            $MessageBoxText = "The serial number is invalid and contains only 0. Execution of the script will be terminated.`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
            $MessageBoxTitle = "Serial number is invalid"      
            TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText
        }#if
    }#if

    if ($_serialNumber.Contains(" "))
    {   
        $SNValid = $false
        $message = "Failed. Serial number contains spaces."
        WriteLog -message $message

        $MessageBoxText = "The serial number is invalid because it contains spaces. This indicates that serial number was not correctly configured to the motherboard. Execution of the script will be terminated.`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "Serial number is invalid"      
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText
    }#if

    if ($SNValid -eq $true)
    {
        $message = "Success. All validity checks of the computer serial number were successful."
        WriteLog -message $message
    }

#endregion Get and evaluate serial number

#region Autopilot - connect to GraphAPI and verify if the device serial number is registered for Intune Autopilot

    $message = "Connecting to GraphAPI to verify computer registration in Microsoft Intune Autopilot..."
    WriteLog -message $message

    $ms_Auth_Header = connectGraph -tenantID $_defaultTennant_ID -appID $_defaultApp_ID -clientSecret $_defaultClientSecret
    if ($ms_Auth_Header -eq $false)
    {
        $message = "Failed. Connection to GraphAPI was not successful."
        WriteLog -message $message

        $MessageBoxText = "System could not connect to GraphAPI. Execution of the script will be terminated.`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "GraphAPI connection failed"
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon

    }#if
    else
    {
        $message = "Success. System successfuly connected to GraphAPI."
        WriteLog -message $message
    }#else
    
    $intuneDevices = getAutopilotDevices -sNumber $_serialNumber -authHeader $ms_Auth_Header
    
    if ($null -eq $intuneDevices)
    {
        $message = "Failed. The regstration in Intune Autopilot could not be verified for this computer serial number `"$_serialNumber`"."
        WriteLog -message $message

        $MessageBoxText = "The regstration in Intune Autopilot could not be verified for this computer serial number `"$_serialNumber`". Execution of the script will be terminated.`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "Intune Autopilot registration error"
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon
    }#if
    else 
    {
        $message = "Success. The registration in Intune Autopilot has been verified."
        WriteLog -message $message
    }#else

#endregion Compatibility - Test if hardware is registered in Autopilot


#region Manufacturer, model, driver folder
    <#
    $message = "Searching for Manufacturer and Driver folder based on detected computer model..."
    WriteLog -message $message

    #Get manufacturer info from registry
    $systemInfo = Get-ItemProperty -Path HKLM:\SYSTEM\HardwareConfig\Current
    $manufacturer = $systemInfo.SystemManufacturer
    
    #Check if driver folder for $manufacturer exists
    if ((Test-Path $_DataDrive'\$Drivers\'$manufacturer) -eq $false)
    {
        $message = "Failed. Manufacturer $manufacturer folder not found."
        WriteLog -message $message
        TerminateExecution
    }#if
    else 
    {
        $message = "Success. Manufacturer $manufacturer folder was found."
        WriteLog -message $message
    }#else

    #Determine model of the device
    if ($manufacturer -eq "LENOVO")
    {
        $model = ($systeminfo.SystemProductName).Substring(0,4)
        $modelFriendlyName = $systemInfo.SystemVersion
    }#if
    else 
    {
        $model = $systeminfo.SystemProductName
        $modelFriendlyName = $systeminfo.SystemProductName
    }#else

    #Save folder path to variable $driverFolder
    $driverFolder = (Get-Childitem -Path $_DataDrive'\$Drivers\'$manufacturer | Where-Object Name -Match $($model))
    if ($null -eq $driverFolder) 
    {   
        $message = "Failed. Driver folder for `"$modelFriendlyName`" model was not found. Model code used for detection: `"$model`" "
        WriteLog -message $message

        $MessageBoxText = "The hardware model is not supported by the Bare Metal Recovery process. Execution will be terminated.`n`nModel name: `"$modelFriendlyName`"`nModel code: `"$model`"`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "Hardware model not supported"
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon
    } 
    else 
    {
        $driverFolder = $driverFolder.FullName
        $message = "Success. Driver folder was found. `"$driverFolder`" will be used for installation."
        WriteLog -message $message
    }
#>
#endregion Manufacturer, model, driver folder

#region Driver folder settings
    $message = "Testing if driver folder is present..."
    WriteLog -message $message

    $driverFolder = "$($_DataDrive)\`$Drivers"

    if ((Test-Path $driverFolder) -eq $false)
    {
        $message = "Failed. `"$driverFolder`" was not found."
        WriteLog -message $message

        $MessageBoxText = "Driver folder not found`n`nPath: `"$driverFolder`"`n`nPlease refer to the logfile at: `"$_DataDrive\$_logfileName`"`nfor more information.`n`nSystem will be automatically rebooted after clicking the OK button. "
        $MessageBoxTitle = "Driver folder not found"
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        TerminateExecution -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon
    }#if
    else
    {
        $message = "Success. Driver folder was found. `"$driverFolder`" will be used for installation."
        WriteLog -message $message

    }#else
#endregion

#region Installation preparation
    
    #create link to drivers directory
    try 
    {   
        subst.exe Z: "$driverFolder"
        $message = "Attempting to map driver folder as Z: drive."
        WriteLog -message $message

    }
    catch 
    {
        $message = $error[0].Exception
        WriteLog -message $message
        TerminateExecution
    }

    #Verify that $driverFolder mapping was successfull
    if (Test-Path Z:)
    {
        $message = "Success: $DriverFolder was successfully mapped as drive Z:"
        WriteLog -message $message
    }#if
    else 
    {
        $message = "Failed: drive Z: could not be found. Terminating installation."
        WriteLog -message $message
        TerminateExecution
    }


    #start Windows Setup with necessary paramaters
        $message = "Starting Windows Setup.exe..."
        WriteLog -message $message
        $message = "Please wait..."
        WriteLog -message $message

        Start-Process -filePath "$_DataDrive\sources\Setup.exe" -argumentList "/unattend:$_TempPath\unattend.xml /noreboot" -Wait

#endregion

#region Finishing OS installation
    if (($LASTEXITCODE -eq 0) -or ($LASTEXITCODE -eq 1))
    {
        $message = "Success: Setup.exe executed successfully."
        WriteLog -message $message
    }
    else
    {
        $message = "Failed: Setup.exe failed with return code: $LASTEXITCODE"
        WriteLog -message $message

        $MessageBoxText = "Windows installation failed with exit code `"$LASTEXITCODE`". Execution will be terminated."
        $MessageBoxTitle = "Windows installation failed."
        $MessageBoxButtons = "OK"
        $MessageBoxIcon = "Stop"
        MessageBoxCustom -MessageBoxTitle $MessageBoxTitle -MessageBoxText $MessageBoxText -MessageBoxButtons $MessageBoxButtons -MessageBoxIcon $MessageBoxIcon
        TerminateExecution
    }

#endregion

#region Create DisableCMDRequest.TAG

    if (!(Test-Path $_DisableCMDRequestPath))
    {
        try 
        {
            $message = "Attempting to create folder $_DisableCMDRequestPath"
            WriteLog -message $message
            New-Item $_DisableCMDRequestPath -Type Directory
        }#try

        catch
        {
            $message = "Failed: Error detected during $_DisableCMDRequestPath folder creation"
            WriteLog -message $message
        }#catch
    }#if

    #test if the folder was created successfuly and try to create the file
    if (Test-Path $_DisableCMDRequestPath)
    {
        $message = "Success: Folder C:\Windows\Setup\Scripts was found."
        WriteLog -message $message
        
        try
        {
            $message = "Attempting to create file $_DisableCMDRequestPath\DisableCMDRequest.TAG"
            WriteLog -message $message
            New-Item -Path "$_DisableCMDRequestPath\DisableCMDRequest.TAG"
        }#try
        catch
        {
            $message = "Failed: Error detected during $_DisableCMDRequestPath\DisableCMDRequest.TAG file creation"
            WriteLog -message $message
        }#catch
    }#if

    #verify the file existence
    if (!(Test-Path "$_DisableCMDRequestPath\DisableCMDRequest.TAG"))
    {
        $message = "Failed: File $_DisableCMDRequestPath\DisableCMDRequest.TAG not found."
        WriteLog -message $message
    }#if
    else 
    {
        $message = "Success: File $_DisableCMDRequestPath\DisableCMDRequest.TAG was found. "
        WriteLog -message $message
    }#else

#endregion Create DisableCMDRequest.TAG   

#region Test if $_CTempPath exists
    if ((Test-Path -Path $_CTempPath) -eq $false)
    {
        $message = "Failed: $_CTempPath not found"
        WriteLog -message $message
        TerminateExecution
    }#if
    else 
    {
        $message = "Success: $_CTempPath has been found"
        WriteLog -message $message
    }#else
#endregion

#region Download configure_system_settings.bat based on global declaration link, save to $_TempPath
if ($developerMode -eq 1)
{
    $blobUri = $_azureConfSystemSettingsDeveloper
}#if
else 
{
    $blobUri = $_azureConfSystemSettingsProductive
}#else
$sas = '?sp=r&st=2022-07-05T07:25:08Z&se=2027-07-05T15:25:08Z&spr=https&sv=2021-06-08&sr=c&sig=WgZlmtcItGzAVUUdG6eOo9Az7CC0y57tK%2BKnl6k8Kk0%3D'
$filePath = $_CTempPath
$configFile = 'configure_system_settings.bat'
$fullUri = "$blobUri$sas"

$downloadStatus = $false
$attempts = 0

while (($attempts -lt 5) -and ($downloadStatus -eq $false))
{   
    $attempts++
    $downloadStatus = (GetConfigFile -path $filePath -configFileName $configFile -downloadUri $fullUri)
    if ($downloadStatus -eq $false)
    {
        $message = "Failed: Attempt $attempts - Failed: Execution of download function from $blobUri has failed. Retry in 10 seconds."
        WriteLog -message $message 
        Start-Sleep -Seconds 10
    }#if
    else 
    {
        $message = "Success: Attempt $attempts - Success: Execution of download function from $blobUri was successfull."
        WriteLog -message $message 
    }#else

}#if
if (($attempts -ge 5) -and ($downloadStatus -eq $false))
{
    $message = "Failed: All download attempts failed. Terminating script."
    WriteLog -message $message
    TerminateExecution 
}#elseif

#endregion

#region check if downloaded file is in place
if (Test-Path "$filePath\$configFile") {
    $message = "Success. File $filePath\$configFile has been found."
    WriteLog -message $message
} else {
    $message = "Failed. File $filePath\$configFile not found."
    WriteLog -message $message
    TerminateExecution
}
#endregion

$message = "Windows installation was completed successfully."
WriteLog -message $message

#end script exection as successful success

$message = "Script exit code: `"0`""
WriteLog -message $message
exit 0
