#PlayTo Tools#

Dot-sourced library of cmdlets to tinker with PlayTo in Windows 8/RT

##Requirements##
* Windows 8 x64

##Install##
1. Start an elevated Powershell instance
2. <code>Set-ExecutionPolicy Unrestricted</code> if necessary.
3. Dot source script
4. Call <code>Suspend-CertifiedDeviceChecks</code> to disable metadata signature checks
5. Call <code>New-DeviceMetadata [-Install] \<hardware ID\></code> to generate metadata for the device needing certification

##Tips##
1. Use helper <code>Get-MediaRenderers</code> to list all DMRs on the network.
2. Expand the HardwareID property to get the entire device hardware ID string.

<code>Get-MediaRenderers | ? Name -like "*popcorn*" | Select -exp HardwareID | Select -first 1</code>

##Uninstall##
1. Navigate to <code>%ProgramData%\Microsoft\Windows\DeviceMetadataStore\en-US</code> and delete all files suffixed with <code>00000ca710af</code>. These are metadata packages created solely by this script.
2. Remove devices associated with the custom metadata
3. Re-add devices. Windows will automatically download new (or use default) metadata.

##Pull request ideas##
* Finish Windows RT support (will need restricted language workarounds)
* Add non-US locale support (if needed)
* (your idea here)
