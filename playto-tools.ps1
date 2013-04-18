#requires -Version 3.0

Add-Type -AssemblyName System.Web

function Suspend-CertifiedDeviceChecks
{
    $_unwind = New-Object Collections.Stack

    function Add-ToUnwind()
    {
        param([Parameter(Mandatory = $true)][ScriptBlock]$Code)

        $_unwind.Push($Code)
    }

    function Invoke-Unwind()
    {
        if($_unwind.Count -gt 0) {
            $_unwind | % { $_.Invoke() | Out-Null }
        }

        $_unwind.Clear()
    }

    function Test-Administrator()
    {  
        $user = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
    }

    if(!(Test-Administrator)) {
        Write-Error "Elevated permissions are required to run this script."
        return
    }

    if(![Environment]::Is64BitProcess) {
        Write-Error "Script requires a 64-bit operating system."
        return
    }

    Add-Type -Name Win32 -Namespace $Null -PassThru -MemberDefinition @"
        [DllImport("kernel32")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            IntPtr lpNumberOfBytesWritten);

        [Flags]
        public enum ProcessAccessFlags
        {
            // ...
            All = 0x001F0FFF
            // ...
        }

        [DllImport("kernel32")]
        public static extern IntPtr OpenProcess(
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [Flags]
        public enum CreationFlags : uint
        {
            None = 0
        }

        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        [Flags]
        public enum AllocationType
        {
             Commit = 0x1000,
             Reserve = 0x2000,
             Decommit = 0x4000,
             Release = 0x8000,
             // ...
        }

        [Flags]
        public enum MemoryProtection
        {
            // ...
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            // ...
        }

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32", EntryPoint="GetModuleHandleW")]
        public static extern IntPtr GetModuleHandle(
            [MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(
            IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        [DllImport("kernel32")]
        public static extern uint GetLastError();

        public enum WaitResult
        {
            // ...
            WaitObject0 = 0x0
            // ...
        }

        [DllImport("kernel32")]
        public static extern uint WaitForSingleObject(
            IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint dwFreeType);
"@ | Out-Null

    #
    # Find the Device Setup Manager service
    #

    Start-Service DsmSvc

    $svcpid = Get-WmiObject Win32_Service | ? { $_.Name -eq "DsmSvc" } | Select -ExpandProperty ProcessId

    if(!$svcpid) {
       Write-Error "Failed to latch onto the Device Setup Manager service. Is it disabled?"
       return
    }

    $svchandle = [Win32]::OpenProcess([Win32+ProcessAccessFlags]::All, $false, $svcpid)

    if(!$svchandle) {
        Write-Error "Failed to open svchost process."
        return
    }

    Add-ToUnwind { [Win32]::CloseHandle($svchandle) }

    #
    # Load DevPropMgr.dll (and leave it loaded)
    #

    $dll = [Text.Encoding]::Unicode.GetBytes("DevPropMgr.dll")
    $mem = [Win32]::VirtualAllocEx($svchandle, [IntPtr]::Zero, $dll.Length, ([Win32+AllocationType]::Reserve -bor [Win32+AllocationType]::Commit),
        [Win32+MemoryProtection]::ExecuteReadWrite)

    if(!$mem) {
        Write-Error "Failed to allocate a chunk of memory in svchost."
        Invoke-Unwind
        return
    }

    Add-ToUnwind { [Win32]::VirtualFreeEx($svchandle, $mem, 0, [Win32]::AllocationType::Release) }

    if(![Win32]::WriteProcessMemory($svchandle, $mem, $dll, $dll.Length, [IntPtr]::Zero)) {
        Write-Error "Failed to write to allocated memory in svchost."
        Invoke-Unwind
        return
    }

    $loadlibrary = [Win32]::GetProcAddress([Win32]::GetModuleHandle("kernel32"), "LoadLibraryW")

    if(!$loadlibrary) {
        Write-Error "Failed to locate kernel32!LoadLibraryW, is this a supported OS?"
        Invoke-Unwind
        return
    }

    $thread = [Win32]::CreateRemoteThread($svchandle, [IntPtr]::Zero, 0, $loadlibrary, $mem, [Win32+CreationFlags]::None, [IntPtr]::Zero)

    if(!$thread) {
        Write-Error "Failed to create remote thread."
        Invoke-Unwind
        return
    }

    if([Win32]::WaitForSingleObject($thread, [TimeSpan]::FromSeconds(10).Milliseconds) -ne [Win32+WaitResult]::WaitObject0) {
        Write-Warning "Remote thread terminated unexpectedly, strangeness may follow."
    }

    #
    # Patch DevPropMgr!_CheckSignature
    #

    $addr = Get-Process -Id $svcpid | Select -ExpandProperty Modules | ? { $_.ModuleName -eq "DevPropMgr.dll" } | Select -ExpandProperty BaseAddress

    if(!$addr) {
        Write-Error "Failed to locate DevPropMgr.dll module in svchost."
        Invoke-Unwind
        return
    }

    # Shelved patch for Windows RT
    # $patchbytes = [Byte[]](0x00, 0x25) # armasm: movs r5, #0
    # [Win32]::WriteProcessMemory($svchandle, [IntPtr]::Add($addr, 0xEABC), $patchbytes, $patchbytes.Length, [IntPtr]::Zero)

    # Patch for Windows 8 x64
    $patchbytes = [Byte[]](0x33, 0xDB, 0x85, 0xDB) # x86-64 asm: xor ebx,ebx | test ebx, ebx
    if(![Win32]::WriteProcessMemory($svchandle, [IntPtr]::Add($addr, 0x1466B), $patchbytes, $patchbytes.Length, [IntPtr]::Zero)) {
        Write-Error "Failed to fiddle with svchost memory."
        Invoke-Unwind
        return
    }

    #
    # Cleanup
    #

    Invoke-Unwind
    Write-Host "OK."
}

function Get-MediaRenderers()
{
    Get-WmiObject Win32_PnPEntity | ? { $_.CompatibleID -Like "*MediaRenderer*" -or $_.CompatibleID -Like "*\MS_*DMR*"  } | Select Name, HardwareID
}

function New-DeviceMetadata()
{

    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]$DeviceId,

        [Switch]$Install
    )

    $device = Get-WmiObject Win32_PnPEntity | ? { $_.HardwareID -Contains $DeviceId } | Select Name, Manufacturer, HardwareID

    if(!$device)
    {
        Write-Error "Failed to locate device with specified hardware ID. Is the device on?"
        return
    }
    
    $scratch = "$(([Guid]::NewGuid() | Select -exp Guid).Remove(23))-00000ca710af"

    New-Item $scratch -ItemType Directory | Out-Null
    Copy-Item .\template\* $scratch -Recurse -Force

    $pkginfo = "$scratch\PackageInfo.xml"

    (Get-Content $pkginfo | ForEach {
        $buffer = $_ -replace "{hwid}", [System.Web.HttpUtility]::HtmlEncode("DOID:$($device.HardwareID[0])")
        $buffer = $buffer -replace "{lastmodified}", ([DateTime]::UtcNow.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"))
        $buffer -replace "{experienceid}", $scratch }) | Out-File $pkginfo -Encoding utf8
    
    $devinfo = "$scratch\DeviceInfo\DeviceInfo.xml"

    (Get-Content $devinfo | ForEach {
        $buffer = $_ -replace "{model}", $device.Name
        $buffer -replace "{manufacturer}", $device.Manufacturer }) | Out-File $devinfo -Encoding utf8

    Get-Item -Path $scratch | New-Cab | Move-Item -Destination ".\$scratch.devicemetadata-ms"   

    if($Install) {
        Copy-Item "$scratch.devicemetadata-ms" "$env:ProgramData\Microsoft\Windows\DeviceMetadataStore\en-US" -Force
    }

    Remove-Item $scratch -Force -Recurse

    Write-Host "OK."
}

function New-Cab()
{
    param(
        [Parameter(ValueFromPipeline=$True, Mandatory=$True)]
        [IO.DirectoryInfo]$Directory,

        [ValidateSet("MSZIP", "LZX")]
        [String]$Algorithm = "MSZIP"
    )

    $uri = New-Object Uri ("$($Directory.FullName)\", [UriKind]::Absolute)
    $files = $Directory.GetFiles("*.*", [IO.SearchOption]::AllDirectories) | % {

        # Each file entry must appear as so: <outside cab path> <inside cab path>
        $entry = $($uri.MakeRelativeUri($_.FullName).OriginalString) -replace "/", "\"
        "`"$($_.FullName)`" `"$entry`"`n"
    }

    $guid = "$([Guid]::NewGuid() | Select -exp Guid)"
    $ddf = "$env:Temp\$guid.ddf"

    "
    .Set CabinetNameTemplate=`"$guid.cab`"
    .Set DiskDirectoryTemplate=`"$env:Temp`"
    .Set RptFileName=`"$ddf`:rpt`"
    .Set InfFileName=`"$ddf`:inf`"
    .Set CompressionType=$Algorithm
    $files
    " | New-Item -ItemType File $ddf | Out-Null

    MakeCab /F "$ddf" | Out-Null
    Remove-Item $ddf -Force | Out-Null

    New-Object IO.FileInfo "$env:Temp\$guid.cab"
}
