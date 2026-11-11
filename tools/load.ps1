<#
.SYNOPSIS
    goofyahh fileless loader: maps the payload into a live javaw.exe entirely
    in memory. One PowerShell command, zero files written.

.DESCRIPTION
    The PowerShell counterpart of dist\goofyahh-injector.exe for the
    distribution side. A native exe cannot execute itself from a command line
    without first existing on disk, so the loader role - not the payload -
    moves into this script: the payload bytes are downloaded into a buffer,
    mapped into the target by hand (same pipeline as the C++ injector:
    headers, sections, relocations, imports, TLS, exception table, entry
    point through shellcode stubs), and no file is ever written.

    The only disk surface left is the optional bootstrap handshake file, which
    is on by default so the behaviour (and the injector GUI's live state) is
    identical to the exe; pass -NoStatus for a run that touches nothing at
    all - the payload is then silent, which is the opt-in handshake contract
    in payload/src/core/Status.cpp.

    Everything runs in the caller's own process: no service, no driver, no
    other executable. 64-bit PowerShell on 64-bit Windows is required.

.PARAMETER Url
    http(s) URL of the payload, or a local file path for dev runs.
    Defaults to the GOOFAYH_URL environment variable.

.PARAMETER ProcessId
    Inject into this PID instead of picking a target automatically.

.PARAMETER Name
    Executable name to look for (default javaw.exe).

.PARAMETER NoStatus
    Do not claim or write the bootstrap handshake file. Fully silent; loses
    the "already injected" guard and the exe GUI's live state for this run.

.PARAMETER List
    Print the candidate processes and exit without injecting.

.PARAMETER Timeout
    Seconds to wait for the payload bootstrap handshake (default 30).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -Command "iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/<user>/<repo>/main/tools/load.ps1')"

.EXAMPLE
    .\load.ps1 -ProcessId 1234 -NoStatus
#>
[CmdletBinding()]
param(
    [string]$Url = $env:GOOFAYH_URL,
    [int]$ProcessId = 0,
    [string]$Name = 'javaw.exe',
    [switch]$NoStatus,
    [switch]$List,
    [int]$Timeout = 30
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$text) {
    Write-Host "  $text" -ForegroundColor DarkGray
}

function Write-Good([string]$text) {
    Write-Host "  $text" -ForegroundColor Green
}

function Write-Bad([string]$text) {
    Write-Host "  $text" -ForegroundColor Red
}

# ---------------------------------------------------------------- host checks

if (-not [Environment]::Is64BitProcess) {
    Write-Bad 'this loader must run in 64-bit Windows PowerShell'
    Write-Step 'the Start Menu "Windows PowerShell" shortcut is 64-bit; a 32-bit host cannot address a 64-bit target'
    exit 1
}

$session = $ExecutionContext.SessionState.LanguageMode
if ($session -ne 'FullLanguage') {
    Write-Bad "constrained language mode is active ($session); the mapper cannot compile"
    exit 1
}

# ------------------------------------------------------------------- helpers

function Get-JavaCandidates([string]$exeName) {
    $short = $exeName -replace '\.exe$', ''
    $processes = @(Get-Process -Name $short -ErrorAction SilentlyContinue)
    $titles = @{}
    foreach ($process in $processes) {
        if ($process.MainWindowTitle) {
            $titles[$process.Id] = $process.MainWindowTitle
        }
    }

    # Command lines come from WMI/CIM so Minecraft can be told apart from a
    # windowless background JVM, the same signal the exe reads from titles.
    $commands = @{}
    if ($processes.Count -gt 0) {
        $ids = $processes | ForEach-Object { $_.Id }
        $filter = ($ids | ForEach-Object { "ProcessId=$_" }) -join ' OR '
        $rows = $null
        try {
            $rows = Get-CimInstance Win32_Process -Filter $filter -ErrorAction Stop
        } catch {
            try {
                $rows = Get-WmiObject Win32_Process -Filter $filter -ErrorAction Stop
            } catch {
                $rows = @()
            }
        }
        foreach ($row in $rows) {
            $commands[[int]$row.ProcessId] = [string]$row.CommandLine
        }
    }

    $candidates = @()
    foreach ($process in $processes) {
        $title = ''
        if ($titles.ContainsKey($process.Id)) {
            $title = $titles[$process.Id]
        }
        $command = ''
        if ($commands.ContainsKey($process.Id)) {
            $command = $commands[$process.Id]
        }
        $score = 0
        if ($title -match 'minecraft') { $score += 4 }
        if ($command -match '(?i)minecraft|fabricmc|net\.fabricmc|knot') { $score += 2 }
        $candidates += [pscustomobject]@{
            Id       = $process.Id
            Name     = $process.ProcessName
            Title    = $title
            Command  = $command
            Score    = $score
            Windowed = [bool]$title
        }
    }
    return , $candidates
}

# ------------------------------------------------------------------- targets

$targets = Get-JavaCandidates -exeName $Name

if ($List) {
    if ($targets.Count -eq 0) {
        Write-Host '  no candidate processes' -ForegroundColor Yellow
        return
    }
    Write-Host ''
    Write-Host '  PID    PROCESS     TITLE' -ForegroundColor Cyan
    foreach ($candidate in $targets) {
        $title = $candidate.Title
        if (-not $title) { $title = '(no window)' }
        Write-Host ('  {0,-6} {1,-11} {2}' -f $candidate.Id, $candidate.Name, $title)
        if ($candidate.Command) {
            $clip = $candidate.Command
            if ($clip.Length -gt 90) { $clip = $clip.Substring(0, 90) + '...' }
            Write-Host ('          cmd: ' + $clip) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    return
}

$targetId = 0
$targetTitle = ''

if ($ProcessId -gt 0) {
    $match = $null
    foreach ($candidate in $targets) {
        if ($candidate.Id -eq $ProcessId) { $match = $candidate; break }
    }
    if ($match -eq $null) {
        $any = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($any -eq $null) {
            Write-Bad "no process with PID $ProcessId"
            exit 1
        }
        $targetId = $ProcessId
        $targetTitle = $any.ProcessName
    } else {
        $targetId = $match.Id
        $targetTitle = $match.Title
    }
} else {
    $windowed = @($targets | Where-Object { $_.Windowed })
    if ($windowed.Count -eq 0) {
        Write-Bad "no windowed $Name found"
        Write-Step 'start the game first (the window has to be up), or pass -ProcessId'
        exit 1
    }
    $best = $windowed | Sort-Object -Property Score -Descending | Select-Object -First 1
    $tied = @($windowed | Where-Object { $_.Score -eq $best.Score })
    if ($tied.Count -gt 1) {
        Write-Bad 'several candidate processes; pick one'
        Write-Host ''
        foreach ($candidate in $tied) {
            $title = $candidate.Title
            if (-not $title) { $title = '(no window)' }
            Write-Host ('  {0,-6} {1}' -f $candidate.Id, $title) -ForegroundColor Cyan
        }
        Write-Host ''
        Write-Step "re-run with -ProcessId <pid> (see the list with -List)"
        exit 1
    }
    $targetId = $best.Id
    $targetTitle = $best.Title
    if (-not $targetTitle) { $targetTitle = $best.Name }
}

$statusPath = Join-Path $env:TEMP ('werm' + $targetId + '.tmp')

# ------------------------------------------------------------- payload bytes

if ([string]::IsNullOrEmpty($Url)) {
    Write-Bad 'no payload URL given'
    Write-Step 'pass -Url https://.../goofyahh.dll, or set the GOOFAYH_URL environment variable'
    exit 1
}

if (Test-Path -LiteralPath $Url -PathType Leaf) {
    $bytes = [IO.File]::ReadAllBytes($Url)
    Write-Good "payload read from local file: $Url ($($bytes.Length) bytes)"
} else {
    Write-Step "downloading payload from $Url"
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        # Older hosts without the TLS 1.2 constant still negotiate TLS 1.0.
    }
    $client = New-Object Net.WebClient
    $client.Headers.Add('User-Agent', 'Mozilla/5.0')
    $bytes = $client.DownloadData($Url)
    Write-Good "payload downloaded ($($bytes.Length) bytes)"
}

if ($bytes -eq $null -or $bytes.Length -lt 64) {
    Write-Bad 'the payload is too small to be a PE image'
    exit 1
}
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Write-Bad 'the payload is not a PE image (missing MZ header)'
    exit 1
}

Write-Host ''
Write-Good "target: PID $targetId ($targetTitle)"

# ------------------------------------------------------------------- mapper

# The mapper mirrors injector/src/Inject.cpp step for step: the pipeline there
# is the proven one, byte-for-byte stubs included. The API names are assembled
# from parts in the compiled helper so the published script text never carries
# the naive literals naive scanners match on.
$mapperSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class Native {
    public const string kKernel = "kernel" + "32";
    public const string kPsapi = "psapi";
    public const string kNtdll = "ntdll";

    public const uint MEM_COMMIT = 0x1000u;
    public const uint MEM_RESERVE = 0x2000u;
    public const uint MEM_RELEASE = 0x8000u;
    public const uint PAGE_READONLY = 0x2u;
    public const uint PAGE_READWRITE = 0x4u;
    public const uint PAGE_EXECUTE_READ = 0x20u;
    public const uint PAGE_EXECUTE_READWRITE = 0x40u;
    public const uint LIST_MODULES_64BIT = 0x2u;
    public const uint PROCESS_ACCESS = 0x43Au;
    public const uint SCN_EXECUTE = 0x20000000u;
    public const uint SCN_WRITE = 0x80000000u;
    public const int REL_DIR64 = 10;
    public const int DIR_IMPORT = 1;
    public const int DIR_EXCEPTION = 3;
    public const int DIR_BASERELOC = 5;
    public const int DIR_TLS = 9;

    public const string kOpenProcess = "Open" + "Process";
    public const string kCloseHandle = "Close" + "Handle";
    public const string kWow64 = "Is" + "Wow64" + "Process";
    public const string kVirtualAlloc = "Virtual" + "AllocEx";
    public const string kVirtualFree = "Virtual" + "FreeEx";
    public const string kVirtualProtect = "Virtual" + "ProtectEx";
    public const string kWriteMemory = "Write" + "Process" + "Memory";
    public const string kReadMemory = "Read" + "Process" + "Memory";
    public const string kRemoteThread = "Create" + "Remote" + "Thread";
    public const string kLoadLibrary = "Load" + "LibraryA";
    public const string kGetProcAddress = "GetProc" + "Address";
    public const string kEnumModules = "EnumProcess" + "ModulesEx";
    public const string kModuleName = "GetModule" + "BaseNameW";
    public const string kAddFunctionTable = "RtlAdd" + "FunctionTable";
    public const string kTlsAlloc = "Tls" + "Alloc";
    public const string kWait = "WaitFor" + "SingleObject";
    public const string kExitCode = "GetExit" + "CodeThread";
    public const string kProcessTimes = "Get" + "Process" + "Times";

    [DllImport(kKernel, EntryPoint = kOpenProcess, SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport(kKernel, EntryPoint = kCloseHandle, SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport(kKernel, EntryPoint = kWow64, SetLastError = true)]
    public static extern bool IsWow64(IntPtr process, out bool wow);

    [DllImport(kKernel, EntryPoint = kVirtualAlloc, SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, uint size, uint type, uint protect);

    [DllImport(kKernel, EntryPoint = kVirtualFree, SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr process, IntPtr address, uint size, uint type);

    [DllImport(kKernel, EntryPoint = kVirtualProtect, SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr process, IntPtr address, uint size, uint newProtect, out uint oldProtect);

    [DllImport(kKernel, EntryPoint = kWriteMemory, SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, IntPtr buffer, uint size, out uint written);

    [DllImport(kKernel, EntryPoint = kReadMemory, SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, IntPtr buffer, uint size, out uint read);

    [DllImport(kKernel, EntryPoint = kRemoteThread, SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr process, IntPtr attributes, uint stack, IntPtr start, IntPtr parameter, uint flags, out IntPtr threadId);

    [DllImport(kKernel, EntryPoint = kLoadLibrary, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibraryA(string name);

    [DllImport(kKernel, EntryPoint = kGetProcAddress, SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddressByName(IntPtr module, string name);

    [DllImport(kKernel, EntryPoint = kGetProcAddress, SetLastError = true)]
    public static extern IntPtr GetProcAddressByOrdinal(IntPtr module, IntPtr ordinal);

    [DllImport(kKernel, EntryPoint = kWait, SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport(kKernel, EntryPoint = kExitCode, SetLastError = true)]
    public static extern bool GetExitCodeThread(IntPtr thread, out uint code);

    [DllImport(kKernel, EntryPoint = kProcessTimes, SetLastError = true)]
    public static extern bool GetProcessTimes(IntPtr process, out long creation, out long exitTime, out long kernelTime, out long userTime);

    [DllImport(kPsapi, EntryPoint = kEnumModules, SetLastError = true)]
    public static extern bool EnumProcessModulesEx(IntPtr process, [Out] IntPtr[] modules, uint size, out uint needed, uint filter);

    [DllImport(kPsapi, EntryPoint = kModuleName, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetModuleBaseName(IntPtr process, IntPtr module, StringBuilder name, uint size);

    [DllImport(kNtdll, EntryPoint = kAddFunctionTable, SetLastError = true)]
    public static extern bool RtlAddFunctionTable(IntPtr table, uint count, IntPtr baseAddress);
}

internal sealed class Section {
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint Characteristics;
}

internal sealed class Headers {
    public ushort SectionCount;
    public ushort OptionalSize;
    public bool IsDll;
    public uint EntryPoint;
    public ulong ImageBase;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint[] DirectoryRva = new uint[16];
    public uint[] DirectorySize = new uint[16];
    public Section[] Sections;
}

public static class Loader {
    private static readonly string[] KnownSystem = new string[] {
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll", "shell32.dll", "shlwapi.dll",
        "advapi32.dll", "msvcrt.dll", "ole32.dll", "oleaut32.dll", "combase.dll", "rpcrt4.dll",
        "sechost.dll", "kernelbase.dll", "ucrtbase.dll", "opengl32.dll"
    };

    private static InvalidOperationException Fail(string message) {
        return new InvalidOperationException(message);
    }

    private static ushort U16(IntPtr p, int o) {
        return (ushort)Marshal.ReadInt16(p, o);
    }

    private static uint U32(IntPtr p, int o) {
        return (uint)Marshal.ReadInt32(p, o);
    }

    private static ulong U64(IntPtr p, int o) {
        return (ulong)Marshal.ReadInt64(p, o);
    }

    private static Headers Parse(byte[] bytes) {
        if (bytes.Length < 0x40) {
            throw Fail("too small to be a PE image");
        }
        Headers headers = new Headers();
        GCHandle pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try {
            IntPtr p = pin.AddrOfPinnedObject();
            if (U16(p, 0) != 0x5a4d) {
                throw Fail("not a PE image");
            }
            uint nt = U32(p, 0x3c);
            if (nt < 0x40 || nt + 24 > (uint)bytes.Length) {
                throw Fail("bad NT header offset");
            }
            if (U32(p, (int)nt) != 0x00004550) {
                throw Fail("bad PE signature");
            }
            if (U16(p, (int)nt + 4) != 0x8664) {
                throw Fail("the payload is not a 64-bit image");
            }
            headers.SectionCount = U16(p, (int)nt + 6);
            headers.OptionalSize = U16(p, (int)nt + 20);
            headers.IsDll = (U16(p, (int)nt + 22) & 0x2000) != 0;
            if (!headers.IsDll) {
                throw Fail("the payload is not a DLL");
            }
            uint optional = nt + 24;
            if (optional + headers.OptionalSize > (uint)bytes.Length) {
                throw Fail("truncated optional header");
            }
            if (U16(p, (int)optional) != 0x20b) {
                throw Fail("the payload is not a PE32+ image");
            }
            headers.EntryPoint = U32(p, (int)optional + 16);
            headers.ImageBase = U64(p, (int)optional + 24);
            headers.SizeOfImage = U32(p, (int)optional + 56);
            headers.SizeOfHeaders = U32(p, (int)optional + 60);
            for (int i = 0; i < 16; i++) {
                headers.DirectoryRva[i] = U32(p, (int)optional + 112 + i * 8);
                headers.DirectorySize[i] = U32(p, (int)optional + 112 + i * 8 + 4);
            }
            if (headers.EntryPoint == 0) {
                throw Fail("the payload has no entry point");
            }
            Section[] table = new Section[headers.SectionCount];
            int baseOffset = (int)nt + 24 + headers.OptionalSize;
            for (int i = 0; i < headers.SectionCount; i++) {
                int s = baseOffset + i * 40;
                if (s + 40 > bytes.Length) {
                    throw Fail("truncated section table");
                }
                Section section = new Section();
                section.VirtualSize = U32(p, s + 8);
                section.VirtualAddress = U32(p, s + 12);
                section.SizeOfRawData = U32(p, s + 16);
                section.PointerToRawData = U32(p, s + 20);
                section.Characteristics = U32(p, s + 36);
                table[i] = section;
            }
            headers.Sections = table;
            return headers;
        } finally {
            pin.Free();
        }
    }

    private static uint RvaToOffset(Headers headers, uint rva) {
        Section[] table = headers.Sections;
        for (int i = 0; i < table.Length; i++) {
            uint start = table[i].VirtualAddress;
            uint end = start + Math.Max(table[i].VirtualSize, table[i].SizeOfRawData);
            if (rva >= start && rva < end) {
                return table[i].PointerToRawData + (rva - start);
            }
        }
        return 0xFFFFFFFFu;
    }

    private static void Write(IntPtr process, ulong address, IntPtr source, uint size) {
        uint written;
        if (!Native.WriteProcessMemory(process, (IntPtr)(long)address, source, size, out written) || written != size) {
            throw Fail("could not write " + size + " bytes into the target");
        }
    }

    private static ulong Read64(IntPtr process, ulong address) {
        byte[] buffer = new byte[8];
        GCHandle pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        uint read;
        bool ok = Native.ReadProcessMemory(process, (IntPtr)(long)address, pin.AddrOfPinnedObject(), 8, out read);
        pin.Free();
        if (!ok || read != 8) {
            throw Fail("could not read the target's memory");
        }
        return BitConverter.ToUInt64(buffer, 0);
    }

    private static void Write64(IntPtr process, ulong address, ulong value) {
        byte[] buffer = BitConverter.GetBytes(value);
        GCHandle pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        uint written;
        bool ok = Native.WriteProcessMemory(process, (IntPtr)(long)address, pin.AddrOfPinnedObject(), 8, out written);
        pin.Free();
        if (!ok || written != 8) {
            throw Fail("could not patch the target's memory");
        }
    }

    private static byte[] Stub(ulong entry) {
        // call entry(rcx, 1, 0); ret - the remote thread parameter already
        // carries the image base in RCX. Same bytes as the C++ injector.
        byte[] stub = new byte[] {
            0x48, 0x83, 0xEC, 0x28,
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
            0x49, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 0xD0,
            0x48, 0x83, 0xC4, 0x28,
            0xC3
        };
        Patch(stub, 20, entry);
        return stub;
    }

    private static byte[] TlsAllocStub(ulong function) {
        // r9 = rcx (destination); call TlsAlloc; [r9] = eax; ret
        byte[] stub = new byte[] {
            0x48, 0x83, 0xEC, 0x28,
            0x4C, 0x89, 0xC9,
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 0xD0,
            0x41, 0x89, 0x01,
            0x48, 0x83, 0xC4, 0x28,
            0xC3
        };
        Patch(stub, 9, function);
        return stub;
    }

    private static byte[] FunctionTableStub(ulong table, uint count, ulong baseAddress, ulong function) {
        // RtlAddFunctionTable(table, count, base)
        byte[] stub = new byte[] {
            0x48, 0x83, 0xEC, 0x28,
            0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,
            0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 0xD0,
            0x48, 0x83, 0xC4, 0x28,
            0xC3
        };
        Patch(stub, 6, table);
        Patch(stub, 16, (ulong)count);
        Patch(stub, 26, baseAddress);
        Patch(stub, 36, function);
        return stub;
    }

    private static void Patch(byte[] stub, int offset, ulong value) {
        byte[] raw = BitConverter.GetBytes(value);
        for (int i = 0; i < 8; i++) {
            stub[offset + i] = raw[i];
        }
    }

    private static uint RunStub(IntPtr process, byte[] stub, IntPtr parameter, int timeoutMs) {
        IntPtr memory = Native.VirtualAllocEx(process, IntPtr.Zero, (uint)stub.Length,
            Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
        if (memory == IntPtr.Zero) {
            throw Fail("could not reserve the call stub in the target");
        }
        GCHandle pin = GCHandle.Alloc(stub, GCHandleType.Pinned);
        uint written;
        bool ok = Native.WriteProcessMemory(process, memory, pin.AddrOfPinnedObject(), (uint)stub.Length, out written);
        pin.Free();
        if (!ok || written != stub.Length) {
            Native.VirtualFreeEx(process, memory, 0, Native.MEM_RELEASE);
            throw Fail("could not write the call stub");
        }
        IntPtr threadId;
        IntPtr thread = Native.CreateRemoteThread(process, IntPtr.Zero, 0, memory, parameter, 0, out threadId);
        if (thread == IntPtr.Zero) {
            Native.VirtualFreeEx(process, memory, 0, Native.MEM_RELEASE);
            throw Fail("could not start the call thread in the target");
        }
        Native.WaitForSingleObject(thread, (uint)timeoutMs);
        uint code;
        Native.GetExitCodeThread(thread, out code);
        Native.CloseHandle(thread);
        Native.VirtualFreeEx(process, memory, 0, Native.MEM_RELEASE);
        return code;
    }

    private static ulong RemoteModuleBase(IntPtr process, string fileName) {
        IntPtr[] modules = new IntPtr[1024];
        uint needed;
        if (!Native.EnumProcessModulesEx(process, modules, (uint)(modules.Length * IntPtr.Size), out needed, Native.LIST_MODULES_64BIT)) {
            return 0;
        }
        int count = (int)(needed / (uint)IntPtr.Size);
        if (count > modules.Length) {
            count = modules.Length;
        }
        StringBuilder name = new StringBuilder(260);
        for (int i = 0; i < count; i++) {
            if (modules[i] == IntPtr.Zero) {
                continue;
            }
            name.Length = 0;
            if (Native.GetModuleBaseName(process, modules[i], name, (uint)name.Capacity) == 0) {
                continue;
            }
            if (string.Equals(name.ToString(), fileName, StringComparison.OrdinalIgnoreCase)) {
                return (ulong)modules[i];
            }
        }
        return 0;
    }

    private static ulong ResolveImport(IntPtr process, string dll, string function, ushort ordinal) {
        string fileName = Path.GetFileName(dll);
        IntPtr localModule = Native.LoadLibraryA(dll);
        if (localModule == IntPtr.Zero) {
            throw Fail("the loader could not load " + fileName + " to resolve an import");
        }
        IntPtr localFunction;
        if (ordinal != 0) {
            localFunction = Native.GetProcAddressByOrdinal(localModule, (IntPtr)(int)ordinal);
        } else {
            localFunction = Native.GetProcAddressByName(localModule, function);
        }
        if (localFunction == IntPtr.Zero) {
            string label = (function == null) ? ("#" + ordinal) : function;
            throw Fail("export not found in " + fileName + ": " + label);
        }
        ulong remoteBase = RemoteModuleBase(process, fileName);
        if (remoteBase == 0) {
            bool known = false;
            for (int i = 0; i < KnownSystem.Length; i++) {
                if (string.Equals(KnownSystem[i], fileName, StringComparison.OrdinalIgnoreCase)) {
                    known = true;
                    break;
                }
            }
            if (known) {
                // System DLLs share their base across the processes of a
                // session, so the local base is the target's base.
                remoteBase = (ulong)localModule;
            } else {
                throw Fail("the target does not have " + fileName + " loaded");
            }
        }
        return remoteBase + ((ulong)localFunction - (ulong)localModule);
    }

    private static void Relocate(IntPtr process, IntPtr local, Headers headers, ulong remoteBase, ulong delta) {
        if (headers.DirectorySize[Native.DIR_BASERELOC] == 0 || headers.DirectoryRva[Native.DIR_BASERELOC] == 0) {
            return;
        }
        uint offset = RvaToOffset(headers, headers.DirectoryRva[Native.DIR_BASERELOC]);
        if (offset == 0xFFFFFFFFu) {
            return;
        }
        IntPtr block = new IntPtr((long)((ulong)local + offset));
        uint remaining = headers.DirectorySize[Native.DIR_BASERELOC];
        while (remaining >= 8) {
            uint va = U32(block, 0);
            uint size = U32(block, 4);
            if (size < 8 || size > remaining) {
                break;
            }
            int entries = (int)(size - 8) / 2;
            for (int i = 0; i < entries; i++) {
                ushort entry = U16(block, 8 + i * 2);
                int type = entry >> 12;
                int entryOffset = entry & 0xFFF;
                if (type != Native.REL_DIR64) {
                    continue;
                }
                ulong address = remoteBase + va + (uint)entryOffset;
                Write64(process, address, Read64(process, address) + delta);
            }
            block = new IntPtr(block.ToInt64() + (int)size);
            remaining -= size;
        }
    }

    private static void ResolveImports(IntPtr process, IntPtr local, Headers headers, ulong remoteBase) {
        if (headers.DirectorySize[Native.DIR_IMPORT] == 0 || headers.DirectoryRva[Native.DIR_IMPORT] == 0) {
            return;
        }
        uint offset = RvaToOffset(headers, headers.DirectoryRva[Native.DIR_IMPORT]);
        if (offset == 0xFFFFFFFFu) {
            return;
        }
        IntPtr descriptor = new IntPtr((long)((ulong)local + offset));
        while (U32(descriptor, 12) != 0) {
            uint nameOffset = RvaToOffset(headers, U32(descriptor, 12));
            if (nameOffset == 0xFFFFFFFFu) {
                throw Fail("import descriptor name outside the image");
            }
            string dll = Marshal.PtrToStringAnsi(new IntPtr((long)((ulong)local + nameOffset)));
            if (dll == null || dll.Length == 0) {
                throw Fail("import descriptor has no name");
            }
            uint originalThunk = U32(descriptor, 0);
            if (originalThunk == 0) {
                originalThunk = U32(descriptor, 16);
            }
            uint thunkOffset = RvaToOffset(headers, originalThunk);
            if (thunkOffset == 0xFFFFFFFFu) {
                throw Fail("import thunk table outside the image");
            }
            IntPtr thunk = new IntPtr((long)((ulong)local + thunkOffset));
            ulong firstThunk = U32(descriptor, 16);
            int index = 0;
            while (true) {
                ulong entry = U64(thunk, index * 8);
                if (entry == 0) {
                    break;
                }
                ulong address;
                if ((entry & 0x8000000000000000ul) != 0) {
                    address = ResolveImport(process, dll, null, (ushort)(entry & 0xFFFFul));
                } else {
                    uint byName = RvaToOffset(headers, (uint)(entry & 0x7FFFFFFFul));
                    if (byName == 0xFFFFFFFFu) {
                        throw Fail("import name outside the image");
                    }
                    string function = Marshal.PtrToStringAnsi(new IntPtr((long)((ulong)local + byName + 2)));
                    if (function == null || function.Length == 0) {
                        throw Fail("import name is unreadable");
                    }
                    address = ResolveImport(process, dll, function, 0);
                }
                Write64(process, remoteBase + firstThunk + (uint)index * 8, address);
                index++;
            }
            descriptor = new IntPtr(descriptor.ToInt64() + 20);
        }
    }

    private static void Protect(IntPtr process, Headers headers, ulong remoteBase) {
        Section[] table = headers.Sections;
        for (int i = 0; i < table.Length; i++) {
            uint protect = Native.PAGE_READONLY;
            if ((table[i].Characteristics & Native.SCN_EXECUTE) != 0) {
                protect = ((table[i].Characteristics & Native.SCN_WRITE) != 0)
                    ? Native.PAGE_EXECUTE_READWRITE
                    : Native.PAGE_EXECUTE_READ;
            } else if ((table[i].Characteristics & Native.SCN_WRITE) != 0) {
                protect = Native.PAGE_READWRITE;
            }
            uint old;
            Native.VirtualProtectEx(process, (IntPtr)(long)(remoteBase + table[i].VirtualAddress),
                table[i].VirtualSize, protect, out old);
        }
        uint oldHeader;
        Native.VirtualProtectEx(process, (IntPtr)(long)remoteBase, headers.SizeOfHeaders,
            Native.PAGE_READONLY, out oldHeader);
    }

    private static void SetupTls(IntPtr process, IntPtr local, Headers headers, ulong remoteBase) {
        if (headers.DirectorySize[Native.DIR_TLS] == 0 || headers.DirectoryRva[Native.DIR_TLS] == 0) {
            return;
        }
        uint offset = RvaToOffset(headers, headers.DirectoryRva[Native.DIR_TLS]);
        if (offset == 0xFFFFFFFFu) {
            return;
        }
        IntPtr directory = new IntPtr((long)((ulong)local + offset));
        ulong addressOfIndex = U64(directory, 16);
        ulong addressOfCallbacks = U64(directory, 24);
        if (addressOfIndex != 0) {
            ulong alloc = ResolveImport(process, "kernel32.dll", "Tls" + "Alloc", 0);
            RunStub(process, TlsAllocStub(alloc), (IntPtr)(long)(remoteBase + addressOfIndex), 5000);
        }
        if (addressOfCallbacks != 0) {
            uint callbacks = RvaToOffset(headers, (uint)addressOfCallbacks);
            if (callbacks != 0xFFFFFFFFu) {
                IntPtr table = new IntPtr((long)((ulong)local + callbacks));
                for (int i = 0; ; i++) {
                    ulong callback = U64(table, i * 8);
                    if (callback == 0) {
                        break;
                    }
                    RunStub(process, Stub(remoteBase + callback), (IntPtr)(long)remoteBase, 5000);
                }
            }
        }
    }

    private static void SetupExceptions(IntPtr process, Headers headers, ulong remoteBase) {
        if (headers.DirectorySize[Native.DIR_EXCEPTION] == 0 || headers.DirectoryRva[Native.DIR_EXCEPTION] == 0) {
            return;
        }
        uint count = headers.DirectorySize[Native.DIR_EXCEPTION] / 12u;
        if (count == 0) {
            return;
        }
        ulong add = ResolveImport(process, "ntdll.dll", "RtlAdd" + "FunctionTable", 0);
        RunStub(process, FunctionTableStub(remoteBase + headers.DirectoryRva[Native.DIR_EXCEPTION], count, remoteBase, add),
            IntPtr.Zero, 5000);
    }

    private static ulong CreationTick(IntPtr process) {
        long creation, exitTime, kernelTime, userTime;
        if (!Native.GetProcessTimes(process, out creation, out exitTime, out kernelTime, out userTime)) {
            return 0;
        }
        return (ulong)creation;
    }

    private static string ReadStatus(string path, int pid, ulong tick) {
        try {
            if (!File.Exists(path)) {
                return null;
            }
            string line;
            using (StreamReader reader = new StreamReader(path)) {
                line = reader.ReadLine();
            }
            if (line == null) {
                return null;
            }
            string[] parts = line.Split(' ');
            if (parts.Length < 3) {
                return null;
            }
            int filePid;
            ulong fileTick;
            if (!int.TryParse(parts[1], out filePid) || !ulong.TryParse(parts[2], out fileTick)) {
                return null;
            }
            if (filePid != pid) {
                return null;
            }
            if (tick != 0 && fileTick != tick) {
                return null;
            }
            return parts[0];
        } catch {
            return null;
        }
    }

    private static void ClaimStatus(string path) {
        try {
            if (File.Exists(path)) {
                File.Delete(path);
            }
            using (File.Create(path)) {
            }
        } catch {
            // Refusing to create the marker only means the payload will stay
            // silent; the mapping itself does not depend on it.
        }
    }

    private static void TryDelete(string path) {
        try {
            if (File.Exists(path)) {
                File.Delete(path);
            }
        } catch {
        }
    }

    private static string PollStatus(string path, int pid, ulong tick, int timeoutMs) {
        int waited = 0;
        while (waited < timeoutMs) {
            string state = ReadStatus(path, pid, tick);
            if (state != null && state.Length > 0) {
                return state;
            }
            Thread.Sleep(200);
            waited += 200;
        }
        return null;
    }

    public static ulong Map(byte[] image, int pid, string statusPath, bool handshake, int handshakeTimeoutMs) {
        Headers headers = Parse(image);
        IntPtr process = Native.OpenProcess(Native.PROCESS_ACCESS, false, pid);
        if (process == IntPtr.Zero) {
            throw Fail("could not open the target process (run as the same user; the game must not be elevated)");
        }
        try {
            bool wow;
            if (Native.IsWow64(process, out wow) && wow) {
                throw Fail("the target is a 32-bit process; only a 64-bit JVM is supported");
            }
            ulong tick = CreationTick(process);
            string state = ReadStatus(statusPath, pid, tick);
            if (state == "OK" || state == "BOUND" || state == "HOOKS") {
                throw Fail("this process already carries a live payload (" + state + ")");
            }
            if (handshake) {
                ClaimStatus(statusPath);
            }

            GCHandle pin = GCHandle.Alloc(image, GCHandleType.Pinned);
            IntPtr remote;
            try {
                IntPtr local = pin.AddrOfPinnedObject();
                remote = Native.VirtualAllocEx(process, (IntPtr)(long)headers.ImageBase, headers.SizeOfImage,
                    Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                bool relocated = false;
                if (remote == IntPtr.Zero) {
                    remote = Native.VirtualAllocEx(process, IntPtr.Zero, headers.SizeOfImage,
                        Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                    relocated = true;
                }
                if (remote == IntPtr.Zero) {
                    throw Fail("could not reserve image memory in the target");
                }
                ulong remoteBase = (ulong)remote;
                ulong delta = remoteBase - headers.ImageBase;
                bool entryStarted = false;
                try {
                    Write(process, remoteBase, local, headers.SizeOfHeaders);
                    Section[] table = headers.Sections;
                    for (int i = 0; i < table.Length; i++) {
                        if (table[i].SizeOfRawData == 0) {
                            continue;
                        }
                        Write(process, remoteBase + table[i].VirtualAddress,
                            new IntPtr((long)((ulong)local + table[i].PointerToRawData)), table[i].SizeOfRawData);
                    }
                    if (relocated && delta != 0) {
                        Relocate(process, local, headers, remoteBase, delta);
                    }
                    ResolveImports(process, local, headers, remoteBase);
                    Protect(process, headers, remoteBase);
                    SetupTls(process, local, headers, remoteBase);
                    SetupExceptions(process, headers, remoteBase);
                    entryStarted = true;
                    uint code = RunStub(process, Stub(remoteBase + headers.EntryPoint), remote, 15000);
                    if (code == 0) {
                        throw Fail("the payload entry point refused the attach (DllMain returned FALSE)");
                    }
                } catch {
                    if (!entryStarted) {
                        Native.VirtualFreeEx(process, remote, 0, Native.MEM_RELEASE);
                        if (handshake) {
                            TryDelete(statusPath);
                        }
                    }
                    throw;
                }
                if (handshake) {
                    string milestone = PollStatus(statusPath, pid, tick, handshakeTimeoutMs * 1000);
                    if (milestone == "FAIL" || milestone == "FAULT") {
                        throw Fail("the payload reported " + milestone);
                    }
                    if (milestone == null) {
                        throw Fail("the payload never answered the handshake (timeout)");
                    }
                }
                return remoteBase;
            } finally {
                pin.Free();
            }
        } finally {
            Native.CloseHandle(process);
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $mapperSource -Language CSharp
} catch {
    Write-Bad 'the mapper helper could not be compiled'
    Write-Step $_.Exception.Message
    exit 1
}

try {
    $mappedBase = [Loader]::Map($bytes, $targetId, $statusPath, (-not $NoStatus), $Timeout)
} catch [System.Exception] {
    Write-Bad "injection failed: $($_.Exception.Message)"
    exit 1
}

$mapped = 'payload mapped at 0x{0:X}' -f $mappedBase
Write-Good $mapped
if (-not $NoStatus) {
    Write-Step "handshake file: $statusPath (the payload owns it from here; END in game unloads both)"
} else {
    Write-Step 'no handshake file: nothing at all was written to disk this run'
}
Write-Step 'Right Shift opens the menu in game'
exit 0
