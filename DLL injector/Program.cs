using System.Diagnostics;
using System.Runtime.InteropServices;

[DllImport("kernel32.dll")]
 static extern IntPtr LoadLibrary(string dllToLoad);

[DllImport("kernel32.dll")]
 static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

[DllImport("kernel32.dll")]
 static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
    uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
 static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
    uint dwSize, uint dwFreeType);

[DllImport("kernel32.dll")]
 static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    byte[] buffer, uint size, out int lpNumberOfBytesWritten);

[DllImport("kernel32.dll")]
 static extern IntPtr CreateRemoteThread(IntPtr hProcess,
    IntPtr lpThreadAttribute, uint dwStackSize, IntPtr lpStartAddress,
    IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


    if (args.Length != 2)
    {
        Console.WriteLine("Usage: DllInjector.exe [pid] [dll path]");
        return;
    }
    int pid = int.Parse(args[0]);
    string dllPath = args[1];

    Process process = Process.GetProcessById(pid);

    IntPtr hModule = LoadLibrary(dllPath);
    if (hModule == IntPtr.Zero)
    {
        Console.WriteLine("Failed to load library");
        return;
    }

    IntPtr hThread = IntPtr.Zero;
    IntPtr lpParameter = IntPtr.Zero;
    int lpNumberOfBytesWritten = 0;
    IntPtr lpAddress = VirtualAllocEx(process.Handle, IntPtr.Zero, (uint)dllPath.Length, 0x1000, 0x40);
    if (lpAddress == IntPtr.Zero)
    {
        Console.WriteLine("Failed to allocate memory in target process");
        return;
    }

    if (!WriteProcessMemory(process.Handle, lpAddress, System.Text.Encoding.ASCII.GetBytes(dllPath), (uint)dllPath.Length, out lpNumberOfBytesWritten))
    {
        Console.WriteLine("Failed to write to memory in target process");
        return;
    }

    IntPtr lpStartAddress = GetProcAddress(hModule, "LoadLibraryA");
    if (lpStartAddress == IntPtr.Zero)
    {
        Console.WriteLine("Failed to get address of LoadLibraryA function");
        return;
    }

    hThread = CreateRemoteThread(process.Handle, IntPtr.Zero, 0, lpStartAddress, lpAddress, 0, IntPtr.Zero);
    if (hThread == IntPtr.Zero)
    {
        Console.WriteLine("Failed to create remote thread in target process");
        return;
    }

    Console.WriteLine("Successfully injected DLL into process");

