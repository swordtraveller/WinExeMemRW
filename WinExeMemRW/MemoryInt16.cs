using System.Runtime.InteropServices;

public class MemoryInt16
{
    public IntPtr BasicAddress;
    public IntPtr Offset { get; }
    public uint LastError;
    public IntPtr ProcessHandle;

    public MemoryInt16(IntPtr BasicAddress, IntPtr Offset, IntPtr ProcessHandle)
    {
        this.BasicAddress = BasicAddress;
        this.Offset = Offset;
        this.ProcessHandle = ProcessHandle;
    }

    public Int16 Get()
    {
        var buffer = new byte[2];
        if (!ReadProcessMemory(
                ProcessHandle,
                BasicAddress + Offset,
                buffer,
                2,
                IntPtr.Zero)
            )
        {
            // fail
            LastError = GetLastError();
            throw new ArgumentException("ReadProcessMemory failed");
        } else {
            // success
            return BitConverter.ToInt16(buffer, 0);
        }
    }

    public void Set(Int16 input)
    {
        // pre-check
        MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
        int queryResult = VirtualQueryEx(ProcessHandle, BasicAddress + Offset, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
        if (queryResult == 0)
        {
            // fail
            LastError = GetLastError();
            throw new ArgumentException("VirtualQueryEx failed");
        }
        
        // check it can be written
        uint oldProtect;
        if ((mbi.Protect & PAGE_READWRITE) == 0 && (mbi.Protect & PAGE_EXECUTE_READWRITE) == 0)
        {
            // memory can not be written, and try to make it can be written
            if (!VirtualProtectEx(ProcessHandle, BasicAddress + Offset, (uint)mbi.RegionSize.ToInt64(), PAGE_READWRITE, out oldProtect))
            {
                // fail
                LastError = GetLastError();
                throw new ArgumentException("VirtualQueryEx failed");
            }

            // Console.WriteLine("内存保护属性已更改为可写。");
        }

        var buffer = BitConverter.GetBytes(input);
        if (!WriteProcessMemory(
                ProcessHandle,
                BasicAddress + Offset,
                buffer,
                2,
                IntPtr.Zero)
           )
        {
            // fail
            LastError = GetLastError();
            throw new ArgumentException("WriteProcessMemory failed");
        }
        
        // 恢复原来的保护属性
        if ((mbi.Protect & PAGE_READWRITE) == 0 && (mbi.Protect & PAGE_EXECUTE_READWRITE) == 0)
        {
            VirtualProtectEx(ProcessHandle, BasicAddress + Offset, (uint)mbi.RegionSize.ToInt64(), mbi.Protect, out oldProtect);
            // Console.WriteLine("内存保护属性已恢复到原来的状态。");
        }
    }

    [DllImport("kernel32.dll")]
    static extern uint GetLastError();
    
    // ReadProcessMemory
    // hProcess 目标进程句柄。句柄必须具有对进程的 PROCESS_VM_WRITE 和 PROCESS_VM_OPERATION 访问权限。
    // lpBaseAddress 目标进程内存基址
    // lpBuffer 缓冲区
    // nSize 需要读取的字节数
    // lpNumberOfBytesRead 实际读取的字节数，如不需要可传IntPtr.Zero
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesRead);
    
    // WriteProcessMemory
    // https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    // hProcess 要修改的进程内存的句柄
    // lpBaseAddress 指向将数据写入到的指定进程中基址的指针
    // lpBuffer 指向缓冲区的指针
    // nSize 要写入指定进程的字节数
    // lpNumberOfBytesRead 指向变量的指针，该变量接收传输到指定进程的字节数。 此参数是可选的。 如果 lpNumberOfBytesWritten 为 NULL，则忽略参数。
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesWritten);
    
    // VirtualQueryEx
    // https://www.pinvoke.net/default.aspx/kernel32.virtualqueryex
    // hProcess 进程的句柄
    // lpAddress 为要分配的页面区域指定所需起始地址的指针
    // mbi
    // dwLength
    // 导入 VirtualQueryEx 函数
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        uint dwLength
    );
    
    [StructLayout(LayoutKind.Sequential)]
    struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    };
    
    // 导入 VirtualProtectEx
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(
        IntPtr hProcess, 
        IntPtr lpAddress, 
        uint dwSize, 
        uint flNewProtect, 
        out uint lpflOldProtect
    );
    
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
}