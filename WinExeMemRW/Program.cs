// refer to https://codingvision.net/c-read-write-another-process-memory

using System.Diagnostics;
using System.Runtime.InteropServices;

// import
[DllImport("kernel32.dll")]
static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

[DllImport("kernel32.dll")]
static extern uint GetLastError();

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr nSize, IntPtr lpNumberOfBytesRead);

// get pid
Console.WriteLine("输入需要分析的进程PID");
var pid = Convert.ToInt32(Console.ReadLine());

// read memory
var process = Process.GetProcessById(pid);
Console.WriteLine("准备分析 [{0}] {1}", pid, process.MainModule?.ModuleName??"Missing MainModule");

IntPtr startOffset = process.MainModule.BaseAddress;
IntPtr endOffset = IntPtr.Add(startOffset, process.MainModule.ModuleMemorySize);

Console.WriteLine("起始地址 [{0}]", startOffset);
Console.WriteLine("末端地址 [{0}]", endOffset);
Console.WriteLine("空间大小 {0}", process.MainModule.ModuleMemorySize);

const int PROCESS_ALL_ACCESS = 0xffff;
const int PROCESS_VM_OPERATION = 0x08;
const int PROCESS_VM_READ = 0x10;
const int PROCESS_VM_WRITE = 0x20;

var processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, process.Id);
if (processHandle == IntPtr.Zero)
{
    Console.WriteLine("进程打开失败");
    return 255;
}

var buffer = new byte[process.MainModule.ModuleMemorySize];
// read all memory
// nSize 不能超过 process.MainModule.ModuleMemorySize，否则会失败
if (!ReadProcessMemory(processHandle, startOffset, buffer, process.MainModule.ModuleMemorySize, IntPtr.Zero))
{
    Console.WriteLine("ReadProcessMemory Failed");
    Console.WriteLine(GetLastError());
    Console.WriteLine(Marshal.GetLastWin32Error());
    return 255;
}

Console.WriteLine("内存加载成功");
Console.WriteLine("输入要搜索的数值后回车搜索，如47");
var input = Int16.Parse(Console.ReadLine());
Console.WriteLine("开始搜索{0}，请耐心等待...", input);

// 用于保存命中结果
var hits = new List<MemoryInt16>{};

// search input in memory
for (var i = 0; i + 1 <= process.MainModule.ModuleMemorySize - 1; i++)
{
    var value = BitConverter.ToInt16(buffer, i);
    if (value == input)
    {
        Console.WriteLine("[{0}] {1}", startOffset + i, value);
        hits.Add(new MemoryInt16(startOffset, i, processHandle));
    }
}
Console.WriteLine("搜索结束，共命中{0}个结果", hits.Count);
const String helpMessage = "输入w或watch回车查看当前命中变量\n输入s或set回车可修改变量\n输入f或filter回车可在当前命中结果中观测新的值\n输入h或help回车可显示帮助信息\n输入q或quit或e或exit退出";
Console.WriteLine(helpMessage);

while (true)
{
    var command = Console.ReadLine();
    if (command == "watch" || command == "w")
    {
        foreach (var hit in hits)
        {
            Console.WriteLine("[{0}] {1}", hit.Offset, hit.Get());
        }
    }
    else if (command == "set" || command == "s")
    {
        Console.WriteLine("请输入要设置的值");
        var setValue = Int16.Parse(Console.ReadLine());
        foreach (var hit in hits)
        {
            try
            {
                hit.Set(setValue);
            }
            catch (Exception e)
            {
                Console.WriteLine("设置失败，异常信息：{0}", e);
                Console.WriteLine("错误信息：{0}", hit.LastError);
                Console.WriteLine("继续寻找是否有下个可设置的结果", e);
            }
        }
        Console.WriteLine("遍历结束");
    } else if (command == "filter" || command == "f") {
        Console.WriteLine("请输入要观测的新值");
        var value = Int16.Parse(Console.ReadLine());
        var newHits = new List<MemoryInt16> {};
        foreach (var hit in hits)
        {
            if (hit.Get() == value)
            {
                newHits.Add(new MemoryInt16(
                        hit.BasicAddress,
                        hit.Offset,
                        hit.ProcessHandle
                    ));
            }
        }
        hits = newHits;
        Console.WriteLine("搜索结束，共命中{0}个结果", hits.Count);
    } else if (command == "quit" || command == "q" || command == "exit" || command == "e")
    {
        return 0;
    } else if (command == "help" || command == "h")
    {
        Console.WriteLine(helpMessage);
    }
    else {
        Console.WriteLine("无效指令。请重新输入指令。");
    }
}
