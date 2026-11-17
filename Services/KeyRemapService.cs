// KeyRemapService.cs - 物理键改键 (OmenXHub 版)
// 把 OMEN 键 / 计算器键 / Insert / PrtSc 改成 Home / End / PageUp / PageDown 等常用键。
//
// 两条通道:
//   1. OMEN 键: 不产生键盘扫描码(BIOS 走 WMI 事件),由 OmenHardware.OmenKeyPressed 驱动注入;
//      与 Omen 键功能绑定互斥 —— ConfigService.OmenKey 不是 "none" 时本项自动失效。
//   2. 计算器键 / Insert / PrtSc: 正常键码,用 WH_KEYBOARD_LL 低级键盘钩子拦截后改发。
//
// ponytail: 注入用 keybd_event(与本项目 MacroController 同一条路),不用 SendInput ——
// SendInput 要求 INPUT 结构体在 x64 下正好 40 字节(联合体必须含 MOUSEINPUT),
// 尺寸算错时它会静默返回 0、一个键都发不出去,是踩过的坑。
//
// RDP 兼容(远程桌面 mstsc): WH_KEYBOARD_LL 的钩子是**按桌面**挂的,挂在哪个桌面就只收
// 哪个桌面的输入。mstsc 全屏会接管 console 会话(输入桌面在 Default/Winlogon 之间来回切)、
// 会话断开重连也会换桌面 —— 此时系统不会报错,但回调从此不再被调用,表现就是:
//   远程收到原始键(计算器/Insert/PrtSc),而 Omen 键因为走 WMI 注入反而正常。
// 因此钩子改挂到**专用线程**,每次重装都先 SetThreadDesktop(OpenInputDesktop()) 绑到当前
// 输入桌面,并由 800ms 轮询(输入桌面名 / 前台是否 mstsc)驱动重装;另有心跳看门狗兜底。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace OmenSuperHub.Services {
  internal static class KeyRemapService {
    const int WH_KEYBOARD_LL = 13;
    const int WM_KEYDOWN = 0x0100;
    const int WM_SYSKEYDOWN = 0x0104;
    const uint KEYEVENTF_EXTENDEDKEY = 0x0001;
    const uint KEYEVENTF_KEYUP = 0x0002;
    // KBDLLHOOKSTRUCT.flags bit4: 事件由程序注入(非真实按键)
    const int LLKHF_INJECTED = 0x10;

    // 走键盘钩子的物理键
    const uint VK_CALC = 0xB7;   // 计算器键 (VK_LAUNCH_APP2)
    const uint VK_INSERT = 0x2D;
    const uint VK_PRTSC = 0x2C;

    delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("user32.dll")]
    static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    [DllImport("user32.dll")]
    static extern uint MapVirtualKey(uint uCode, uint uMapType);

    // ---- 桌面 / 会话相关(RDP 兼容) ----
    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr OpenInputDesktop(uint dwFlags, [MarshalAs(UnmanagedType.Bool)] bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseDesktop(IntPtr hDesktop);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetThreadDesktop(IntPtr hDesktop);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);

    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll")]
    static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    // ---- 钩子线程消息泵 ----
    [DllImport("user32.dll")]
    static extern int MsgWaitForMultipleObjects(uint nCount, IntPtr[] pHandles, [MarshalAs(UnmanagedType.Bool)] bool bWaitAll, uint dwMilliseconds, uint dwWakeMask);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr DispatchMessage(ref MSG lpmsg);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [StructLayout(LayoutKind.Sequential)]
    struct MSG {
      public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam;
      public uint time; public int ptX; public int ptY;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }

    const uint QS_ALLINPUT = 0x04FF;
    const uint PM_REMOVE = 0x0001;
    const uint DESKTOP_ALL_ACCESS = 0x000F01FF;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const int UOI_NAME = 2;

    // 可选目标键(顺序即设置页下拉框顺序),值存键名到注册表
    internal static readonly string[] TargetKeyNames = {
      "Home", "End", "PageUp", "PageDown", "Insert", "Delete", "PrintScreen",
      "Esc", "Up", "Down", "Left", "Right"
    };

    static readonly Dictionary<string, uint> TargetKeyVk = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase) {
      {"HOME",0x24},{"END",0x23},{"PAGEUP",0x21},{"PGUP",0x21},{"PAGEDOWN",0x22},{"PGDN",0x22},
      {"INSERT",0x2D},{"INS",0x2D},{"DELETE",0x2E},{"DEL",0x2E},
      {"PRINTSCREEN",0x2C},{"PRTSC",0x2C},{"ESC",0x1B},{"ESCAPE",0x1B},
      {"UP",0x26},{"DOWN",0x28},{"LEFT",0x25},{"RIGHT",0x27},
    };

    // 钩子线程专用状态
    static Thread _thread;
    static volatile bool _stop;
    static IntPtr _hook = IntPtr.Zero;
    static LowLevelKeyboardProc _proc;      // ponytail: 必须保留委托引用,否则 GC 回收后原生回调崩进程
    static int _rebindFlag;                 // 只用 Interlocked 访问,不加 volatile(否则 CS0420)
    static volatile string _rebindReason = "";
    static int _lastHookHitTick;            // 最近一次钩子回调(Environment.TickCount 口径)
    static uint _lastInputSeen;             // 最近一次 GetLastInputInfo 的 dwTime
    static int _lastDogTick;
    static volatile string _desktopName = "?";

    // 800ms 轮询: 输入桌面名 / 前台进程
    static Timer _watchTimer;
    static string _lastDeskSeen;
    static string _lastForegroundSeen;

    // 生效中的映射目标 VK,0 = 不替换(钩子线程读,UI 线程写 → volatile)
    static volatile uint _calcVk, _insertVk, _prtscVk, _omenVk;

    public static bool HookActive => _hook != IntPtr.Zero;

    // OMEN 键是否处于"改键生效"状态(调用方据此决定是否需要订阅 BIOS 事件)
    public static bool OmenRemapActive => _omenVk != 0;

    // 从配置重算映射并装卸钩子。任何相关设置变更后都要调一次。
    public static void Apply() {
      bool on = ConfigService.KeyRemapEnabled;
      _calcVk = on ? ResolveTarget(ConfigService.RemapCalc) : 0;
      _insertVk = on ? ResolveTarget(ConfigService.RemapInsert) : 0;
      _prtscVk = on ? ResolveTarget(ConfigService.RemapPrtSc) : 0;
      // 功能互斥: Omen 键已绑定其它功能("showMain"/"cyclePresets"/"app"/"custom")时改键不生效
      _omenVk = (on && ConfigService.OmenKey == "none") ? ResolveTarget(ConfigService.RemapOmen) : 0;

      if (_calcVk != 0 || _insertVk != 0 || _prtscVk != 0) Install();
      else Uninstall();
    }

    // 键名 -> VK,空值/未知键名都返回 0(不替换)
    public static uint ResolveTarget(string keyName) {
      if (string.IsNullOrWhiteSpace(keyName)) return 0;
      uint vk;
      return TargetKeyVk.TryGetValue(keyName.Trim(), out vk) ? vk : 0;
    }

    // OMEN 键按下时由 TrayService 调用(运行在 WMI 事件线程,与钩子线程无关)
    public static void HandleOmenKey() {
      uint vk = _omenVk;
      if (vk == 0) return;
      InjectKey(vk);
      LogHitAsync("OMEN", vk, vk);
    }

    // ---------------- 钩子生命周期 ----------------

    static void Install() {
      if (_thread != null) return;
      _stop = false;
      _proc = HookCallback;                  // 保持引用,防止委托被 GC
      _lastHookHitTick = Environment.TickCount;
      var t = new Thread(HookThreadProc) { IsBackground = true, Name = "KeyRemapHook" };
      _thread = t;
      t.Start();

      // 输入桌面/前台轮询(RDP 全屏、锁屏、UAC 都会换输入桌面)
      var old = _watchTimer;
      _watchTimer = new Timer(WatchTick, null, 800, 800);
      old?.Dispose();
    }

    static void Uninstall() {
      if (_thread != null) {
        _stop = true;
        var t = _thread;
        _thread = null;
        // 钩子线程 500ms 一轮循环,Join 给它一次翻身机会;超时也不影响进程退出(后台线程)
        if (!t.Join(2000)) Logger.Warn("KeyRemap: hook thread did not exit in 2s");
      }
      var wt = _watchTimer;
      _watchTimer = null;
      wt?.Dispose();
      _hook = IntPtr.Zero;
      _lastDeskSeen = null;
      _lastForegroundSeen = null;
    }

    // 钩子线程: 先绑到当前输入桌面,再装钩子,然后泵消息(LL 钩子必须由装载线程泵消息才会被回调)
    static void HookThreadProc() {
      uint tid = GetCurrentThreadId();
      try {
        Bind();
        var msg = new MSG();
        var empty = new IntPtr[0];
        while (!_stop) {
          // 500ms 超时: 兼作重装请求与看门狗的检查点
          MsgWaitForMultipleObjects(0, empty, false, 500, QS_ALLINPUT);
          while (PeekMessage(out msg, IntPtr.Zero, 0, 0, PM_REMOVE)) {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
          }
          if (_stop) break;

          if (Interlocked.Exchange(ref _rebindFlag, 0) != 0) {
            string why = _rebindReason;
            Unbind();
            Bind();
            Logger.Info($"KeyRemap: hook rebound (desktop={_desktopName}, reason={why})");
            continue;
          }

          Watchdog();
        }
      } catch (Exception ex) {
        Logger.Error("KeyRemap hook thread: " + ex.Message);
      } finally {
        Unbind();
        Logger.Verbose($"KeyRemap: hook thread exit (tid={tid})");
      }
    }

    static void Bind() {
      // 1) 切到当前输入桌面 —— 钩子只对所在桌面收键,mstsc 全屏/锁屏/UAC 都会换桌面
      IntPtr desk = OpenInputDesktop(0, false, DESKTOP_ALL_ACCESS);
      if (desk != IntPtr.Zero) {
        try {
          _desktopName = DesktopName(desk);
          if (!SetThreadDesktop(desk))
            Logger.Warn($"KeyRemap: SetThreadDesktop({_desktopName}) failed, err={Marshal.GetLastWin32Error()}");
        } finally {
          CloseDesktop(desk);   // SetThreadDesktop 已把桌面对象挂到线程上,句柄可关
        }
      } else {
        Logger.Warn("KeyRemap: OpenInputDesktop failed, err=" + Marshal.GetLastWin32Error());
      }

      // 2) 装钩子(hMod 对 LL 钩子实际不参与路由,传 exe 基址即可)
      _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(null), 0);
      if (_hook == IntPtr.Zero)
        Logger.Error("KeyRemap: SetWindowsHookEx failed, err=" + Marshal.GetLastWin32Error());
      else
        Logger.Info($"KeyRemap: hook installed (desktop={_desktopName})");
      _lastHookHitTick = Environment.TickCount;
    }

    static void Unbind() {
      if (_hook != IntPtr.Zero) {
        UnhookWindowsHookEx(_hook);
        _hook = IntPtr.Zero;
      }
    }

    // 800ms 轮询: 输入桌面变了 / 前台切到(或切出) mstsc → 请求重装钩子
    static void WatchTick(object _) {
      try {
        if (_thread == null) return;

        string desk = QueryInputDesktopName();
        string fg = QueryForegroundSignature();

        bool deskChanged = desk != null && _lastDeskSeen != null && desk != _lastDeskSeen;
        bool fgChanged = fg != null && _lastForegroundSeen != null && fg != _lastForegroundSeen;
        string reason = null;

        if (deskChanged) reason = "inputdesktop=" + desk;
        else if (fgChanged && (IsRdpSignature(fg) || IsRdpSignature(_lastForegroundSeen)))
          reason = "foreground " + _lastForegroundSeen + " -> " + fg;

        if (desk != null) _lastDeskSeen = desk;
        if (fg != null) _lastForegroundSeen = fg;

        if (reason != null) RequestRebind(reason);
      } catch { /* 轮询失败不得成为崩溃源 */ }
    }

    // 心跳看门狗: 只在 mstsc 有焦点时判(此时用户就是在用它),有输入活动但钩子 8s 没被回调 → 重装
    static void Watchdog() {
      int now = Environment.TickCount;
      if (now - _lastDogTick < 5000) return;   // 5s 节流
      _lastDogTick = now;

      if (!IsRdpSignature(_lastForegroundSeen ?? QueryForegroundSignature())) return;

      var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO)) };
      if (!GetLastInputInfo(ref lii)) return;
      if (lii.dwTime == _lastInputSeen) return;  // 没有新的输入活动
      _lastInputSeen = lii.dwTime;

      uint lastHit = unchecked((uint)_lastHookHitTick);
      uint delta = unchecked(lii.dwTime - lastHit);
      if (delta > 8000) {
        Logger.Warn($"KeyRemap: hook silent {delta}ms while mstsc focused -> rebind");
        RequestRebind("watchdog: no hook callback while mstsc focused");
      }
    }

    static void RequestRebind(string reason) {
      _rebindReason = reason;
      Interlocked.Exchange(ref _rebindFlag, 1);
    }

    // ---------------- 输入桌面 / 前台查询 ----------------

    static string QueryInputDesktopName() {
      IntPtr desk = OpenInputDesktop(0, false, DESKTOP_ALL_ACCESS);
      if (desk == IntPtr.Zero) return null;
      try { return DesktopName(desk); } finally { CloseDesktop(desk); }
    }

    static string DesktopName(IntPtr hDesk) {
      var sb = new StringBuilder(256);
      int need;
      if (GetUserObjectInformation(hDesk, UOI_NAME, sb, sb.Capacity * 2, out need))
        return sb.ToString();
      return "?";
    }

    // 前台窗口 "进程名|窗口类名",取不到返回 null
    static string QueryForegroundSignature() {
      IntPtr fg = GetForegroundWindow();
      if (fg == IntPtr.Zero) return "none|none";

      uint pid;
      GetWindowThreadProcessId(fg, out pid);
      string proc = ProcessNameOf(pid);

      var cls = new StringBuilder(256);
      GetClassName(fg, cls, cls.Capacity);
      return proc + "|" + cls;
    }

    static string ProcessNameOf(uint pid) {
      if (pid == 0) return "?";
      IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
      if (h == IntPtr.Zero) return "?";
      try {
        var sb = new StringBuilder(1024);
        uint size = (uint)sb.Capacity;
        if (!QueryFullProcessImageName(h, 0, sb, ref size)) return "?";
        string full = sb.ToString();
        int i = full.LastIndexOf('\\');
        return (i >= 0 ? full.Substring(i + 1) : full).ToLowerInvariant();
      } finally { CloseHandle(h); }
    }

    // mstsc 的特征: 进程 mstsc.exe,或窗口类是 RDP 客户端宿主 TscShellContainerClass
    static bool IsRdpSignature(string sig) {
      if (string.IsNullOrEmpty(sig)) return false;
      return sig.StartsWith("mstsc.exe|", StringComparison.OrdinalIgnoreCase)
          || sig.IndexOf("TscShellContainerClass", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    // ---------------- 钩子回调 ----------------

    static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
      if (nCode >= 0) {
        _lastHookHitTick = Environment.TickCount;   // 心跳: 钩子还活着

        // 跳过自己注入的事件:否则 A->B、B->A 这类映射会互相触发成死循环
        int flags = Marshal.ReadInt32(lParam, 8);
        if ((flags & LLKHF_INJECTED) == 0) {
          uint vk = (uint)Marshal.ReadInt32(lParam);
          uint target = 0;
          if (vk == VK_CALC) target = _calcVk;
          else if (vk == VK_INSERT) target = _insertVk;
          else if (vk == VK_PRTSC) target = _prtscVk;

          if (target != 0) {
            if (wParam == (IntPtr)WM_KEYDOWN || wParam == (IntPtr)WM_SYSKEYDOWN)
              InjectKey(target);
            // ponytail: keydown/keyup 一起吞掉,只吞一半会让目标键残留按下状态
            // 注意日志不能在钩子里同步写文件: 超过 LowLevelHooksTimeout(默认 300ms)
            // 系统会静默卸掉钩子,所以统一丢线程池。
            LogHitAsync("hook", vk, target);
            return (IntPtr)1;
          }
        }
      }
      return CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    static void InjectKey(uint vk) {
      // 方向键/翻页/Insert 等 E0 前缀键必须带 EXTENDEDKEY,否则被当成小键盘数字
      uint flags = MacroController.IsExtendedKey(vk) ? KEYEVENTF_EXTENDEDKEY : 0;
      // 带真实扫描码注入: mstsc 转发 RDP 键盘事件走扫描码,扫描码为 0 时远端可能直接丢弃
      byte scan = (byte)(MapVirtualKey(vk, 0) & 0xFF);
      keybd_event((byte)vk, scan, flags, UIntPtr.Zero);
      keybd_event((byte)vk, scan, flags | KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    // 改键命中日志(诊断 RDP 问题用: 有这行说明钩子触发过,没有就是钩子没被回调)
    static void LogHitAsync(string channel, uint fromVk, uint toVk) {
      ThreadPool.QueueUserWorkItem(_ => {
        try {
          string fg = QueryForegroundSignature();
          Logger.Info($"KeyRemap: [{channel}] 0x{fromVk:X2} -> 0x{toVk:X2} (fg={fg}, desktop={_desktopName})");
        } catch { }
      });
    }
  }
}
