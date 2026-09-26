$dll = "C:\Users\admin\Desktop\memo\target\debug\memo_hook.dll"
$sig = @'
using System;
using System.Runtime.InteropServices;
public static class N {
  [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)] public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32", SetLastError=true)] public static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32", SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr h, IntPtr ordinal);
}
'@
Add-Type -TypeDefinition $sig
$h = [N]::LoadLibraryW($dll)
if ($h -eq [IntPtr]::Zero) { Write-Output ("LOAD_FAIL err=" + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()); exit 1 }
Write-Output ("LOADED h=" + $h)
$p = [N]::GetProcAddress($h, [IntPtr]1)   # ordinal 1
Write-Output ("ORDINAL1 addr=" + $p)
$ok = [N]::FreeLibrary($h)
Write-Output ("FREED=" + $ok)
