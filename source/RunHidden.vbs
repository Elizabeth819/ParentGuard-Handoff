' ParentGuard hidden launcher (GUI subsystem: creates no console itself).
' Usage: wscript.exe //B //Nologo RunHidden.vbs <exe> <script> [extra args...]
' Child is started with SW_HIDE(0), so its console window is hidden from creation.
' (powershell -WindowStyle Hidden shows the console first, then hides it -> flicker.)
Option Explicit
Dim exe, script, extra, i, cmd
If WScript.Arguments.Count < 2 Then WScript.Quit 2
exe = WScript.Arguments(0)
script = WScript.Arguments(1)
extra = ""
For i = 2 To WScript.Arguments.Count - 1
    extra = extra & " " & WScript.Arguments(i)
Next
cmd = """" & exe & """ -NoProfile -ExecutionPolicy Bypass -File """ & script & """" & extra
CreateObject("WScript.Shell").Run cmd, 0, False
