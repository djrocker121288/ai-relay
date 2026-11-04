//go:build windows

package security

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const checkACL = `$ErrorActionPreference='Stop'
$p=$env:AI_RELAY_PROTECTED_FILE
$a=Get-Acl -LiteralPath $p
$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed=@($me,'S-1-5-18','S-1-5-32-544')
if (-not $a.AreAccessRulesProtected) { throw 'credential ACL inheritance must be disabled' }
$owner=$a.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($allowed -notcontains $owner) { throw 'credential owner is not trusted' }
foreach($r in $a.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
 if ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $allowed -notcontains $r.IdentityReference.Value) { throw 'credential ACL grants access to another identity' }
}
`
const protectACL = `$ErrorActionPreference='Stop'
$p=$env:AI_RELAY_PROTECTED_FILE
$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$a=New-Object System.Security.AccessControl.FileSecurity
$a.SetOwner($me)
$a.SetAccessRuleProtection($true,$false)
foreach($sid in @($me.Value,'S-1-5-18','S-1-5-32-544')) {
 $id=New-Object System.Security.Principal.SecurityIdentifier($sid)
 $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')
 $a.AddAccessRule($rule)
}
Set-Acl -LiteralPath $p -AclObject $a
`

func runACL(path, script string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := os.Getenv("SystemRoot")
	if root == "" {
		return fmt.Errorf("SystemRoot is required for ACL validation")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "AI_RELAY_PROTECTED_FILE="+absolute)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("protected credential ACL: %w: %s", err, output)
	}
	return nil
}
func CheckProtectedFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("credential must be a regular file")
	}
	return runACL(path, checkACL)
}
func ProtectFile(path string) error {
	if err := runACL(path, protectACL); err != nil {
		return err
	}
	return CheckProtectedFile(path)
}
