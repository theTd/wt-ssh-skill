param(
    [Parameter(Mandatory=$true)][string]$Title,
    [string]$EntryHint = "",           # e.g. "条目：alpha" (built by wtssh.py)
    [string]$PassLabel = "私钥口令短语",
    [string]$ConfirmLabel = "再输入一遍以确认",
    [string]$MismatchLabel = "两次输入不一致，请重新输入",
    [string]$OkLabel = "确定",
    [string]$CancelLabel = "取消",
    [switch]$Confirm
)
# Secure passphrase capture via a WPF dialog (modern flat styling; WPF is
# DPI-correct and renders with the system theme fonts). The passphrase NEVER
# leaves this process in the clear: SecureString -> BSTR -> UTF-8 bytes ->
# DPAPI(CurrentUser); only the base64 ciphertext goes to stdout. UTF-8 (not
# raw UTF-16) matches scripts/dpapi.ps1's Protect/Unprotect byte semantics.
# Exit codes: 0 = captured, 1 = dialog failure, 2 = cancelled / empty input.
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

Add-Type -AssemblyName System.Security
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase


function Esc([string]$s) { [Security.SecurityElement]::Escape($s) }

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$(Esc $Title)" Width="440" SizeToContent="Height"
        Background="#FAFAFA" FontFamily="Segoe UI" ShowInTaskbar="False">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Height" Value="32"/>
      <Setter Property="MinWidth" Value="96"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" CornerRadius="4"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Opacity" Value="0.88"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="bd" Property="Opacity" Value="0.75"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Border Margin="24,20,24,20">
    <StackPanel>
      <TextBlock Text="$(Esc $PassLabel)" FontSize="15" FontWeight="SemiBold" Foreground="#1B1B1B"/>
      <TextBlock x:Name="EntryHint" Text="$(Esc $EntryHint)" FontSize="12" Foreground="#616161" Margin="0,4,0,0"/>
      <PasswordBox x:Name="PassBox" Height="34" FontSize="13" Padding="8,4"
                   Margin="0,16,0,0" VerticalContentAlignment="Center"/>
      <PasswordBox x:Name="PassBox2" Height="34" FontSize="13" Padding="8,4"
                   Margin="0,8,0,0" VerticalContentAlignment="Center"
                   Visibility="Collapsed" ToolTip="$(Esc $ConfirmLabel)"/>
      <TextBlock x:Name="ConfirmHint" Text="$(Esc $ConfirmLabel)" FontSize="11"
                 Foreground="#616161" Margin="0,6,0,0" Visibility="Collapsed"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,24,0,0">
        <Button x:Name="BtnCancel" Content="$(Esc $CancelLabel)" Background="#FFFFFF"
                Foreground="#1B1B1B" BorderBrush="#CFCFCF" IsCancel="True"/>
        <Button x:Name="BtnOk" Content="$(Esc $OkLabel)" Background="#0067C0"
                Foreground="White" BorderBrush="#0067C0" Margin="8,0,0,0" IsDefault="True"/>
      </StackPanel>
    </StackPanel>
  </Border>
</Window>
"@

try {
    $win = [Windows.Markup.XamlReader]::Parse($xaml)
} catch {
    [Console]::Error.WriteLine("dialog build failed: $_")
    exit 1
}
$passBox = $win.FindName("PassBox")
$passBox2 = $win.FindName("PassBox2")
$btnOk   = $win.FindName("BtnOk")
if ($Confirm) {
    $passBox2.Visibility = [Windows.Visibility]::Visible
    $win.FindName("ConfirmHint").Visibility = [Windows.Visibility]::Visible
    $btnOk.Add_Click({
        if ($passBox.SecurePassword.Length -eq 0) { return }
        # full content compare, not just length: an OK'd mismatch would
        # seal the export under the wrong passphrase irrecoverably
        $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passBox.SecurePassword)
        $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passBox2.SecurePassword)
        try {
            $p1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1)
            $p2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2)
        }
        if ($p1 -ceq $p2) { $win.DialogResult = $true; return }
        $win.FindName("ConfirmHint").Text = $MismatchLabel
        $passBox2.Clear(); $passBox2.Focus()
    })
} else {
    $btnOk.Add_Click({ $win.DialogResult = $true })
}
$win.Add_Loaded({ $passBox.Focus() })

if ($win.ShowDialog() -ne $true) { exit 2 }
$sec = $passBox.SecurePassword
if ($sec.Length -eq 0) { exit 2 }
if ($Confirm -and $passBox2.SecurePassword.Length -ne $sec.Length) { exit 2 }


$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
try {
    $pt = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
$bytes = [Text.Encoding]::UTF8.GetBytes($pt)
$enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($enc))
exit 0
