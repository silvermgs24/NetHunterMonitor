# Generates src/NetHunter.App/Assets/NetHunter.ico (PNG-compressed multi-size icon) from code.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools/make-icon.ps1
param([string]$Out = (Join-Path $PSScriptRoot '..\src\NetHunter.App\Assets\NetHunter.ico'))
Add-Type -AssemblyName System.Drawing

function New-IconPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 256.0
    # Background disc
    $bg = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 14, 19, 26))
    $g.FillEllipse($bg, 8 * $s, 8 * $s, 240 * $s, 240 * $s)
    $ring = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 63, 182, 255)), ([Math]::Max(1, 10 * $s))
    $g.DrawEllipse($ring, 14 * $s, 14 * $s, 228 * $s, 228 * $s)
    # Radar rings
    $thin = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(160, 63, 182, 255)), ([Math]::Max(1, 6 * $s))
    $g.DrawEllipse($thin, 58 * $s, 58 * $s, 140 * $s, 140 * $s)
    $g.DrawEllipse($thin, 98 * $s, 98 * $s, 60 * $s, 60 * $s)
    # Sweep
    $sweep = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 63, 182, 255)), ([Math]::Max(1, 10 * $s))
    $sweep.StartCap = 'Round'; $sweep.EndCap = 'Round'
    $g.DrawLine($sweep, 128 * $s, 128 * $s, 205 * $s, 70 * $s)
    # Detected contact (red)
    $hit = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 248, 81, 73))
    $g.FillEllipse($hit, 162 * $s, 150 * $s, 36 * $s, 36 * $s)
    $center = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 230, 237, 243))
    $g.FillEllipse($center, 116 * $s, 116 * $s, 24 * $s, 24 * $s)
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$images = foreach ($sz in $sizes) { ,(New-IconPng $sz) }
$fs = [System.IO.File]::Create($Out)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $data = $images[$i]
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32); $w.Write([UInt32]$data.Length); $w.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($data in $images) { $w.Write($data) }
$w.Close()
Write-Output "Wrote $Out"
