function Get-ScriptDirectory
{
	Split-Path -Parent $PSCommandPath
}

function RemoveEmptyDir([string]$dir)
{
	if (Test-Path $dir)
	{
		$parentdir = Split-Path -Path $dir -Parent
		$subitem = Get-ChildItem -Path $dir -Recurse -Force
		if ($subitem.Count -eq 0)
		{
			Write-Host $dir
			Remove-Item -Path $dir -Force -Recurse
			RemoveEmptyDir $parentdir
		}
	}
}

$dir = Get-ScriptDirectory
$filter = @("*.aps", "*.idb", "*.ncb", "*.obj", "*.pch", "*.sbr", "*.tmp", "*.pdb", "*.bsc", "*.ilk", "*.res", "*.sdf", "*.dep", "*.ipch", "*.tlog", "*.exp", "*.hpj", "*.opt", "*.mdp", "*.plg", "*.clw", "*.vs", "*.recipe")
$files = Get-ChildItem -Path $dir -Include $filter -Recurse -Force -File
$deldir = Get-ChildItem -Path $dir -Include $filter -Recurse -Force -Directory
$emptydir = Get-ChildItem -Path $dir -Recurse -Force -Directory
Write-Host "[*]Phase Delete Clean File[*]"
foreach ($file in $files)
{
	Write-Host $file.FullName
	Remove-Item -Path $file.FullName -Force
}
Write-Host "[*]Phase Delete Clean Directory[*]"
foreach ($dir in $deldir)
{
	Write-Host $dir.FullName
	Remove-Item -Path $dir.FullName -Force -Recurse
}
Write-Host "[*]Phase Delete Empty Directory[*]"
foreach ($dir in $emptydir)
{	
	RemoveEmptyDir $dir.FullName
}
Write-Host "[*]Clean All Done[*]"