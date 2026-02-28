
$directoryPath = "C:\Users\varsh"
$filePath = Join-Path -Path $directoryPath -ChildPath "monfichier.txt"


if (Test-Path $directoryPath) {
    Write-Output "Le répertoire existe"
} else {
    Write-Output "Le répertoire n'existe pas"
}

New-Item -Path $filePath -ItemType File
Write-Output "Le fichier a été créé avec succès"


$files = Get-ChildItem -Path $directoryPath -File
foreach ($file in $files) {
    Write-Output "Nom du fichier : $($file.Name), Taille : $($file.Length) octets"
}

if (-not $files) {
    Write-Output "Le répertoire est vide"
}
