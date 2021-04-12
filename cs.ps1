mkdir C:\CustomExtensions
Invoke-WebRequest -Uri "https://github.com/jlunde-cisco/azure/blob/main/greenshot.exe" -OutFile "C:\CustomExtensions\greenshot.exe"
& C:\CustomExtensions\greenshot.exe /lang=English /verysilent
Invoke-WebRequest -Uri "https://github.com/jlunde-cisco/azure/blob/main/tet.ps1" -OutFile "C:\CustomExtensions\tet.ps1"
& C:\CustomExtensions\tet.ps1