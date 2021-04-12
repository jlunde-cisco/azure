mkdir C:\CustomExtensions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://github.com/jlunde-cisco/azure/raw/main/greenshot.exe" -OutFile "C:\CustomExtensions\greenshot.exe"
& C:\CustomExtensions\greenshot.exe /lang=English /verysilent
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jlunde-cisco/azure/main/tet.ps1" -OutFile "C:\CustomExtensions\tet.ps1"
& C:\CustomExtensions\tet.ps1
