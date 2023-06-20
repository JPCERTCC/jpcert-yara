rule SteelClover_PowerShell_Encryption {
    meta:
        description = "PowerShell in SteelClover - Decryption of GPG file"
        author = "JPCERT/CC Incident Response Group"
        hash = "05e6f7a4184c9688ccef4dd17ae8ce0fe788df1677c6ba754b37a895a1e430e9"

    strings:
        $s1 = "function Add-Encryption" ascii wide nocase
        $s2 = "function Remove-Encryption" ascii wide nocase
        $s3 = "Remove-Encryption -FolderPath $env:APPDATA -Password" ascii wide nocase

     condition:
        all of them
}

rule SteelClover_PowerShell_InstallGnuPG {
    meta:
        description = "PowerShell in SteelClover - Install GnuPG"
        author = "JPCERT/CC Incident Response Group"
        hash = "05e6f7a4184c9688ccef4dd17ae8ce0fe788df1677c6ba754b37a895a1e430e9"

    strings:
        $s1 = "function Install-GnuPg" ascii wide nocase
        $s2 = "Install-GnuPG -DownloadFolderPath $env:APPDATA" ascii wide nocase

     condition:
        all of them
}

rule SteelClover_MSI_RunningPS {
    meta:
        description = "MSI in SteelClover"
        author = "JPCERT/CC Incident Response Group"
        hash = "00a1de538b552c482b649a878dc1f04aa729f6e0e5fd07a499776b45eab6759a"

    strings:
        $magic = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
        $s1 = "# Your code goes here." ascii wide nocase
        $s2 = "DownloadString" ascii wide nocase
        $s3 = ".gpg\") | iex" ascii wide nocase

     condition:
        $magic at 0 and all of ($s*)
}