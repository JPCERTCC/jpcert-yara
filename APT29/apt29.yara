rule APT29_wellmess_pe {
      meta:
        description = "detect WellMess in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "0322c4c2d511f73ab55bf3f43b1b0f152188d7146cc67ff497ad275d9dd1c20f"
        hash2 = "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8 "

      strings:
        $botlib1 = "botlib.wellMess" ascii
        $botlib2 = "botlib.Command" ascii
        $botlib3 = "botlib.Download" ascii
        $botlib4 = "botlib.AES_Encrypt" ascii
        $dotnet1 = "WellMess" ascii
        $dotnet2 = "<;head;><;title;>" ascii wide
        $dotnet3 = "<;title;><;service;>" ascii wide
        $dotnet4 = "AES_Encrypt" ascii

      condition: (uint16(0) == 0x5A4D) and (all of ($botlib*) or all of ($dotnet*))
}

rule APT29_wellmess_elf {
      meta:
        description = "ELF_Wellmess"
        author = "JPCERT/CC Incident Response Group"
        hash = "00654dd07721e7551641f90cba832e98c0acb030e2848e5efc0e1752c067ec07"

      strings:
        $botlib1 = "botlib.wellMess" ascii
        $botlib2 = "botlib.Command" ascii
        $botlib3 = "botlib.Download" ascii
        $botlib4 = "botlib.AES_Encrypt" ascii

      condition: (uint32(0) == 0x464C457F) and all of ($botlib*)
}

rule APT29_csloader_code {
      meta:
        description = "CobaltStrike loader using APT29"
        author = "JPCERT/CC Incident Response Group"
        hash = "459debf426444ec9965322ba3d61c5ada0d95db54c1787f108d4d4ad2c851098"
        hash = "a0224574ed356282a7f0f2cac316a7a888d432117e37390339b73ba518ba5d88"
        hash = "791c28f482358c952ff860805eaefc11fd57d0bf21ec7df1b9781c7e7d995ba3"

      strings:
        $size = { 41 B8 08 02 00 00 }
        $process = "explorer.exe" wide
        $resource1 = "docx" wide
        $resource2 = "BIN" wide
        $command1 = "C:\\Windows\\System32\\cmd.exe /C ping 8.8.8.8 -n 3  && del /F \"%s\"" wide
        $command2 = "C:\\Windows\\System32\\cmd.exe /k ping 8.8.8.8 -n 3  && del /F \"%s\"" wide
        $pdb = "C:\\Users\\jack\\viewer\\bin\\viewer.pdb" ascii

      condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3c)) == 0x00004550 and
        ((#size >= 4 and $process and 1 of ($command*) and 1 of ($resource*)) or
        $pdb)
}