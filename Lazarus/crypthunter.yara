rule CryptHunter_downloaderjs {
     meta:
        description = "JS downloader executed from an lnk file used in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash = "bb7349d4fd7efa838a92fc4a97ec2a25b82dde36236bdc09b531c20370d7f848"

     strings:
        $a = "pi.ProcessID!==0 && pi.ProcessID!==4){"
        $b = "prs=prs+pi.CommandLine.toLowerCase();}"

     condition:
       any of them
}

rule CryptHunter_lnk_bitly {
      meta:
        description = "detect suspicious lnk file"
        author = "JPCERT/CC Incident Response Group"
        reference = "internal research"
        hash1 = "01b5cd525d18e28177924d8a7805c2010de6842b8ef430f29ed32b3e5d7d99a0"

      strings:
        $a1 = "cmd.exe" wide ascii
        $a2 = "mshta" wide ascii
        $url1 = "https://bit.ly" wide ascii

      condition:
        (uint16(0) == 0x004c) and
        (filesize<100KB)  and
        ((1 of ($a*)) and ($url1))
}

rule CryptHunter_httpbotjs_str {
    meta:
        description = "HTTP bot js in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b316b81bc0b0deb81da5e218b85ca83d7260cc40dae97766bc94a6931707dc1b"

     strings:
        $base64 = "W0NtZGxldEJpbmRpbmcoKV1QYXJhbShbUGFyYW1ldGVyKFBvc2l0aW9uPTApXVtTdHJpbmddJFVSTCxbUGFyYW1ldGVyKFBvc2l0aW9uPTEpXVtTdHJpbmddJFVJRCkNCmZ1bmN0aW9uIEh0dHBSZXEyew" ascii
        $var1 = { 40 28 27 22 2b 70 32 61 2b 22 27 2c 20 27 22 2b 75 69 64 2b 22 27 29 3b 7d }

     condition:
        all of them
}



rule CryptHunter_python_downloader {
    meta:
        description = "1st stage python downloader in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "Hunting"
        hash1 = "e0891a1bfa5980171599dc5fe31d15be0a6c79cc08ab8dc9f09ceec7a029cbdf"

    strings:
        $str01 = "auto_interrupt_handle" ascii wide fullword
        $str02 = "aW1wb3J0IHN0cmluZw0KaW1wb3J0IHJhbmRvbQ0" ascii wide fullword

        $rot13_01 = "clguba" ascii wide fullword
        $rot13_02 = "log_handle_method" ascii wide fullword
        $rot13_03 = "rot13" ascii wide fullword
        $rot13_04 = "zfvrkrp" ascii wide fullword
        $rot13_05 = "Jvaqbjf" ascii wide fullword
        $rot13_06 = ".zfv" ascii wide fullword
        $rot13_07 = "qrirybcpber" ascii wide fullword
        $rot13_08 = "uggc://ncc." ascii wide fullword
        $rot13_09 = "cat_file_header_ops" ascii wide fullword

    condition:
        (filesize > 10KB)
        and (filesize < 5MB)
        and ( 1 of ($str*) or ( 3 of ($rot13*) ))
}

rule CryptHunter_python_simple_rat {
    meta:
        description = "2nd stage python simple rat in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "Hunting"
        hash1 = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"
        hash2 = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"

    strings:
        $domain01 = "www.git-hub.me" ascii wide fullword
        $domain02 = "nivyga.com" ascii wide fullword
        $domain03 = "tracking.nivyga.com" ascii wide fullword
        $domain04 = "yukunmaoyi.com" ascii wide fullword
        $domain05 = "gameofwarsite.com" ascii wide fullword
        $domain06 = "togetherwatch.com" ascii wide fullword
        $domain07 = "9d90-081d2f-vultr-los-angeles-boxul.teridions.net" ascii wide fullword
        $domain08 = "8dae-77766a-vultr-los-angeles-egnyte-sj.d1.teridioncloud.net" ascii wide fullword
        $domain09 = "www.jacarandas.top" ascii wide fullword
        $domain10 = "cleargadgetwinners.top" ascii wide fullword
        $domain11 = "ns1.smoothieking.info" ascii wide fullword
        $domain12 = "ns2.smoothieking.info" ascii wide fullword

        $str01 = "Jvaqbjf" ascii wide fullword
        $str02 = "Yvahk" ascii wide fullword
        $str03 = "Qnejva" ascii wide fullword
        $str04 = "GITHUB_REQ" ascii wide fullword
        $str05 = "GITHUB_RES" ascii wide fullword
        $str06 = "BasicInfo" ascii wide fullword
        $str07 = "CmdExec" ascii wide fullword
        $str08 = "DownExec" ascii wide fullword
        $str09 = "KillSelf" ascii wide fullword
        $str10 = "pp -b /gzc/.VPR-havk/tvg" ascii wide fullword
        $str11 = "/gzc/.VPR-havk/tvg" ascii wide fullword
        $str12 = "NccyrNppbhag.gtm" ascii wide fullword
        $str13 = "/GrzcHfre/NccyrNppbhagNffvfgnag.ncc" ascii wide fullword
        $str14 = "Pheerag Gvzr" ascii wide fullword
        $str15 = "Hfreanzr" ascii wide fullword
        $str16 = "Ubfganzr" ascii wide fullword
        $str17 = "BF Irefvba" ascii wide fullword
        $str18 = "VQ_YVXR=qrovna" ascii wide fullword
        $str19 = "VQ=qrovna" ascii wide fullword
        $str20 = "/rgp/bf-eryrnfr" ascii wide fullword
        $str21 = " -yafy -ycguernq -yerfbyi -fgq=tah99" ascii wide fullword

    condition:
        (filesize > 1KB)
        and (filesize < 5MB)
        and ( 1 of ($domain*) or ( 3 of ($str*) ))
}

rule CryptHunter_js_downloader {
    meta:
        description = "1st stage js downloader in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "Hunting"
        hash1 = "67a0f25a20954a353021bbdfdd531f7cc99c305c25fb03079f7abbc60e8a8081"

    strings:
        $code01 = "UID + AgentType + SessionType + OS;" ascii wide fullword
        $code02 = "received_data.toString().startsWith" ascii wide fullword
        $str01 = "GITHUB_RES" ascii wide fullword
        $str02 = "GITHUB_REQ" ascii wide fullword

    condition:
        (filesize > 1KB)
        and (filesize < 5MB)
        and ( 1 of ($code*) or ( 2 of ($str*) ))
}

rule CryptHunter_JokerSpy_macos {
     meta:
        description = "Mach-O malware using CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
        hash = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
        hash = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"

     strings:
        $db = "/Library/Application Support/com.apple.TCC/TCC.db" ascii
        $path = "/Users/joker/Downloads/Spy/XProtectCheck/XProtectCheck/" ascii
        $msg1 = "The screen is currently LOCKED!" ascii
        $msg2 = "Accessibility: YES" ascii
        $msg3 = "ScreenRecording: YES" ascii
        $msg4 = "FullDiskAccess: YES" ascii
        $msg5 = "kMDItemDisplayName = *TCC.db" ascii

     condition:
       (uint32(0) == 0xfeedface or
        uint32(0) == 0xcefaedfe or
        uint32(0) == 0xfeedfacf or
        uint32(0) == 0xcffaedfe or
        uint32(0) == 0xcafebabe or
        uint32(0) == 0xbebafeca or
        uint32(0) == 0xcafebabf or
        uint32(0) == 0xbfbafeca) and
       5 of them
}