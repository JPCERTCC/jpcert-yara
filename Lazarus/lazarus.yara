rule Lazarus_BILDINGCAN_RC4 {
    meta:
        description = "BILDINGCAN_RC4 in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "8db272ea1100996a8a0ed0da304610964dc8ca576aa114391d1be9d4c5dab02e"

    strings:
        $customrc4 = { 75 C0 41 8B D2 41 BB 00 0C 00 00 0F 1F 80 00 00 00 00 }
            // jnz     short loc_180002E60
            // mov     edx, r10d
            // mov     r11d, 0C00h
            //nop     dword ptr [rax+00000000h]
         $id = "T1B7D95256A2001E" ascii
         $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
         $post = "id=%s%s&%s=%s&%s=%s&%s=" ascii
         $command = "%s%sc \"%s > %s 2>&1" ascii

     condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_AES {
    meta:
        description = "BILDINGCAN_AES in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "925922ef243fa2adbd138942a9ecb4616ab69580a1864429a1405c13702fe773 "

    strings:
        $AES = { 48 83 C3 04 30 43 FC 0F B6 44 1F FC 30 43 FD 0F B6 44 1F FD 30 43 FE 0F B6 44 1F FE 30 43 FF 48 FF C9 }
        $pass = "RC2zWLyG50fPIPkQ" wide
        $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
        $confsize = { 48 8D ?? ?? ?? ?? 00 BA F0 06 00 00 E8 }
        $buffsize = { 00 00 C7 ?? ?? ??  B8 8E 03 00 }
        $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

     condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_module {
    meta:
        description = "BILDINGCAN_AES module in Lazarus"
        author = "JPCERT/CC Incident Response Group"

    strings:
      $cmdcheck1 = { 3D ED AB 00 00 0F ?? ?? ?? 00 00 3D EF AB 00 00 0F ?? ?? ?? 00 00 3D 17 AC 00 00 0F ?? ?? ?? 00 00 }
      $cmdcheck2 = { 3D 17 AC 00 00 0F ?? ?? ?? 00 00 3D 67 EA 00 00 0F ?? ?? ?? 00 00 }
      $recvsize = { 00 00 41 81 F8 D8 AA 02 00 }
      $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
      $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

    condition:
      uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_Torisma_strvest {
    meta:
        description = "Torisma in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "7762ba7ae989d47446da21cd04fd6fb92484dd07d078c7385ded459dedc726f9"

    strings:
         $post1 = "ACTION=NEXTPAGE" ascii
         $post2 = "ACTION=PREVPAGE" ascii
         $post3 = "ACTION=VIEW" ascii
         $post4 = "Your request has been accepted. ClientID" ascii
         $password = "ff7172d9c888b7a88a7d77372112d772" ascii
         $vestt = { 4F 70 46 DA E1 8D F6 41 }
         $vestsbox = { 07 56 D2 37 3A F7 0A 52 }
         $vestrns = { 41 4B 1B DD 0D 65 72 EE }

     condition:
         uint16(0) == 0x5a4d and (all of ($post*) or $password or all of ($vest*))
}

rule Lazarus_LCPDot_strings {
    meta:
        description = "LCPDot in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "0c69fd9be0cc9fadacff2c0bacf59dab6d935b02b5b8d2c9cb049e9545bb55ce"

    strings:
         $ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
         $class = "HotPlugin_class" wide
         $post = "Cookie=Enable&CookieV=%d&Cookie_Time=64" ascii

     condition:
         uint16(0) == 0x5a4d and all of them
}

rule Lazarus_Torisma_config {
    meta:
        description = "Torisma config header"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b78efeac54fa410e9e3e57e4f3d5ecc1b47fd4f7bf0d7266b3cb64cefa48f0ec"

     strings:
        $header = { 98 11 1A 45 90 78 BA F9 4E D6 8F EE }

     condition:
        all of them
}

rule Lazarus_loader_thumbsdb {
    meta:
        description = "Loader Thumbs.db malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "44e4e14f8c8d299ccf5194719ab34a21ad6cc7847e49c0a7de05bf2371046f02"

     strings:
        $switchcase = { E8 ?? ?? ?? ?? 83 F8 64 74 ?? 3D C8 00 00 00 74 ?? 3D 2C 01 00 00 75 ?? E8 ?? ?? ?? ?? B9 D0 07 00 00 E8 }

     condition:
        all of them
}

rule Lazarus_Comebacker_strings {
    meta:
        description = "Comebacker malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "1ff4421a99793acda5dd7412cb9a62301b14ed0a455edbb776f56471bef08f8f"

     strings:
        $postdata1 = "%s=%s&%s=%s&%s=%s&%s=%d&%s=%d&%s=%s" ascii
        $postdata2 = "Content-Type: application/x-www-form-urlencoded" wide
        $postdata3 = "Connection: Keep-Alive" wide
        $key  = "5618198335124815612315615648487" ascii
        $str1 = "Hash error!" ascii wide
        $str2 = "Dll Data Error|" ascii wide
        $str3 = "GetProcAddress Error|" ascii wide
        $str4 = "Sleeping|" ascii wide
        $str5 = "%s|%d|%d|" ascii wide

     condition:
        all of ($postdata*) or $key or all of ($str*)
}

rule Lazarus_VSingle_strings {
     meta:
        description = "VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
        hash2 = "63fa8ce7bf7c8324ed16c297092e1b1c5c0a0f8ab7f583ab16aa86a7992193e6"

     strings:
        $encstr1 = "Valefor was uninstalled successfully." ascii wide
        $encstr2 = "Executable Download Parameter Error" ascii wide
        $encstr3 = "Plugin Execute Result" ascii wide
        $pdb = "G:\\Valefor\\Valefor_Single\\Release\\VSingle.pdb" ascii
        $str1 = "sonatelr" ascii
        $str2 = ".\\mascotnot" ascii
        $str3 = "%s_main" ascii
        $str4 = "MigMut" ascii
        $str5 = "lkjwelwer" ascii
        $str6 = "CreateNamedPipeA finished with Error-%d" ascii
        $str7 = ".\\pcinpae" ascii
        $str8 = { C6 45 80 4C C6 45 81 00 C6 45 82 00 C6 45 83 00 C6 45 84 01 C6 45 85 14 C6 45 86 02 C6 45 87 00 }
        $xorkey1 = "o2pq0qy4ymcrbe4s" ascii wide
        $xorkey2 = "qwrhcd4pywuyv2mw" ascii wide
        $xorkey3 = "3olu2yi3ynwlnvlu" ascii wide
        $xorkey4 = "uk0wia0uy3fl3uxd" ascii wide

     condition:
        all of ($encstr*) or $pdb or 1 of ($xorkey*) or 3 of ($str*)
}

rule Lazarus_ValeforBeta_strings {
    meta:
        description = "ValeforBeta malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"

     strings:
        $str0 = "cmd interval: %d->%d" ascii wide
        $str1 = "script interval: %d->%d" ascii wide
        $str2 = "Command not exist. Try again." ascii wide
        $str3 = "successfully uploaded from %s to %s" ascii wide
        $str4 = "success download from %s to %s" ascii wide
        $str5 = "failed with error code: %d" ascii wide

     condition:
        3 of ($str*)
}

//import "pe"

//rule Lzarus_2toy_sig {
//   meta:
//      description = "Lazarus using signature 2 TOY GUYS LLC"
//      date = "2021-02-03"
//      author = "JPCERT/CC Incident Response Group"
//      hash1 = "613f1cc0411485f14f53c164372b6d83c81462eb497daf6a837931c1d341e2da"
//      hash2 = "658e63624b73fc91c497c2f879776aa05ef000cb3f38a340b311bd4a5e1ebe5d"

//   condition:
//      uint16(0) == 0x5a4d and
//      for any i in (0 .. pe.number_of_signatures) : (
//         pe.signatures[i].issuer contains "2 TOY GUYS LLC" and
//         pe.signatures[i].serial == "81:86:31:11:0B:5D:14:33:1D:AC:7E:6A:D9:98:B9:02"
//      )
//}

rule Lazarus_packer_code {
    meta:
        description = "Lazarus using packer"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
        hash2 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"

     strings:
        $code = { 55 8B EC A1 ?? ?? ?? 00 83 C0 01 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 ( 01 | 02 | 03 | 04 | 05 ) 76 16 8B 0D ?? ?? ?? 00 83 E9 01 89 0D ?? ?? ?? 00 B8 ?? ?? ?? ?? EB  }
     condition:
        all of them
}

rule Lazarus_Kaos_golang {
    meta:
        description = "Kaos malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "6db57bbc2d07343dd6ceba0f53c73756af78f09fe1cb5ce8e8008e5e7242eae1"
        hash2 = "2d6a590b86e7e1e9fa055ec5648cd92e2d5e5b3210045d4c1658fe92ecf1944c"

     strings:
        $gofunc1 = "processMarketPrice" ascii wide
        $gofunc2 = "handleMarketPrice" ascii wide
        $gofunc3 = "EierKochen" ascii wide
        $gofunc4 = "kandidatKaufhaus" ascii wide
        $gofunc5 = "getInitEggPrice" ascii wide
        $gofunc6 = "HttpPostWithCookie" ascii wide

     condition:
        4 of ($gofunc*)
}

rule Lazarus_VSingle_elf {
    meta:
        description = "ELF_VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"

     strings:
        $code1 = { C6 85 ?? ?? FF FF 26 C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 73 } // &uis
        $code2 = { C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 66 C6 85 ?? ?? FF FF 77 } // ufw
        $code3 = { C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 73 C6 85 ?? ?? FF FF 7C C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 78 } // %s|%x
        $code4 = { C6 85 ?? ?? FF FF 4D C6 85 ?? ?? FF FF 6F C6 85 ?? ?? FF FF 7A C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 61 C6 85 ?? ?? FF FF 2F } // Mozilla
        $code5 = { C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 73 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 } // %s%1u%1u
     condition:
        3 of ($code*)
}

rule Lazarus_packer_upxmems {
    meta:
        description = "ELF malware packer based UPX in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"

     strings:
        $code1 = { 47 2C E8 3C 01 77 [10-14] 86 C4 C1 C0 10 86 C4 }
                                       // inc edi
                                       // sub al, 0E8h
                                       // cmp al, 1
                                       // xchg al, ah
                                       // rol eax, 10h
                                       // xchg al, ah
        $code2 = { 81 FD 00 FB FF FF 83 D1 02 8D } // cmp ebp, FFFFFB00h    adc ecx, 2
        $sig = "MEMS" ascii
     condition:
        all of ($code*) and #sig >= 3 and uint32(0x98) == 0x534d454d
}

rule Lazarus_httpbot_jsessid {
    meta:
        description = "Unknown HTTP bot in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "451ad26a41a8b8ae82ccfc850d67b12289693b227a7114121888b444d72d4727"

     strings:
        $jsessid = "jsessid=%08x%08x%08x" ascii
        $http = "%04x%04x%04x%04x" ascii
        $init = { 51 68 ?? ?? ?? 00 51 BA 04 01 00 00 B9 ?? ?? ?? 00 E8 }
        $command = { 8B ?? ?? 05 69 62 2B 9F 83 F8 1D 0F ?? ?? ?? 00 00 FF}

     condition:
        $command or ($jsessid and $http and #init >= 3)
}

rule Lazarus_tool_smbscan {
    meta:
        description = "SMB scan tool in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc"
        hash2 = "11b29200f0696041dd607d0664f1ebf5dba2e2538666db663b3077d77f883195"

     strings:
        $toolstr1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" ascii
        $toolstr2 = "%s%-30s%I64d\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr3 = "%s%-30s(DIR)\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr4 = "%s U/P not Correct! - %d" ascii
        $toolstr5 = "%s %-20S%-30s%S" ascii
        $toolstr6 = "%s - %s:(Username - %s / Password - %s" ascii

     condition:
        4 of ($toolstr*)
}

rule Lazarus_simplecurl_strings {
    meta:
        description = "Tool of simple curl in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "05ffcbda6d2e38da325ebb91928ee65d1305bcc5a6a78e99ccbcc05801bba962"
     strings:
        $str1 = "Usage: [application name].exe url filename" ascii
        $str2 = "completely succeed!" ascii
        $str3 = "InternetOpenSession failed.." ascii
        $str4 = "HttpSendRequestA failed.." ascii
        $str5 = "HttpQueryInfoA failed.." ascii
        $str6 = "response code: %s" ascii
        $str7 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :" ascii
     condition:
        4 of ($str*)
}

rule Lazarus_Dtrack_code {
     meta:
        description = "Dtrack malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "2bcb693698c84b7613a8bde65729a51fcb175b04f5ff672811941f75a0095ed4"
        hash = "467893f5e343563ed7c46a553953de751405828061811c7a13dbc0ced81648bb"

     strings:
        $rc4key1 = "xwqmxykgy0s4"
        $rc4key2 = "hufkcohxyjrm"
        $rc4key3 = "fm5hkbfxyhd4"
        $rc4key4 = "ihy3ggfgyohx"
        $rc4key5 = "fwpbqyhcyf2k"
        $rc4key6 = "rcmgmg3ny3pa"
        $rc4key7 = "a30gjwdcypey"
        $zippass1 = "dkwero38oerA^t@#"
        $zippass2 = "z0r0f1@123"
        $str1 = "Using Proxy"
        $str2 = "Preconfig"
        $str3 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :"
        $str4 = "%02X:%02X:%02X:%02X:%02X:%02X"
        $str5 = "%s\\%c.tmp"
        $code = { 81 ?? EB 03 00 00 89 ?? ?? ?? FF FF 83 ?? ?? ?? FF FF 14 0F 87 EA 00 00 00 }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($rc4key*) or 1 of ($zippass*) or (3 of  ($str*) and $code))
}

rule Lazarus_keylogger_str {
     meta:
        description = "Keylogger in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "e0567863b10e9b1ac805292d30626ea24b28ee12f3682a93d29120db3b77a40a"

     strings:
        $mutex = "c2hvcGxpZnRlcg"
        $path = "%APPDATA%\\\\Microsoft\\\\Camio\\\\"
        $str = "[%02d/%02d/%d %02d:%02d:%02d]"
        $table1 = "CppSQLite3Exception"
        $table2 = "CppSQLite3Query"
        $table3 = "CppSQLite3DB"
        $table4 = "CDataLog"
        $table5 = "CKeyLogger"

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       4 of them
}

rule Lazarus_DreamJob_doc2021 {
     meta:
        description = "Malicious doc used in Lazarus operation Dream Job"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "ffec6e6d4e314f64f5d31c62024252abde7f77acdd63991cb16923ff17828885"
        hash2 = "8e1746829851d28c555c143ce62283bc011bbd2acfa60909566339118c9c5c97"
        hash3 = "294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"

     strings:
        $peheadb64 = "dCBiZSBydW4gaW4gRE9TIG1vZGU"
        $command1 = "cmd /c copy /b %systemroot%\\system32\\"
        $command2 = "Select * from Win32_Process where name"
        $command3 = "cmd /c explorer.exe /root"
        $command4 = "-decode"
        $command5 = "c:\\Drivers"
        $command6 = "explorer.exe"
        $command7 = "cmd /c md"
        $command8 = "cmd /c del"

     condition:
       uint16(0) == 0xCFD0 and
       $peheadb64 and 4 of ($command*)
}

rule Lazarus_boardiddownloader_code {
     meta:
        description = "boardid downloader in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "fe80e890689b0911d2cd1c29196c1dad92183c40949fe6f8c39deec8e745de7f"

     strings:
        $enchttp = { C7 ?? ?? 06 1A 1A 1E C7 ?? ?? 1D 54 41 41 }
        $xorcode = { 80 74 ?? ?? 6E 80 74 ?? ?? 6E (48 83|83) ?? 02 (48|83) }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}
