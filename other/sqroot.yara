rule malware_sqroot_code {
     meta:
        description = "sqroot malware using unknown actors"
        author = "JPCERT/CC Incident Response Group"
        hash = "556018653737386c9d291cb2ca90cde360394897b2e7800c7eb119730d3bda3c"

     strings:
        $str1 = "sqroot" ascii wide
        $str2 = "1234QWER11" ascii wide
        $str3 = "edge_service_packet.tmp" ascii wide
        $str4 = "/ol" ascii wide
        $str5 = "/task" ascii wide
        $str6 = "%s %s \"%s-%s|%s-%s %s,%s,%s|%s-%s -%s|%s-%s -%s %d" ascii wide
        $str7 = "jss/font-awesome.min.css" ascii wide
        $str8 = "css/jquery-ui.min.css" ascii wide
        $str9 = "{\"%s\":\"%s(%s)\",\"%s\":\"%s\",\"%s\":\"%s\"}" ascii wide
        $str10 = "/dl" ascii wide
        $str11 = "21.30.ec.9d.c4.20" ascii wide
        $str12 = "/papers/ja-jp" ascii wide
        $filename1 = "8015ba282c" ascii wide
        $filename2 = "abb8fcc3b5" ascii wide
        $filename3 = "8714c42184" ascii wide
        $filename4 = "6eadde753d" ascii wide

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (7 of ($str*) or all of ($filename*))
}

//import "pe"
//rule malware_sqroot_loader {
//     meta:
//        description = "sqroot loader using unknown actors"
//        author = "JPCERT/CC Incident Response Group"
//        hash = "e65f5683ad6272feff5a59175ef55525e0c873c373cf030fd937e2527f53efd1"

//     condition:
//       uint16(0) == 0x5A4D and
//       uint32(uint32(0x3c)) == 0x00004550 and
//       pe.number_of_sections >= 6 and
//       for any i in (0..pe.number_of_sections -1):
//       (
//           pe.sections[i].name iequals ".newimp"
//       ) and
//       (
//           pe.imports("dmiapi32.dll", "R32Start")
//       )
//}

rule malware_sqroot_lnk {
     meta:
        description = "sqroot drop lnk file using unknown actors"
        author = "JPCERT/CC Incident Response Group"
        hash = "16ac092af64bbab7dbaef60cd796e47c5d2a6fec6164906c1fbd0c9c51861936"

     strings:
       $command1 = "bwBuACAAZQByAHIAbwByACAAcgBlAHMA" wide
       $command2 = "%temp%\\ex.lnk" wide nocase
       $command3 = "%temp%\\f.vbs" wide nocase
       $command4 = "%temp%\\b64.txt" wide nocase
       $command5 = "%temp%\\i.log" wide nocase
       $command6 = "%temp%\\result.vbs" wide nocase
       $command7 = ".position = .size-12" wide
       $command8 = "AscW(.read(2))=^&" wide

     condition:
       uint16(0) == 0x004c and
       filesize>1MB and
       4 of ($command*)
}

rule malware_sqroot_webphp {
     meta:
        description = "sqroot drop web page using unknown actors"
        author = "JPCERT/CC Incident Response Group"
        hash = "8b9f229012512b9e4fb924434caa054275410574c5b0c364b850bb2ef70a0f3d"

     strings:
       $func1 = "send_download_file_as_exe($filename)" ascii
       $func2 = "check_remote_client()" ascii
       $func3 = "mylog('[e]');" ascii
       $func4 = "mylog('[z]');" ascii
       $func5 = "mylog('[4]');" ascii
       $func6 = "mylog('[*]');" ascii
       $func7 = "mylog('[p]');" ascii
       $func8 = "mylog($flag)" ascii
       $func9 = "get_remote_ip()" ascii

     condition:
       uint32(0) == 0x68703f3c and
       4 of ($func*)
}