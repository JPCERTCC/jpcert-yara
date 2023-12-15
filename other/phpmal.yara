rule malware_lvscam_phpwebshell {
    meta:
        description = "PHP malware used in lucky visitor scam"
        author = "JPCERT/CC Incident Response Group"
        hash = "1c7fe8ee16da73a337c1502b1fe600462ce4b9a3220f923d02f900ea61c63020"
        hash = "aebeadc7a6c5b76d842c7852705152930c636866c7e6e5a9fa3be1c15433446c"

    strings:
        $s1 = "http://136.12.78.46/app/assets/api"
        $s2 = "['a'] == 'doorway2')"
        $s3 = "['sa'] == 'eval')"

    condition:
        2 of them
}

rule malware_seospam_php {
     meta:
        description = "PHP using Japanese SEO Spam"
        author = "JPCERT/CC Incident Response Group"
        hash = "619cf6a757a1967382287c30d95b55bed3750e029a7040878d2f23efda29f8f0"

     strings:
        $func1 = "function dageget($" ascii
        $func2 = "function sbot()" ascii
        $func3 = "function st_uri()" ascii
        $func4 = "function is_htps()" ascii
        $query1 = /sha1\(sha1\(@\$_GET\[\"(a|\\x61|\\141)"\]\)\);/ ascii
        $query2 = /sha1\(sha1\(@\$_GET\[\"(b|\\x62|\\142)"\]\)\);/ ascii
        $query3 = /@\$_GET\[\"(p|\\x70|\\160)(d|\\x64|\\144)\"\]/ ascii
        $content1 = "nobotuseragent" ascii
        $content2 = "okhtmlgetcontent" ascii
        $content3 = "okxmlgetcontent" ascii
        $content4 = "pingxmlgetcontent" ascii

     condition:
       7 of them
}
