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
