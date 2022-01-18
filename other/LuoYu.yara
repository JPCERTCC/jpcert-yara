rule malware_LuoYu_Stealer {
    meta:
      description = "detect LuoYu_Stealer"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "d9df38fcd9fb557ff26c5950a1a7478226091cca7f17c65162f68e5feb6e2d8d"
      hash2 = "1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128"
      hash3 = "b9f526eea625eec1ddab25a0fc9bd847f37c9189750499c446471b7a52204d5a"
      hash4 = "0c365d9730a10f1a3680d24214682f79f88aa2a2a602d3d80ef4c1712210ab07"
      hash5 = "2eef273af0c768b514db6159d7772054d27a6fa8bc3d862df74de75741dbfb9c"

    strings:
      /* monitoring files */
      $str_m1 = "~B5D9" fullword ascii
      $str_m2 = "65ce-731bffbb" fullword ascii
      $str_m3 = "~BF24" fullword ascii
      $str_m4 = "~BF34" fullword ascii
      $str_m5 = "63ae-a20cf808" fullword ascii
      $str_m6 = "28e4-20a6acec" fullword ascii
      $str_m7 = "~FFFE" fullword ascii
      $str_m8 = "~B5BE" fullword ascii
      $str_m9 = "~B61A" fullword ascii
      $str_m10 = "d0c8-b9baa92f" fullword ascii
      $str_m11 = "~CE14" fullword ascii
      $str_m12 = "070a-cf37dcf5"  fullword ascii

      /* routine */
      $auth1 = {DB 70 20 24}
      $auth2 = {2A C6 87 47}
      $str_r1 = "Shell Folders" fullword ascii
      $str_r2 = "Common AppData" fullword ascii
      $str_r3 = "%s\\*.a" fullword ascii
      $str_r4 = "ackfile" fullword ascii
      $str_r5 = "YYYY" fullword ascii
      $str_r6 = "%s\\*.*" fullword ascii
      $str_r7 = "%s\\c25549fe" fullword ascii

    condition:
      ($str_m1 and $str_m2 and $str_m3 and $str_m4 and $str_m5 and $str_m6 and $str_m7 and $str_m8 and $str_m9 and $str_m10 and $str_m11 and $str_m12)
       or ($auth1 and $auth2 and $str_r1 and $str_r2 and $str_r3 and $str_r4 and $str_r5 and $str_r6 and $str_r7)
}
