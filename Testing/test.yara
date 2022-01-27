rule test_binaries {
 
  strings:
     $s1 = "GetActiveWindowMessageBoxAUSER32.DLL"
     $s2 = "WriteFilez"
     $s3 = "EnumResourceTypesW"

  condition:
    uint16(0) == 0x5a4d and all of them
}