rule ReorderDemo
{
    strings:
        $a = "evil" nocase
        $b = { 6A 40 68 00 30 00 00 }
        $c = /cmd\.exe\s+\/c/
    condition:
        (not $a and $c) or ($b and $a)
}

