rule ReorderDemo
{
    strings:
        $a = "evil" nocase
        $b = { 6A 40 68 00 30 00 00 }
        $c = /cmd\.exe\s+\/c/
    condition:
        ($a and $b) or ($c and not $a)
}

