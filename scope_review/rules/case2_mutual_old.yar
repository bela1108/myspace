rule MutualDemo
{
    strings:
        $a = "evil" nocase
        $b = "payload"
        $c = "c2.beacon"
    condition:
        $a and $b
}

