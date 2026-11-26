rule base_shared
{
    meta:
        deploy = "base"
        owner = "soc"
    condition:
        filesize < 10000
}

rule base_alpha
{
    meta:
        deploy = "base"
        deploy = "windows"
        owner = "soc"
    strings:
        $a = "alpha"
    condition:
        $a and base_shared
}

rule base_linux
{
    meta:
        deploy = "linux"
    condition:
        true
}
