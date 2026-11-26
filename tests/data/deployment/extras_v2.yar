rule extras_legacy
{
    meta:
        deploy = "legacy"
    condition:
        true
}

rule extras_upgraded
{
    meta:
        deploy = "upgraded"
    strings:
        $u = "upgraded"
    condition:
        $u
}
