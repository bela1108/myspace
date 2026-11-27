import "pe"

rule LibCallDemo
{
    strings:
        $a = "evil" nocase
    condition:
        pe.imports("kernel32.dll", "CreateFileW") and $a
}

