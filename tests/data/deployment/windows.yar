rule windows_alpha
{
    meta:
        deploy = "windows"
    strings:
        $w = "windows"
    condition:
        $w and base_alpha
}
