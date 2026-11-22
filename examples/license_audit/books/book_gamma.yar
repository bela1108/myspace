// release_book: book_gamma

rule BankerStr_Gamma {
    meta:
        authorization_id = "AZ-7741"
        sample_id = "SP-1001"
        receipt_text = "Sample source license recorded: shared threat-intel feed."
        scope = "internal_detection"
    strings:
        $login = "https://bank.example.test/login"
        $post = "X-Banker-Token"
    condition: any of them
}

rule LoaderSig_Gamma {
    meta:
        authorization_id = "AUTH-0099"
        sample_id = "SAM-3099"
        receipt_text = "Loader artifacts licensed under the incident-sharing MOU."
        scope = "internal_detection"
    strings:
        $ldr = "beta_loader_marker"
    condition: $ldr
}

rule BackdoorStr {
    meta:
        authorization_id = "AUTH-0005"
        sample_id = "SAM-5005"
        receipt_text = "Backdoor sample license, case partner exchange PX-09."
        scope = "internal_detection"
    strings:
        $bd = "backdoor_implant_beacon_v2"
    condition: $bd
}

