// release_book: book_beta

rule BankerStr_Beta {
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

rule BetaStealer {
    meta:
        authorization_id = "AUTH-0002"
        sample_id = "SAM-2002"
        receipt_text = "Vendor sample-sharing authorization, ref VND-226."
        scope = "internal_detection"
    strings:
        $p = "beta_stealer_c2"
        $q = "beta_stealer_ua"
    condition: any of them
}

rule LoaderSig_Beta {
    meta:
        authorization_id = "AUTH-0003"
        sample_id = "SAM-3003"
        receipt_text = "Loader artifacts licensed under the incident-sharing MOU."
        scope = "internal_detection"
    strings:
        $ldr = "beta_loader_marker"
    condition: $ldr
}

rule RansomNote_Beta {
    meta:
        authorization_id = "AUTH-0004"
        sample_id = "SAM-4004"
        receipt_text = "Ransom note corpus licensed via vendor portal VP-44."
        scope = "external_publication"
    strings:
        $note = "your files have been encrypted"
    condition: $note
}

