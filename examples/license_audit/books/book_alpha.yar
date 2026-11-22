// release_book: book_alpha
// Ordinary text matching rules with a sample-source license receipt each.

rule AlphaTextIndicator {
    meta:
        authorization_id = "AUTH-7001"
        sample_id = "SAMPLE-AA-01"
        receipt_text = "Alpha vendor shared this sample for internal detection use only."
        scope = "internal_detection"
    strings:
        $marker = "alpha-proprietary-marker"
    condition: $marker
}

rule CampaignSharedText {
    meta:
        authorization_id = "AUTH-8100"
        sample_id = "SAMPLE-BB-01"
        receipt_text = "Shared campaign string licensed from the alpha exchange."
        scope = "internal_detection"
    strings:
        $marker = "shared-campaign-string"
    condition: $marker
}

