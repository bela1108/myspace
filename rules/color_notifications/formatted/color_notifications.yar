private rule cn_has_notification_channel {
    strings:
        $notify       = "notify" nocase
        $notification = "notification" nocase
        $webhook      = "webhook" nocase
        $alert        = "alert" nocase

    condition:
        any of them
}

private rule cn_red_vocabulary {
    strings:
        $red     = "red" nocase
        $crimson = "crimson" nocase
        $scarlet = "scarlet" nocase

    condition:
        (
            2 of ($red, $crimson, $scarlet)
            or #red >= 2
        )
}

rule ColorNotification_Red {
    strings:
        $badge = "RED_NOTIFICATION"
        $ui    = "color-red"

    condition:
        (
            cn_red_vocabulary
            and cn_has_notification_channel
        )
        or (
            $badge
            and cn_has_notification_channel
        )
}

rule ColorNotification_Amber {
    strings:
        $amber   = "amber" nocase
        $orange  = "orange" nocase
        $warning = "warning" nocase

    condition:
        (
            ($amber or $orange)
            and ($warning or cn_has_notification_channel)
            and #warning >= 2
        )
}

rule ColorNotification_Green {
    strings:
        $green   = "green" nocase
        $emerald = "emerald" nocase
        $success = "success" nocase

    condition:
        all of ($green, $emerald)
        and ($success or cn_has_notification_channel)
}

rule ColorNotification_Blue {
    strings:
        $blue  = "blue" nocase
        $azure = "azure" nocase
        $info  = "info" nocase

    condition:
        1 of ($blue, $azure)
        and ($info or cn_has_notification_channel)
}
