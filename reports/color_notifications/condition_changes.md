# Condition changes with counterexamples

## 🔴 ColorNotification_Amber

- Baseline: `rules/color_notifications/baseline/color_notifications.yar`
- Candidate: `rules/color_notifications/changed/color_notifications.yar`
- Baseline condition: `( $amber or $orange ) and ( $warning or cn_has_notification_channel ) and #warning >= 2`
- Candidate condition: `( ( $amber or $orange ) and ( $warning or cn_has_notification_channel ) and #warning >= 5 )`
- Baseline result: `True`
- Candidate result: `False`

| Abstract atom | Occurrences | Match |
| --- | ---: | --- |
| `ColorNotification_Amber.$amber` | 0 | False |
| `ColorNotification_Amber.$orange` | 1 | True |
| `ColorNotification_Amber.$warning` | 2 | True |
| `cn_has_notification_channel.$alert` | 0 | False |
| `cn_has_notification_channel.$notification` | 0 | False |
| `cn_has_notification_channel.$notify` | 0 | False |
| `cn_has_notification_channel.$webhook` | 0 | False |

## 🔴 ColorNotification_Blue

- Baseline: `rules/color_notifications/baseline/color_notifications.yar`
- Candidate: `rules/color_notifications/changed/color_notifications.yar`
- Baseline condition: `1 of ( $blue , $azure ) and ( $info or cn_has_notification_channel )`
- Candidate condition: `2 of ( $blue , $azure ) and ( $info or cn_has_notification_channel )`
- Baseline result: `True`
- Candidate result: `False`

| Abstract atom | Occurrences | Match |
| --- | ---: | --- |
| `ColorNotification_Blue.$azure` | 0 | False |
| `ColorNotification_Blue.$blue` | 1 | True |
| `ColorNotification_Blue.$info` | 0 | False |
| `cn_has_notification_channel.$alert` | 0 | False |
| `cn_has_notification_channel.$notification` | 0 | False |
| `cn_has_notification_channel.$notify` | 0 | False |
| `cn_has_notification_channel.$webhook` | 1 | True |

## 🔴 ColorNotification_Green

- Baseline: `rules/color_notifications/baseline/color_notifications.yar`
- Candidate: `rules/color_notifications/changed/color_notifications.yar`
- Baseline condition: `all of ( $green , $emerald ) and ( $success or cn_has_notification_channel )`
- Candidate condition: `any of ( $green , $emerald ) and ( $success or cn_has_notification_channel )`
- Baseline result: `False`
- Candidate result: `True`

| Abstract atom | Occurrences | Match |
| --- | ---: | --- |
| `ColorNotification_Green.$emerald` | 0 | False |
| `ColorNotification_Green.$green` | 1 | True |
| `ColorNotification_Green.$success` | 0 | False |
| `cn_has_notification_channel.$alert` | 0 | False |
| `cn_has_notification_channel.$notification` | 0 | False |
| `cn_has_notification_channel.$notify` | 0 | False |
| `cn_has_notification_channel.$webhook` | 1 | True |

## 🔴 ColorNotification_Red

- Baseline: `rules/color_notifications/baseline/color_notifications.yar`
- Candidate: `rules/color_notifications/changed/color_notifications.yar`
- Baseline condition: `( cn_red_vocabulary and cn_has_notification_channel ) or ( $badge and cn_has_notification_channel )`
- Candidate condition: `( cn_red_vocabulary or cn_has_notification_channel ) or ( $badge and cn_has_notification_channel )`
- Baseline result: `False`
- Candidate result: `True`

| Abstract atom | Occurrences | Match |
| --- | ---: | --- |
| `ColorNotification_Red.$badge` | 0 | False |
| `ColorNotification_Red.$ui` | 0 | False |
| `cn_has_notification_channel.$alert` | 0 | False |
| `cn_has_notification_channel.$notification` | 0 | False |
| `cn_has_notification_channel.$notify` | 0 | False |
| `cn_has_notification_channel.$webhook` | 0 | False |
| `cn_red_vocabulary.$crimson` | 0 | False |
| `cn_red_vocabulary.$red` | 1 | True |
| `cn_red_vocabulary.$scarlet` | 1 | True |
