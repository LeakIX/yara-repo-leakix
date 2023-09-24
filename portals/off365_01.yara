rule office365_login_01 {
    meta:
        author = "BloodyShell"
        date = "2023-09-24"
        link = "https://github.com/LeakIX/yara-repo-leakix"
        tlp = "WHITE"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
    strings:
        $str_1 = "https://login.microsoftonline.com/common/GetCredentialType"
        $str_2 = "BannerLogo"
        $str_3 = "putuser"
        $str_4 = "loginHeader"

    condition:
        3 of them
}
