rule outlook_login_01 {
    meta:
        author = "BloodyShell"
        date = "2023-09-24"
        link = "https://github.com/LeakIX/yara-repo-leakix"
        tlp = "WHITE"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
    strings:
        $str_1 = "aria-label=\"Outlook\""
        $str_2 = "signInCheckBoxText"
        $str_3 = "Web App"
        $str_4 = "0utlook"

    condition:
        3 of them
}
