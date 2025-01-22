/*
    YARA rules for phishing kit detection
    Author: PhishingKit Analyzer
    Date: 2024
*/

rule phishing_login_form {
    meta:
        description = "Detects suspicious login forms"
        author = "PhishingKit Analyzer"
        severity = "medium"
        
    strings:
        $form1 = "<form" nocase
        $form2 = "method=" nocase
        $form3 = "action=" nocase
        $input1 = "type=\"password\"" nocase
        $input2 = "type=\"text\"" nocase
        $input3 = "type=\"email\"" nocase
        $submit = "type=\"submit\"" nocase
        
        $sus1 = "login" nocase
        $sus2 = "signin" nocase
        $sus3 = "account" nocase
        
    condition:
        all of ($form*) and
        2 of ($input*) and
        $submit and
        1 of ($sus*)
}

rule phishing_data_exfiltration {
    meta:
        description = "Detects data exfiltration mechanisms"
        author = "PhishingKit Analyzer"
        severity = "high"
        
    strings:
        $mail1 = "mail(" nocase
        $mail2 = "sendmail" nocase
        $mail3 = "smtp" nocase
        
        $post1 = "curl_exec" nocase
        $post2 = "file_get_contents" nocase
        $post3 = "fopen" nocase
        
        $data1 = "password" nocase
        $data2 = "credential" nocase
        $data3 = "username" nocase
        $data4 = "email" nocase
        
    condition:
        (1 of ($mail*) or 1 of ($post*)) and
        2 of ($data*)
}

rule phishing_obfuscation {
    meta:
        description = "Detects common obfuscation techniques"
        author = "PhishingKit Analyzer"
        severity = "high"
        
    strings:
        $encode1 = "base64_decode" nocase
        $encode2 = "str_rot13" nocase
        $encode3 = "gzinflate" nocase
        $encode4 = "eval(" nocase
        $encode5 = "\\x" nocase
        
        $var1 = /\$[a-zA-Z0-9_]{1,2}\s*=/ // Short variables
        $var2 = /@?eval\(\$[a-zA-Z0-9_]{1,2}\)/ // Eval with short variables
        
    condition:
        2 of ($encode*) or
        (#var1 > 5 and $var2)
}

rule phishing_fake_page {
    meta:
        description = "Detects phishing pages imitating legitimate services"
        author = "PhishingKit Analyzer"
        severity = "medium"
        
    strings:
        // Commonly targeted brands
        $brand1 = "microsoft" nocase
        $brand2 = "google" nocase
        $brand3 = "apple" nocase
        $brand4 = "paypal" nocase
        $brand5 = "amazon" nocase
        $brand6 = "facebook" nocase
        $brand7 = "linkedin" nocase
        
        // Suspicious terms
        $sus1 = "verify" nocase
        $sus2 = "secure" nocase
        $sus3 = "update" nocase
        $sus4 = "confirm" nocase
        
        // Images and logos
        $img1 = "logo" nocase
        $img2 = ".svg" nocase
        $img3 = ".png" nocase
        
    condition:
        1 of ($brand*) and
        2 of ($sus*) and
        1 of ($img*)
}

rule phishing_evasion {
    meta:
        description = "Detects evasion and anti-analysis techniques"
        author = "PhishingKit Analyzer"
        severity = "high"
        
    strings:
        // Bot and crawler detection
        $bot1 = "HTTP_USER_AGENT" nocase
        $bot2 = "bot" nocase
        $bot3 = "crawler" nocase
        $bot4 = "spider" nocase
        
        // Geographical blocking
        $geo1 = "geoip" nocase
        $geo2 = "country" nocase
        
        // Anti-debugging
        $debug1 = "ini_set('display_errors'" nocase
        $debug2 = "error_reporting(0)" nocase
        
        // Redirections
        $redir1 = "header(\"Location:" nocase
        $redir2 = "window.location" nocase
        
    condition:
        (2 of ($bot*) and 1 of ($redir*)) or
        (1 of ($geo*) and 1 of ($redir*)) or
        (all of ($debug*))
}

rule phishing_credential_theft {
    meta:
        description = "Detects credential theft"
        author = "PhishingKit Analyzer"
        severity = "high"
        
    strings:
        // Sensitive form fields
        $field1 = "password" nocase
        $field2 = "passwd" nocase
        $field3 = "pass" nocase
        $field4 = "pwd" nocase
        $field5 = "username" nocase
        $field6 = "user" nocase
        $field7 = "email" nocase
        
        // Data storage/sending
        $store1 = "fwrite" nocase
        $store2 = "file_put_contents" nocase
        $store3 = "mysqli" nocase
        $store4 = "PDO" nocase
        
        // Suspicious headers
        $header1 = "$_POST" nocase
        $header2 = "$_REQUEST" nocase
        
    condition:
        3 of ($field*) and
        1 of ($store*) and
        1 of ($header*)
}

rule phishing_kit_structure {
    meta:
        description = "Detects the typical structure of a phishing kit"
        author = "PhishingKit Analyzer"
        severity = "medium"
        
    strings:
        // Common files
        $file1 = "index.php" nocase
        $file2 = "login.php" nocase
        $file3 = "submit.php" nocase
        $file4 = "success.php" nocase
        $file5 = "config.php" nocase
        
        // Common directories
        $dir1 = "/images/" nocase
        $dir2 = "/includes/" nocase
        $dir3 = "/assets/" nocase
        
        // Configurations
        $conf1 = "define(" nocase
        $conf2 = "include(" nocase
        $conf3 = "require(" nocase
        
    condition:
        2 of ($file*) and
        1 of ($dir*) and
        2 of ($conf*)
} 