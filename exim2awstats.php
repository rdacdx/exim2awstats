<?php

/*
    This file is a part of the exim2awstats project, version 0.1.
    http://exim2awstats.sourceforge.net
    Copyright (c) 2007 - MotivCode, LLC
    
    This software comes with ABSOLUTELY NO WARRANTY.  For details, see
    the enclosed file COPYING for license information (GPL).  If you
    did not receive this file, see http://www.gnu.org/licenses/gpl.txt.
*/

    ///////////////////////////
    // CONFIGURATION SECTION //
    ///////////////////////////

    // Set this to the location of your exim main log file.  If empty,
    // the path to the log file will come from the first command-line
    // argument (useful for processing multiple log files).

    //$exim_log_file = "/var/log/exim4/mainlog";
    $exim_log_file = "";

    // This section defines what is done with log entries the script
    // does not know how to handle.  If $error_email is non-empty then
    // an email with this information will be sent.  If $error_file is
    // non-empty then the information will be placed in that file.  Both
    // can be used simultaneously and if neither are defined then the
    // information is disregarded.  Note that with the email option,
    // the machine the script runs on must be setup to send mail.
    
    //$error_email = "someone@somewhere.com";
    $error_email = "";
    
    //$error_file = "/tmp/e2a_errors";
    $error_file = "";

    // This boolean flag can be enabled to print the above mentioned
    // errors as they occur.  This should only be used for debugging
    // as AWStats will not like this in the output of the script.
    
    $print_errors = false;
    
    // This limit may need to be increased if your log file is huge.
    
    ini_set("memory_limit", "64M");

    //////////////////
    // MAIN PROGRAM //
    //////////////////
    if($exim_log_file == "") $exim_log_file = $argv[1];

    if($exim_log_file == "")
    {
        print "No exim log file specified.\n";
        exit();
    }

    $ts_regex = "\d{4}\-\d{2}\-\d{2}\s+\d{2}\:\d{2}\:\d{2}";
    $id_regex = "[\w\d]+\-[\w\d]+\-[\w\d]+";
    $email_regex = "[\w\d\@\.\-\'\"\+\=\|\_]+";
    $from_email_regex = "($email_regex|\<\>)";
    $to_email_regex = "(?:(?:$email_regex\s+\<($email_regex)\>)|($email_regex))";
    $single_host = "\(?\[?[\w\d\-\.]+\]?\)?";
    $host_regex = "(?:H\=)?(?:($single_host)\s*($single_host)?\s*($single_host)?)?";
    $host_regex_noh = "(?:($single_host)\s*($single_host)?\s*($single_host)?)?";
    $user_regex = "(?:U\=)?([\w\d\-\\\@\.]+)?";
    $proto_regex = "P\=(\w+)";
    $enc_regex = "(?:X\=)?([\w\d\:\-]+)?";
    $auth_regex = "(?:A\=)?([\w\d\:\-\@\'\"\_\.]+)?";
    $size_regex = "S\=(\d+)";
    
    $error_log = "";
    $output = array();
    $mailings = array();

    function logerr($err)
    {
        if($GLOBALS['print_errors']) print "[EXIM2AWSTATS ERROR] $err\n";
        $GLOBALS['error_log'] .= "$err\n";
    }

    if(!($logfd = @fopen($exim_log_file, "r")))
    {
        print "Could not read the exim log file ($exim_log_file).\n";
        exit();
    }

    // Input loop.
    while(!feof($logfd))
    {
        $line = stream_get_line($logfd, 1024, "\n");
        proc_line($line);
    }

    // Checker/sorter.
    function proc_line(&$line)
    {
        global $mailings, $ts_regex, $id_regex;
        
        // Skip stuff we don't care about.
        if($line == "") return;
        if(strstr($line, "IPv6 socket creation failed: Address family not supported by protocol")) return;
        if(strstr($line, "Failed to create IPv6 socket for wildcard listening (Address family not supported by protocol): will use IPv4")) return;
        if(preg_match("/exim [\d\.]+ daemon started\: pid\=/", $line) > 0) return;
        if(strstr($line, "Start queue run: pid=")) return;
        if(strstr($line, "End queue run: pid=")) return;

        $check_regex = "/$ts_regex\s*($id_regex)/";
        $matches = array();
        if(preg_match($check_regex, $line, $matches) > 0)
        {
            $id = $matches[1];
    
            if(strstr($line, " <= ")) $mailings[$id]['from'] = $line;
            else if(strstr($line, " => ")) $mailings[$id]['to'][] = $line;
            else if(strstr($line, " -> ")) $mailings[$id]['to'][] = $line;
            else if(strstr($line, " == ")) return;
            else
            {
                $complete_regex = "/[\w\d\s\-\:]+\ Completed$/";
                if(preg_match($complete_regex, $line) == 0)
                {
                    if(strstr($line, "SMTP error from remote mail server after initial connection:")) return;
                    if(strstr($line, "Warning: ACL \"warn\" statement skipped: condition test deferred")) return;
                    if(strstr($line, "Spool file is locked (another process is handling this message)")) return;
                    if(strstr($line, "spam acl condition: error reading from spamd socket: ")) return;
                    $mailings[$id]['error'] = str_replace(" $id", "", $line);
                }
            }
        }
        else $mailings['NOID-' . $ts . "-" . mt_rand(1, 10000)]['error'] = $line;
    }

    fclose($logfd);

    // Processing loop.
    foreach($mailings as $id => $mailing)
    {
        if(isset($mailing['error']) && $mailing['error'] != ""){proc_error($mailing['error']);}
        else
        {
            if((count($mailing['to']) == 0) || ($mailing['from'] == "")){continue;}
            else {proc_mailing($id, $mailing);}
        }
    }

    function proc_error(&$line)
    {
        global $output, $mailings, $ts_regex, $id_regex, $email_regex, $from_email_regex, $to_email_regex, $single_host, $host_regex, $host_regex_noh, $user_regex, $proto_regex, $enc_regex, $auth_regex, $size_regex;

        $err_regex = "/($ts_regex)\s*/";
        $matches = array();

        if(preg_match($err_regex, $line, $matches) == 0)
        {
            logerr("MALFORMED ERROR LINE: $line");
            return;
        }

        $o = array();
        $o['ts'] = $matches[1];
        $o['code'] = "";

        $err = substr($line, strlen($o['ts']) + 1);

        $err_recs = array();
        $err_recs[] = array("code" => 451, "regex" => "/unexpected disconnection while reading SMTP command from $host_regex_noh/", "matches" => "from_ip");
        $err_recs[] = array("code" => 451, "regex" => "/Remote host $host_regex_noh closed connection in response to initial connection/", "matches" => "from_ip");
        $err_recs[] = array("code" => 451, "regex" => "/SMTP data timeout \(message abandoned\) on connection from $host_regex_noh F\=\<($email_regex)?\>/", "matches" => "from_ip,from_email");
        $err_recs[] = array("code" => 451, "regex" => "/SMTP error from remote mail server after end of data\: host ($host_regex_noh)\: 451 4.3.0/", "matches" => "from_ip");
        $err_recs[] = array("code" => 501, "regex" => "/rejected (?:(?:EHLO)|(?:HELO)) from $host_regex_noh\: syntactically invalid argument/", "matches" => "from_ip");
        $err_recs[] = array("code" => 503, "regex" => "/SMTP protocol synchronization error \([\w\d\s\:]+\)\: rejected (?:(?:connection from)|(?:\".+\")) $host_regex (?:next )?input/", "matches" => "from_ip");
        $err_recs[] = array("code" => 503, "regex" => "/SMTP call from $host_regex_noh dropped\: too many nonmail commands/", "matches" => "from_ip");
        $err_recs[] = array("code" => 503, "regex" => "/ignoring AUTH=\\<($email_regex)\> from $host_regex \(client not authenticated\)/", "matches" => "from_ip");
        $err_recs[] = array("code" => 535, "regex" => "/mysql\_login authenticator failed for $host_regex_noh\: 535 Incorrect authentication data \(set\_id\=($user_regex)\)/", "matches" => "from_ip,auth");
        $err_recs[] = array("code" => 550, "regex" => "/$host_regex F\=\<($email_regex)?\> rejected RCPT \<($email_regex)\>\: /", "matches" => "from_ip,from_email,to_email");
        $err_recs[] = array("code" => 550, "regex" => "/\*\* ($email_regex) R\=[\w\_]+ T\=[\w\_]+\: SMTP error from remote mail server after RCPT TO:\<$email_regex\>\: host ($host_regex_noh)\: 550 Requested action not taken: mailbox unavailable/", "matches" => "from_email,from_ip");
        $err_recs[] = array("code" => 550, "regex" => "/\*\* ($email_regex) R\=[\w\_]+ T\=[\w\_]+\: SMTP error from remote mail server after end of data: host ($host_regex_noh)\: 550 5.7.1 This system has been configured to reject your mail./", "matches" => "from_email,from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/no host name found for IP address ($single_host)/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/no IP address found for host ($single_host)/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/SMTP connection from $host_regex_noh lost while reading message data/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/SMTP command timeout on connection from $host_regex_noh/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/SMTP command timeout on TLS connection from $host_regex_noh/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/host name alias list truncated for ($single_host)/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/TLS error on connection from $host_regex_noh \(SSL\_accept\)\: error\:/", "matches" => "from_ip");
        $err_recs[] = array("code" => 554, "regex" => "/\*\* ($email_regex) \<$email_regex\>\: Unrouteable address/", "matches" => "to_email");

        foreach($err_recs as $err_rec)
        {
            $from_ip = "";
            $auth = "";
            $from_email = "";
            $to_email = "";

            $submatches = array();
            if(preg_match($err_rec['regex'], $err, $submatches) > 0)
            {
                $o['code'] = $err_rec['code'];

                $matchorder = explode(",", $err_rec['matches']);
                $ctr = 1;

                foreach($matchorder as $matchfield)
                {
                    switch($matchfield)
                    {
                        case "from_ip":
                            $from_ip = $submatches[$ctr + 2];
                            if($from_ip == "") $from_ip = $submatches[$ctr + 1];
                            if($from_ip == "") $from_ip = $submatches[$ctr];
                            $ctr += 3;
                        break;

                        case "auth":
                            $auth = $submatches[$ctr++];
                        break;

                        case "from_email":
                            $from_email = $submatches[$ctr++];
                        break;

                        case "to_email":
                            $to_email = $submatches[$ctr++];
                        break;
                    }
                }

                $o['from_ip'] = $from_ip;
                $o['auth'] = $auth;
                $o['from_email'] = $from_email;
                $o['to_email'] = $to_email;

                $output[] = $o;
                return;
            }
        }
        logerr("UNMATCHED LINE: $line");
    }

    function proc_mailing(&$id, &$mailing)
    {
        global $output, $mailings, $ts_regex, $id_regex, $email_regex, $from_email_regex, $to_email_regex, $single_host, $host_regex, $host_regex_noh, $user_regex, $proto_regex, $enc_regex, $auth_regex, $size_regex;

        $from_regex = "/($ts_regex)\s*$id_regex\s*\<\=\s*$from_email_regex\s*(?:R\=[\w\d\-]+)?\s*$user_regex\s*$host_regex?\s*$proto_regex\s*$enc_regex\s*$auth_regex\s*$size_regex/";

        $matches = array();
        if(preg_match($from_regex, $mailing['from'], $matches) > 0)
        {
            $o = array();

            $o['id'] = $id;
            $o['ts'] = $matches[1];
            $o['from_email'] = $matches[2];
            $o['to_email'] = "DEFERRED";
            $o['to_host'] = "DEFERRED";

            $from_ip = $matches[6];
            if($from_ip == ""){ $from_ip = $matches[5]; }

            $o['from_ip'] = $from_ip;

            $o['auth'] = $matches[9];
            $o['size'] = $matches[10];

            $to_regex = "/$ts_regex\s*$id_regex\s*(?:\=|\-)\>\s*$to_email_regex\s*/";

            foreach($mailing['to'] as $mailto)
            {
                $matches = array();
                if(preg_match($to_regex, $mailto, $matches) > 0)
                {
                    $email = $matches[1];
                    if($email == "") $email = $matches[2];
                    $o['to_email'] = $email;

                    $output[] = $o;
                }
                else
                {
                    logerr("FAIL ON TO: " . $mailto);
                }
            }
        }
        else
        {
            logerr("FAIL ON FROM: " . $mailing['from']);
        }
    }

    // Sort output.
    function cmp($a, $b)
    {
        if($a['ts'] == $b['ts']) return 0;
        return ($a['ts'] < $b['ts']) ? -1 : 1;
    }

    usort($output, "cmp");

    // Output loop.
    foreach($output as $o)
    {
        $id = $o['id'];
        if($id == ""){ $id = "NOID"; }

        $ts = $o['ts'];

        $from_ip = $o['from_ip'];
        if($from_ip == ""){ $from_ip = "127.0.0.1"; }
        else $from_ip = str_replace("[", "", str_replace("]", "", $from_ip));

        $auth = $o['auth'];
        $auth = str_replace("mysql_login:", "", str_replace("mysql_plain:", "", $auth));
        if($auth == "") $auth = "NOAUTH";

        $size = $o['size'];
        if(($size == "") || ($size < 0)){ $size = 0; }

        $from_email = $o['from_email'];
        if(($from_email == "<>") || ($from_email == "")){ $from_email = "UNKNOWN"; }

        $to_email = $o['to_email'];
        if($to_email == ""){ $to_email = "UNKNOWN"; }
        if($to_email != "UNKNOWN")
        {
            $pieces = split("@", $to_email);
            $to_host = $pieces[1];
            if($to_host == ""){ $to_host = "UNKNOWN"; }
        }
        else
        {
            $to_host = "UNKNOWN";
        }

        if(isset($o['code']))
        {
            $code = $o['code'];
        }
        else
        {
            $code = '';
        }
        if(($code == "") || ($code < 0)){ $code = 250; }

        $proto = "SMTP";

        $log = array($ts, $from_ip, $to_host, $auth, $size, $from_email, $to_email, $id, $proto, $code);
        print implode(" ", $log) . "\n";
    }

    // Report any errors.
    if($error_email != "")
    {
        if($GLOBALS['error_log'] != "")
        {
            mail($error_email, "[Exim2AWStats] Error(s)", $GLOBALS['error_log']);
        }
    }

    if($error_file != "")
    {
        if($GLOBALS['error_log'] != "")
        {
            file_put_contents($error_file, $GLOBALS['error_log']);
        }
    }

?>
