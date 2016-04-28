#!/usr/bin/perl

use strict;
use warnings;
use LWP::UserAgent;
use Encode;
use Digest::MD5 qw(md5_hex);
use JSON;

my $ua = LWP::UserAgent->new;

### start of config section

# if you don't want to store your credentials within this script just
# keep the next three dummy values and set $ask_auth = 1

# the following credentials are needed for remote login, e.g. from WAN/Internet
my $remote_user = "myUsername";
my $remote_pass = "myPassword";

# local admin password required for some fritzboxes 
my $local_admin_pass = "myAdminPassword";

# enable interactive authentication to avoid storing credentials in this script
my $ask_auth = 0;

# fritzbox host to connect to
my $host = "my.hostname.net";

# fritzbox port, usually 443
my $port = 443;

# MAC of the computer to send the wakeup packet to,
# use mac format 01:23:45:67:89:AB
my $mac = "00:CO:1D:CO:FF:EE";

# uncomment the following line to disable ssl certificate verification
#$ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0);

### end of config section
### do not change anything below!

sub err_exit($) {
    my $msg = shift;
    print "[error] $msg\n";
    exit 1;
}

sub readcreds() {
    use Term::ReadKey;
    print "remote login username: "; chomp($remote_user = ReadLine(0));
    ReadMode('noecho');
    print "remote login password: "; chomp($remote_pass = ReadLine(0));
    print "\nlocal admin password: "; chomp($local_admin_pass = ReadLine(0));
    ReadMode('restore');
    print "\n\n";
}

readcreds if ($ask_auth);

$ua->timeout(30);
push @{$ua->requests_redirectable}, 'POST';
$ua->credentials("$host:$port", "HTTPS Access", $remote_user, $remote_pass);

my $url_base = "https://$host:$port";
my $url_login_suffix = "/login.lua";
my $url_login = $url_base.$url_login_suffix;
my $url_netdevs = "$url_base/net/network_user_devices.lua?sid=";
my $url_editdev_suffix = "net/edit_device.lua";
my $url_wakeup = "$url_base/$url_editdev_suffix?sid=";
my $url_wakeup_old = "$url_base/cgi-bin/webcm";
my $url_data = "$url_base/data.lua";

my $r = $ua->get($url_login);
if ($r->is_success) {
    my $c = $r->decoded_content;
    if ($c =~ m#(?:g_challenge|"challenge"|var challenge|\["security:status/challenge"\])(?: =|:) "([a-f0-9]+)"#) {
        my $challenge = $1;
        my $pass = ($c =~ m#Benutzername#) ? $remote_pass : $local_admin_pass;
        my %data = (
            username => $remote_user,
            response => sprintf "%s-%s", $challenge, md5_hex(encode("UTF16-LE", sprintf "%s-%s", $challenge, $pass))
        );
        my $vers = 0;
        my $target = ($c =~ m#action="$url_login_suffix"#) ? $url_login : $url_base;
        $r = $ua->post($target, \%data);
        $c = $r->decoded_content;
        if ($c =~ m#(?:FRITZ!OS |version%3D\d\d\.)(\d+)\.(\d+)#) {
            $vers = sprintf "%d", $1.$2;
        }
        err_exit "login failed" if ($c =~ m#(?:error_text|ErrorMsg)#i);
        if ($c =~ m#(?:(?:home|logout)\.lua\?sid=|"sid": ")([a-f0-9]+)#) {
            my $sid = $1;
            if ($vers < 630) {
                %data = (sid => $sid, "wakeup:settings/mac" => $mac);
                $r = $ua->post($url_wakeup_old, \%data);
                if ($r->is_success) {
                    print "[success] wakeup done\n";
                } else {
                    err_exit "invalid post data" . $r->status_line;
                }
            } elsif ($vers < 650) {
                $r = $ua->get($url_netdevs.$sid);
                $c = $r->decoded_content;
                if ($c =~ m#$mac.*? value="([^"]+)"#i) {
                    my $uid = $1;
                    %data = (dev => $uid, btn_wake => "");
                    $r = $ua->post($url_wakeup.$sid, \%data);
                    if ($r->is_success) {
                        print "[success] wakeup done\n";
                    } else {
                        err_exit "invalid post data: " . $r->status_line;
                    }
                } else {
                    err_exit "could not find mac";
                }
            } else {
                %data = (
                    sid => $sid,
                    page => "netDev"
                );
                $r = $ua->post($url_data, \%data);
                $c = $r->decoded_content;
                my $json = from_json($c);
                my $uid = "";
                my @devs = @{$json->{'data'}->{'passive'}};
                push @devs, @{$json->{'data'}->{'active'}};
                foreach my $dev (@devs) {
                    if ($dev->{'mac'} eq $mac) {
                        $uid = $dev->{'UID'};
                        last;
                    }
                }
                if ($uid ne "") {
                    %data = (
                        sid => $sid,
                        dev => $uid,
                        oldpage => $url_editdev_suffix,
                        btn_wake => ""
                    );
                    $r = $ua->post($url_data, \%data);
                    $c = $r->decoded_content;
                    if ($c =~ m#"pid": "netDev"#) {
                        print "[success] wakeup done\n";
                    } else {
                        err_exit "invalid post data: " . $r->status_line;
                    }
                } else {
                    err_exit "could not find mac"
                }
            }
        } else {
            err_exit "could not find a session id";
        }
    } else {
        err_exit "could not find a challenge";
    }
} else {
    err_exit "could not load login page: " . $r->status_line;
}

exit 0;
