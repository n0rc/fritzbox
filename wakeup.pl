#!/usr/bin/perl

use strict;
use warnings;
use LWP::UserAgent;
use Encode;
use Digest::MD5 qw(md5_hex);

my $ua = LWP::UserAgent->new;

### start of config section

# if you don't want to store your credentials within this script just keep the
# following three dummy values and set $ask_auth = 1

# the following credentials are needed for remote login, e.g. from WAN/Internet
my $remote_user = "myusername";
my $remote_pass = "myPassword!";

# enable interactive authentication to avoid storing credentials in this script
my $ask_auth = 0;

# fritzbox host to connect to
my $host = "my.hostname.net";

# fritzbox port, usually 443
my $port = 443;

# MAC of the computer to send the wakeup packet to,
# use mac format 01:23:45:67:89:AB
my $mac = "00:CO:1D:CO:FF:EE";

# uncomment the following line if you get ssl certificate warnings
#$ua->ssl_opts(verify_hostname => 0);

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
	ReadMode('restore');
	print "\n\n";
}

readcreds if ($ask_auth);

$ua->timeout(30);
push @{$ua->requests_redirectable}, 'POST';
$ua->credentials($host.":".$port, "HTTPS Access", $remote_user, $remote_pass);

my $url_base = "https://".$host;
my $url_login = $url_base."/login.lua";
my $url_wakeup = $url_base."/cgi-bin/webcm";

my $r = $ua->get($url_login);
if ($r->is_success) {
	my $c = $r->decoded_content;
	if ($c =~ m#(?:g_challenge|var challenge|\["security:status/challenge"\]) = "([a-f0-9]+)"#) {
		my $challenge = $1;
		my %data = (
			username => $remote_user,
			response => sprintf "%s-%s", $challenge, md5_hex(encode("UTF16-LE", sprintf "%s-%s", $challenge, $remote_pass))			
		);
		$r = $ua->post($url_login, \%data);
		$c = $r->decoded_content;
		if ($c =~ m#(?:home|logout)\.lua\?sid=([a-f0-9]+)#) {
			my $sid = $1;
			%data = (sid => $sid, "wakeup:settings/mac" => $mac);
			$r = $ua->post($url_wakeup, \%data);
			if ($r->is_success) {
				print "[success] wakeup done\n";
			} else {
				err_exit $r->status_line;
			}
		} else {
			err_exit "could not find a session id";
		}
	} else {
		err_exit "could not find a challenge";
	}
} else {
	err_exit "could not login: " . $r->status_line;
}

exit 0;
