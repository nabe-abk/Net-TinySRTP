#!/usr/bin/perl
################################################################################
# DTLS client example for Net::TinySRTP
################################################################################
use 5.8.1;
use strict;
use Socket;
use Net::TinySRTP;

my $HOST;
my $PORT;
if ($ARGV[0] =~ /^([\w\.]+):(\d+)$/) {
	$HOST = $1;
	$PORT = $2;
	print "match\n";
} else {
	$HOST = $ARGV[0] || '127.0.0.1';
	$PORT = int($ARGV[1]) || 3001;
}

print "Connect to: $HOST:$PORT\n";
my $ip   = inet_aton($HOST) || die "host not found: $HOST";
my $addr = pack_sockaddr_in($PORT, $ip);

socket(my $sock, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
bind($sock, pack_sockaddr_in(0, INADDR_ANY)) || die "bind failed: $!";

my $privkey = generate_ec_pkey();
my $x509    = make_cert($privkey, $privkey, 30, { CN => 'example.com' });

print "Local certificate fingerprint: ", &dumphex( $x509->fingerprint() ), "\n";

my $ssl = ssl_dtls_new(fileno($sock), $privkey, $x509);
my $r   = $ssl->connect($addr);
if (!$r) {
	die "Connection failed!"
}

my $peercert = $ssl->get_peer_certificate();
my @key      = $ssl->get_srtp_key_info();
print "Peer's fingerprint: ", &dumphex( $peercert->fingerprint() ), "\n";
print "srtp_profile: ", $ssl->get_selected_srtp_profile(), "\n";
print "Server-key : ", &dumphex( $key[1] ), "\n";
print "Client-key : ", &dumphex( $key[0] ), "\n";
print "Server-salt: ", &dumphex( $key[3] ), "\n";
print "Client-salt: ", &dumphex( $key[2] ), "\n";

sub dumphex {
	return unpack('H*', shift) =~ s/(\w\w)(?=\w)/$1:/rg;
}
