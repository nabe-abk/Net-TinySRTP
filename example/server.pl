#!/usr/bin/perl
################################################################################
# DTLS server example for Net::TinySRTP
################################################################################
use 5.8.1;
use strict;
use Socket;
use Net::TinySRTP;

my $PORT = int($ARGV[1]) || 3001;

socket(my $sock, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
bind($sock, pack_sockaddr_in($PORT, INADDR_ANY)) || die "bind failed: $!";

my $privkey = generate_ec_pkey();
my $x509    = make_cert($privkey, $privkey, 30, { CN => 'example.com' });

print "Local certificate fingerprint: ", &dumphex( $x509->fingerprint() ), "\n";

print get_ssl_error(),"\n";
print get_ssl_error(),"\n";
print get_ssl_error(),"\n";

while(1) {
	my $ssl  = ssl_dtls_new(fileno($sock), $privkey, $x509);
	my $addr = $ssl->DTLSv1_listen();

	if ($addr) {
		my $peercert = $ssl->get_peer_certificate();
		my @key      = $ssl->get_srtp_key_info();
		print "Peer's fingerprint: ", &dumphex( $peercert->fingerprint() ), "\n";
		print "srtp_profile: ", $ssl->get_selected_srtp_profile(), "\n";
		print "Server-key : ", &dumphex( $key[1] ), "\n";
		print "Client-key : ", &dumphex( $key[0] ), "\n";
		print "Server-salt: ", &dumphex( $key[3] ), "\n";
		print "Client-salt: ", &dumphex( $key[2] ), "\n";
		print "\n";
	}
}

sub dumphex {
	return unpack('H*', shift) =~ s/(\w\w)(?=\w)/$1:/rg;
}
