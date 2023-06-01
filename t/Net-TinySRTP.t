# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Net-TinySRTP.t'

#########################

use strict;
use warnings;
use Socket;

use Test::More tests => 3;
BEGIN { use_ok('Net::TinySRTP;') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

{
	my $key = pack('H*', "00112233445566778899AABBCCDDEEFF");	# 16byte
	my $iv  = pack('H*', "010203040506070809101112");		# 12byte

	my $adata = &generate_rand_string(40);
	my $plain = &generate_rand_string(100);

	my ($cipher, $tag) = &aes_gcm_encrypt($key, $iv, $adata, $plain);
	my $dec            = &aes_gcm_decrypt($key, $iv, $adata, $cipher, $tag);

	ok($plain eq $dec, "aes_gcm_encrypt and aes_gcm_decrypt : cipher");
}
{
	my $key = pack('H*', "00112233445566778899AABBCCDDEEFF") x 2;	# 32byte
	my $iv  = pack('H*', "010203040506070809101112");		# 12byte

	my $adata = &generate_rand_string(32);
	my $plain = &generate_rand_string(64);

	my ($cipher, $tag) = &aes_gcm_encrypt($key, $iv, $adata, $plain);
	my $dec            = &aes_gcm_decrypt($key, $iv, $adata, $cipher, $tag);

	ok($plain eq $dec, "aes_gcm_encrypt and aes_gcm_decrypt : cipher");
}

#########################

sub generate_rand_string {
	my $len = shift;
	my $s='';
	foreach(1..$len) {
		$s .= chr( int(rand(256)) );
	}
	return $s;
}
