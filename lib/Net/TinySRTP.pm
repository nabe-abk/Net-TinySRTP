package Net::TinySRTP;

use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(
	generate_ec_pkey
	make_cert
	ssl_dtls_new

	supported_SRTP_PROFILES
	get_ssl_error

	aes_cm_kdf
	aes_gcm_encrypt
	aes_gcm_decrypt
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT    = ( @{ $EXPORT_TAGS{'all'} } );

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Net::TinySRTP', $VERSION);

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::TinySRTP - Perl extension for DTLS/SRTP

=head1 SYNOPSIS

    use Socket;
    use Net::TinySRTP;
    socket(my $sock, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
    bind($sock, sockaddr_in($PORT, INADDR_ANY));

    my $privkey = generate_ec_pkey();
    my $x509    = make_cert($privkey, $privkey, 30, { CN => 'example.com' });
    my $ssl     = ssl_dtls_new(fileno($sock), $privkey, $x509);

    # server
    my $addr = $ssl->DTLSv1_listen();
    $ssl->sock_connect($addr);

    # client
    my $ret  = $ssl->connect($addr);
    $ssl->sock_connect($addr);

=head1 DESCRIPTION

Net::TinySRTP a library using OpenSSL to implement DTLS/SRTP.
This library uses an existing preconfigured socket for DTLS negotiation.
And provides the necessary encryption and decryption functions for SRTP (SRTP_AEAD_AES_128_GCM).

=head1 USAGE

=head2 SSL functions

=head3 my $privkey = generate_ec_pkey();

Generate a private key of prime256v1 format.

Return value is Net::TinySRTP::EVP_PKEYPtr object on success.
On failed the return value is undef.

=head3 my $x509 = make_cert($pubkey, $privkey, $days, \%subject);

Create $pubkey certificate data signed by $privkey using SHA256, and can self-signing by making $pubkey and $privkey the same.
Set the number of days the signature is valid for $days.
Set the subject data of the signature in %subject.

    my $privkey = generate_ec_pkey();
    my $x509    = make_cert($privkey, $privkey, 30, { C=>'JP', CN => 'example.com' });

Return value is Net::TinySRTP::X509Ptr object on success.
On failed the return value is undef.

=head3 my $ssl = ssl_dtls_new(fileno($sock), $privkey, $x509);

Create SSL object and initialize it for DTLS negotiation.

Return value is Net::TinySRTP::SSLPtr object on success.
On failed the return value is undef.

=head3 my $str = supported_SRTP_PROFILES();

Returns the supported strp_profile names separated by colon.
Current version returns "SRTP_AEAD_AES_128_GCM".

=head3 my $str = get_ssl_error();

Returns the earliest error message from error queue and removes the entry.
This function use ERR_get_error() of OpenSSL.



=head2 Net::TinySRTP::SSLPtr methods

=head3 my $ret = $ssl->connect($addr, $timeout_sec);

$addr is DTLS server address(refer to L<sock_connect()|/ssl-sock_connect-addr>).
If $timeout is omitted, not timeout.

Return value is 1, if success.
On failed (include timeout) the return value is undef.


=head3 my $addr = $ssl->DTLSv1_listen($timeout_sec);

Start DTLS server listen.
If $timeout is omitted, not timeout.

Return value is $addr struct(refer to L<sock_connect()|/ssl-sock_connect-addr>).
On failed (including timeout) the return value is undef.


=head3 my $ret = $ssl->connect_with_sock_connect($addr, $timeout_sec);

=head3 my $ret = $ssl->DTLSv1_listen_with_sock_connect($addr, $timeout_sec);

These functions work same to $ssl->connect()/$ssl->DTLSv1_listen(),
and internal call L<sock_connect()|/ssl-sock_connect-addr>.

Therefore, if the connection fails,
B<you cannot connect again to a different address (port) using the same socket.>

Return value is 1, if success.
On failed (including timeout) the return value is undef.


=head3 my $bin = $ssl->get_peer_certificate();

Return value is peer's certificate Net::TinySRTP::X509Ptr object.
On failed the return value is undef.


=head3 my $str = $ssl->get_selected_srtp_profile();

Return value is srtp_profile name.
On failed the return value is undef.


=head3 my @key = $ssl->get_srtp_key_info();

Return value is srtp key array.
On failed the return value is undef.

    my @key = $ssl->get_srtp_key_info();
    print "client-key : ", unpack('H*', $key[0]), "\n";
    print "server-key : ", unpack('H*', $key[1]), "\n";
    print "client-salt: ", unpack('H*', $key[2]), "\n";
    print "server-salt: ", unpack('H*', $key[3]), "\n";


=head3 my $ret = $ssl->set_sock(fileno($sock));

Set SSL object's bio socket.

Return value is 1, if success.
On failed (include timeout) the return value is undef.

Internal C code:

    BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

=head3 my $ret = $ssl->sock_connect($addr);

SSL object and setted socket connect to $addr.
$addr can be generated by perl's pack_sockaddr_in().

    my $HOST = '127.0.0.1';
    my $PORT = 3001;
    my $addr = pack_sockaddr_in($PORT, inet_aton($HOST));

Return value is 1, if success.
On failed (include timeout) the return value is undef.

Internal C code:

    BIO *bio = SSL_get_wbio(ssl);
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (struct sockaddr *)addr);
    int sock = 0;
    BIO_get_fd(bio, &sock);
    connect(sock, (struct sockaddr *)addr, len);


=head2 Net::TinySRTP::X509Ptr methods

=head3 $x509->fingerprint();

Get certificate's fingerprint binary data, using SHA256.


=head2 Cipher functions

=head3 my $bin = aes_cm_kdf($mkey, $msalt, $label, $length, $index);

Calculate session key/salt from master key and master salt.
The Key Derivation Function (KDF) to use is specified in RFC 3711.

$label is 1 byte integer.
This value is specified in Sections 4.3.1 and 4.3.2 of RFC 3711.

$length specifies the length of the return value,
and if it is shorter than the generated string (usually 16 bytes),
it will be truncated.
If omitted, it is 0, and truncation is not performed.

$index is a value to update the key when using the key for a long time (up to lifetime).
If omitted, it is 0.
The only supported "AES-GCM" in this library has a long enough lifetime, so you don't usually need to specify it.

Return value is string, if success.
On failed the return value is undef.

    my @key = $ssl->get_srtp_key_info();
    my $client_srtp_key	 = aes_cm_kdf($key[0], $key[2], 0);
    my $client_srtp_key	 = aes_cm_kdf($key[0], $key[2], 3, 12);
    my $server_srtp_salt = aes_cm_kdf($key[1], $key[3], 0);
    my $server_srtp_salt = aes_cm_kdf($key[1], $key[3], 3, 12);

This function has the same behavior as Perl code in aes_cm_kdf() of 
L<tiny-rtsp-server|https://github.com/nabe-abk/tiny-rtsp-server/blob/main/tiny-rtsp-server.pl>.


=head3 my ($cipher, $tag) = aes_gcm_encrypt($key, $iv, $adata, $plain);

=head3 my $data = aes_gcm_encrypt($key, $iv, $adata, $plain);

Authenticate to $adata and encrypt $plain using the given $key and $salt.

$data is concatenation of $cipher and $tag.
$cipher is the encrypted $plain data.
$tag is authenticate data.

On failed the return value is undef.

This function has the same behavior as Perl code in send_srtp_packet() of 
L<tiny-rtsp-server|https://github.com/nabe-abk/tiny-rtsp-server/blob/main/tiny-rtsp-server.pl>.


=head3 $plain = aes_gcm_decrypt($key, $iv, $adata, $cipher, $tag);

Authenticate input data with $tag and decrypt with $cipher.

On failed (including authentication failure by $tag) the return value is undef.



=head1 Examples

L<tiny-rtsp-server|https://github.com/nabe-abk/tiny-rtsp-server> and L<example/|https://github.com/nabe-abk/Net-TinySRTP/example/> directory.



=head1 Thanks

=over 4

=item *

L<DTLS Examples for OpenSSL|https://github.com/nplab/DTLS-Examples>

=item *

L<libdtlssrtp - A small library implementing DTLS-SRTP|https://github.com/persmule/libdtlssrtp>

=item *

L<OpenSSL Manpages|https://www.openssl.org/docs/manmaster/man3/>

=back



=head1 COPYRIGHT AND LICENSE

Copyright (C) 2023 by nabe@abk

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut