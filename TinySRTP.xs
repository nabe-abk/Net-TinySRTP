#define PERL_NO_GET_CONTEXT

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>

#include "TinySRTP.h"
/////////////////////////////////////////////////////////////////////////////////
// [C] functions
/////////////////////////////////////////////////////////////////////////////////
BIO *ssl_set_timeout_sec(SSL *ssl, int timeout_sec, struct timeval *old) {
	if (timeout_sec<1) return NULL;

	BIO *bio = SSL_get_rbio(ssl);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMEOUT, 0, old);

	struct timeval tmout;
	tmout.tv_sec  = timeout_sec;
	tmout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tmout);
	return bio;
}

int ssl_udp_connect(SSL *ssl, const void *addr, int len) {
	BIO *bio = SSL_get_wbio(ssl);

	if (len<sizeof(struct sockaddr_in)) return 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (struct sockaddr *)addr);

	int fd = 0;
	BIO_get_fd(bio, &fd);
	if (!fd) return 0;

	if (connect(fd, (struct sockaddr *)addr, len)) return 0;	// 0 is success
	return 1;
}

/////////////////////////////////////////////////////////////////////////////////
// [C] DTLS cookie functions
/////////////////////////////////////////////////////////////////////////////////
// typedef union {
//	sa_family_t     sin_family;
//	struct sockaddr		sa;
//	struct sockaddr_in	s4;
//	struct sockaddr_in6	s6;
// } u_sockaddr;

int bio2sockaddr(BIO_ADDR *bio_addr, u_sockaddr *u) {
	memset(u, 0, sizeof(u_sockaddr));

	u->sin_family = BIO_ADDR_family(bio_addr);

	if (u->sin_family == AF_INET) {
		u->s4.sin_port = BIO_ADDR_rawport(bio_addr);
		BIO_ADDR_rawaddress(bio_addr, &u->s4.sin_addr,  NULL);
		return 1;	// Sucess
	}
	if (u->sin_family == AF_INET6) {
		u->s6.sin6_port = BIO_ADDR_rawport(bio_addr);
		BIO_ADDR_rawaddress(bio_addr, &u->s6.sin6_addr, NULL);
		return 1;	// Sucess
	}
	return 0;	// fail
}

int dtls_verify_callback(int ok, X509_STORE_CTX *ctx) {
	return 1;
}

int make_ssl_cookie(SSL *ssl, char *buf, unsigned int *clen) {
	static char secret[SSL_COOKIE_SECRET_BYTES];
	static int  init = 0;
	if (!init) {
		RAND_bytes(secret, SSL_COOKIE_SECRET_BYTES);
		init = 1;
	}

	BIO_ADDR *bio_addr = BIO_ADDR_new();
	BIO_dgram_get_peer(SSL_get_rbio(ssl), bio_addr);
	u_sockaddr addr;
	int r = bio2sockaddr(bio_addr, &addr);
	BIO_ADDR_free(bio_addr);

	if (!r) return 0;

	HMAC(SSL_COOKIE_METHOD, secret, SSL_COOKIE_SECRET_BYTES, (char *)&addr, sizeof(addr), buf, clen);
	return 1;
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *clen) {
	return make_ssl_cookie(ssl, cookie, clen);
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int clen) {
	unsigned int len;
	char buf[SSL_COOKIE_BYTES];
	if (! make_ssl_cookie(ssl, buf, &len)) return 0;

	if (len != clen) return 0;
	return memcmp(cookie, buf, len) ? 0 : 1;
}

/////////////////////////////////////////////////////////////////////////////////
// DEBUG
/////////////////////////////////////////////////////////////////////////////////
#ifdef DEBUG
void print_hex(const char *head, unsigned char *buf, unsigned int size) {
	if (head) printf(head);
	for(unsigned int i=0; i<size; i++) {
		printf("%02x:", buf[i]);
	}
	printf("\n");
}
#endif

/////////////////////////////////////////////////////////////////////////////////
// XS functions
/////////////////////////////////////////////////////////////////////////////////

MODULE = Net::TinySRTP		PACKAGE = Net::TinySRTP

TYPEMAP: <<TMAP
SSL*		T_PTROBJ_SP
EVP_PKEY*	T_PTROBJ_SP
X509*		T_PTROBJ_SP

INPUT
T_PTROBJ_SP
	if (sv_derived_from($arg, \"Net::TinySRTP::${\(substr($ntype,0,length($ntype)-3))}\")){
		IV tmp = SvIV((SV*)SvRV($arg));
		$var = INT2PTR($type, tmp);
	}
	else
		croak(\"$var is not of type Net::TinySRTP::${\(substr($ntype,0,length($ntype)-3))}\");
OUTPUT
T_PTROBJ_SP
	sv_setref_pv($arg, \"Net::TinySRTP::${\(substr($ntype,0,length($ntype)-3))}\", (void*)$var);
TMAP

################################################################################
# BOOT
################################################################################
BOOT:
	SSL_load_error_strings();

################################################################################
# Global
################################################################################
const char *supported_SRTP_PROFILES()
	CODE:
	RETVAL = SRTP_PROFILE_NAME;
	OUTPUT:
	RETVAL

const char *get_ssl_error()
	CODE:
	int err = ERR_get_error();
	if (!err) XSRETURN_UNDEF;

	char buf[256];
	ERR_error_string_n(err, buf, 256);
	RETVAL = buf;
	OUTPUT:
	RETVAL

################################################################################
# generate private key
################################################################################
EVP_PKEY *generate_ec_pkey()
	CODE:
	EVP_PKEY *pkey     = EVP_PKEY_new();
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (pkey == NULL || pctx == NULL) {
		if (pkey) EVP_PKEY_free(pkey);
		XSRETURN_UNDEF;
	}

	int err=1;
	do {
		if (!EVP_PKEY_keygen_init(pctx)) break;
		if (!EVP_PKEY_CTX_set_group_name(pctx, "prime256v1")) break;
		if (!EVP_PKEY_keygen(pctx, &pkey)) break;
		err=0;
	} while(false);

	EVP_PKEY_CTX_free(pctx);
	if (err) {
		XSRETURN_UNDEF;
	}

	RETVAL = pkey;
	OUTPUT:
	RETVAL

################################################################################
# generate certification
################################################################################
X509 *make_cert(EVP_PKEY *pubkey, EVP_PKEY *privkey, int days, HV *subj = NULL)
	CODE:
	X509_REQ  *req  = NULL;
	X509_NAME *name = NULL;
	X509      *x509 = NULL;

	if (!pubkey)  XSRETURN_UNDEF;
	if (!privkey) XSRETURN_UNDEF;
	if (days<0)   XSRETURN_UNDEF;

	int err=1;
	do {
		req = X509_REQ_new();
		if (! req) break;

		if (! X509_REQ_set_version(req, X509_VERSION_1)	) break;
		if (! X509_REQ_set_pubkey(req, pubkey)		) break;

		if (subj) {
			name = X509_NAME_new();
			if (!name) break;

			int  h_len;
			char *key;
			SV   *sval;

			hv_iterinit(subj);
			while (sval = hv_iternextsv(subj, &key, &h_len)) {
				char *val = SvOK(sval) ? SvPV_nolen(sval) : "";

				X509_NAME_add_entry_by_txt(name, key,  MBSTRING_ASC, (const unsigned char *)val, -1, -1, 0);
			}
			if (! X509_REQ_set_subject_name(req, name) ) break;
		}

		// sign to X509_REQ
		if (! X509_REQ_sign(req, privkey, DIGEST_METHOD) ) break;

		// X509_REQ to X509
		x509 = X509_new();
		if (! x509) break;

		EVP_PKEY *pubkey = X509_REQ_get0_pubkey(req);
		if (! pubkey) break;

		if (! X509_set_pubkey(x509, pubkey) ) break;

		if (! X509_gmtime_adj(X509_getm_notBefore(x509), 0)            ) break;
		if (! X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, NULL)) break;

		if (! X509_set_subject_name(x509, X509_REQ_get_subject_name(req)) ) break;
		if (! X509_set_issuer_name (x509, X509_REQ_get_subject_name(req)) ) break;

		// sign to X509
		if (! X509_sign(x509, privkey, DIGEST_METHOD) ) break;

		err = 0;
	} while(false);

	if (req)  X509_REQ_free(req);
	if (name) X509_NAME_free(name);

	if (err) {
		if (x509) X509_free(x509);
		XSRETURN_UNDEF;
	}

	// success
	RETVAL = x509;
	OUTPUT:
	RETVAL

################################################################################
# new SSL with DTLS
################################################################################
SSL *ssl_dtls_new(int sock_fd, EVP_PKEY *privkey, X509 *x509)
	CODE:
	SSL     *ssl = NULL;
	SSL_CTX *ctx = NULL;

	if (!privkey)    XSRETURN_UNDEF;
	if (!x509)       XSRETURN_UNDEF;

	int err=1;
	do {
		// DTLS_method()     : UDP packet header has DTLS v1.0 (0xfeff)
		// DTLSv1_2_method() : UDP packet header has DTLS v1.2 (0xfefd)
		ctx = SSL_CTX_new(DTLS_method());
		if (! ctx) break;

		if (! SSL_CTX_use_PrivateKey (ctx, privkey) ) break;
		if (! SSL_CTX_use_certificate(ctx, x509   ) ) break;

		if ( SSL_CTX_set_tlsext_use_srtp(ctx, SRTP_PROFILE_NAME) ) break;	// 0 is success

		ssl = SSL_new(ctx);
		if (! ssl) break;
		if (! SSL_set_min_proto_version(ssl, DTLS1_2_VERSION) ) break;

		BIO *bio = BIO_new_dgram(sock_fd, BIO_NOCLOSE);
		if (! bio) break;
		SSL_set_bio(ssl, bio, bio);	// SSL_set_bio() is transfers ownership of bio to ssl.

		err = 0;
	} while(false);

	if (ctx) SSL_CTX_free(ctx);

	if (err) {
		if (ssl) SSL_free(ssl);
		XSRETURN_UNDEF;
	}

	// success
	RETVAL = ssl;
	OUTPUT:
	RETVAL

################################################################################
# SSL object
################################################################################
MODULE = Net::TinySRTP	PACKAGE = Net::TinySRTP::SSL

void DESTROY(SSL *ssl)
	CODE:
        DEBUG_PRINT("*** SSL::DESTROY\n")
	if (ssl) SSL_free( ssl );

#-------------------------------------------------------------------------------
# SSL connect
#-------------------------------------------------------------------------------
int connect_with_sock_connect(SSL *ssl, SV *addr, int timeout_sec =0)
	CODE:
	if (!ssl || !SvOK(addr)) XSRETURN_UNDEF;

	STRLEN len;
	const void *p = SvPVbyte(addr, len);
	if (! ssl_udp_connect(ssl, p, len)) XSRETURN_UNDEF;

	struct timeval old;
	BIO *bio = ssl_set_timeout_sec(ssl, timeout_sec, &old);

	RETVAL = SSL_connect(ssl);

	if (bio) BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &old);

	OUTPUT:
	RETVAL

#-------------------------------------------------------------------------------
# SSL DTLS listen
#-------------------------------------------------------------------------------
int DTLSv1_listen_with_sock_connect(SSL *ssl, SV *_addr, int timeout_sec =0)
	CODE:
	if (!ssl || !SvOK(_addr)) XSRETURN_UNDEF;

	// prepare
	SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb  (ctx, verify_cookie);
	SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);	// Require for get peer's cert

	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	// set address
	STRLEN addr_len;
	const void *addr = SvPVbyte(_addr, addr_len);

	// set timeout
	struct timeval old;
	BIO *bio = ssl_set_timeout_sec(ssl, timeout_sec, &old);

	// Listen
	int ok=0;
	BIO_ADDR *bio_addr = BIO_ADDR_new();
	do {
		if (DTLSv1_listen(ssl, bio_addr) != 1) break;

		u_sockaddr con_addr;
		if (! bio2sockaddr(bio_addr, &con_addr)) break;
		if (memcmp(&con_addr, addr, addr_len)) {
			DEBUG_PRINT("Connection address mismatch!\n");
			continue;
		}

		if (! ssl_udp_connect(ssl, addr, addr_len)) break;

		if (SSL_accept(ssl) != 1) break;
		ok=1;
	} while(false);
	BIO_ADDR_free(bio_addr);

	if (bio) BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &old);

	if (!ok) XSRETURN_UNDEF;
	RETVAL=1;

	OUTPUT:
	RETVAL

#-------------------------------------------------------------------------------
# SSL connect, no socket connect
#-------------------------------------------------------------------------------
int connect(SSL *ssl, SV *_addr, int timeout_sec =0)
	CODE:
	if (!ssl || !SvOK(_addr)) XSRETURN_UNDEF;

	STRLEN addr_len;
	const void *addr = SvPVbyte(_addr, addr_len);

	// get socket
	int sock = 0;
	BIO_get_fd(SSL_get_wbio(ssl), &sock);
	if (!sock) XSRETURN_UNDEF;

	BIO *sockbio = BIO_new_dgram(sock, BIO_NOCLOSE);
	if (!sockbio) XSRETURN_UNDEF;

	// generate memory BIO
	BIO *rbio = BIO_new(BIO_s_mem());
	BIO *wbio = BIO_new(BIO_s_mem());
	if (!rbio || !wbio) {
		if (rbio) BIO_free(rbio);
		XSRETURN_UNDEF;
	}
	BIO_set_mem_eof_return(wbio, -1);

	// set memory BIO
	SSL_set_bio(ssl, rbio, wbio);	// SSL_set_bio() is transfers ownership of bio to ssl.
	SSL_set_connect_state(ssl);
	SSL_do_handshake(ssl);

	struct timeval tmout;
	tmout.tv_sec  = timeout_sec;
	tmout.tv_usec = 0;

	char buf[HANDSHAKE_BUF_SIZE];
	int  err=0;
	while(! SSL_is_init_finished(ssl)) {
		int pen_size = BIO_ctrl_pending(wbio);
		if (0<pen_size) {
			if (HANDSHAKE_BUF_SIZE < pen_size) { err=1; break; }

			int sends = BIO_read(wbio, buf, pen_size);
			if (0<sends)
				sendto(sock, buf, sends, 0, (struct sockaddr *)addr, addr_len);
		}

		fd_set rfd;
		FD_ZERO(&rfd);
		FD_SET(sock, &rfd);

		int r = select(sock + 1, &rfd, NULL, NULL, timeout_sec ? &tmout : NULL);
		if (r<=0) { err=1; break; }	// error or timeout

		struct sockaddr_in peer;
		int peerlen = sizeof(peer);
		int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
		if (len<0) { err=1; break; }

		// sender check
		if (peerlen != addr_len || memcmp(&peer, addr, peerlen)) continue;	// other packet

		if (is_dtls(buf)) {
			BIO_write(rbio, buf, len);
			SSL_read(ssl, buf, 0);
		}
	}

	// Recovery socket BIO
	SSL_set_bio(ssl, sockbio, sockbio);

	if (err) XSRETURN_UNDEF;
	RETVAL=1;

	OUTPUT:
	RETVAL

#-------------------------------------------------------------------------------
# SSL DTLS listen, no socket connect
#-------------------------------------------------------------------------------
void DTLSv1_listen(SSL *ssl, int timeout_sec =0)
	PPCODE:
	if (!ssl) XSRETURN_UNDEF;

	// prepare
	SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);	// Require for get peer's cert

	// get socket
	int sock = 0;
	BIO_get_fd(SSL_get_wbio(ssl), &sock);
	if (!sock) XSRETURN_UNDEF;

	BIO *sockbio = BIO_new_dgram(sock, BIO_NOCLOSE);
	if (!sockbio) XSRETURN_UNDEF;

	// generate memory BIO
	BIO *rbio = BIO_new(BIO_s_mem());
	BIO *wbio = BIO_new(BIO_s_mem());
	if (!rbio || !wbio) {
		if (rbio) BIO_free(rbio);
		XSRETURN_UNDEF;
	}
	BIO_set_mem_eof_return(wbio, -1);

	// set memory BIO
	SSL_set_bio(ssl, rbio, wbio);	// SSL_set_bio() is transfers ownership of bio to ssl.
	SSL_set_accept_state(ssl);
	SSL_do_handshake(ssl);

	struct timeval tmout;
	tmout.tv_sec  = timeout_sec;
	tmout.tv_usec = 0;

	// Listen
	struct sockaddr_in peer;
	int peerlen = sizeof(peer);

	char buf[HANDSHAKE_BUF_SIZE];
	int  err=0;

	while(!SSL_is_init_finished(ssl)) {
		fd_set rfd;
		FD_ZERO(&rfd);
		FD_SET(sock, &rfd);

		int r = select(sock + 1, &rfd, NULL, NULL, timeout_sec ? &tmout : NULL);
		if (r<=0) { err=1; break; }	// error or timeout

		int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peerlen);
		if (len<0) { err=1; break; }

		if (! is_dtls(buf)) continue;

		// is DTLS
		BIO_write(rbio, buf, len);
		SSL_read(ssl, buf, 0);

		int pen_size = BIO_ctrl_pending(wbio);
		if (0<pen_size) {
			if (HANDSHAKE_BUF_SIZE < pen_size) { err=1; break; }

			int sends = BIO_read(wbio, buf, pen_size);
			if (0<sends)
				sendto(sock, buf, sends, 0, (struct sockaddr *)&peer, sizeof(peer));
		}
	}

	// Recovery socket BIO
	SSL_set_bio(ssl, sockbio, sockbio);

	if (err) XSRETURN_UNDEF;

	mXPUSHs(newSVpv((char *)&peer, peerlen));
	XSRETURN(1);

#-------------------------------------------------------------------------------
# set socket
#-------------------------------------------------------------------------------
int set_sock(SSL *ssl, int sock)
	CODE:

	BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
	if (!bio) XSRETURN_UNDEF;

	SSL_set_bio(ssl, bio, bio);	// replace socket BIO

	RETVAL=1;

	OUTPUT:
	RETVAL

#-------------------------------------------------------------------------------
# sock connect
#-------------------------------------------------------------------------------
int sock_connect(SSL *ssl, SV *addr)
	CODE:
	if (!ssl || !SvOK(addr)) XSRETURN_UNDEF;

	STRLEN len;
	const void *p = SvPVbyte(addr, len);
	if (! ssl_udp_connect(ssl, p, len)) XSRETURN_UNDEF;
	RETVAL = 1;

	OUTPUT:
	RETVAL

#-------------------------------------------------------------------------------
# SRTP
#-------------------------------------------------------------------------------
X509 *get_peer_certificate(SSL *ssl)
	CODE:
	RETVAL = SSL_get1_peer_certificate(ssl);	// need for X509_free
	if (!RETVAL) XSRETURN_UNDEF;

	OUTPUT:
	RETVAL

void get_selected_srtp_profile(SSL *ssl)
	PPCODE:
	SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile(ssl);
	if (!profile) {
		XSRETURN_UNDEF;
	}
	mXPUSHs(newSVpv(profile->name, 0));
	XSRETURN(1);

void get_srtp_key_info(SSL *ssl)
	PPCODE:
	SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile(ssl);
	if (!profile || strncmp(profile->name, SRTP_PROFILE_NAME, sizeof(SRTP_PROFILE_NAME))) {
		XSRETURN_UNDEF;
	}

	srtp_key_info keyinfo;		// EXTRACTOR-dtls_srtp in RFC 5764
	if (!SSL_export_keying_material(ssl, (unsigned char *)&keyinfo, sizeof(keyinfo), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
		XSRETURN_UNDEF;
	}
	mXPUSHs(newSVpv(keyinfo.remote_key,  sizeof(keyinfo.remote_key) ));
	mXPUSHs(newSVpv(keyinfo.local_key,   sizeof(keyinfo.local_key ) ));
	mXPUSHs(newSVpv(keyinfo.remote_salt, sizeof(keyinfo.remote_salt)));
	mXPUSHs(newSVpv(keyinfo.local_salt,  sizeof(keyinfo.local_salt )));
	XSRETURN(4);

################################################################################
# X509 object
################################################################################
MODULE = Net::TinySRTP	PACKAGE = Net::TinySRTP::X509

void DESTROY(X509 *x509)
	CODE:
        DEBUG_PRINT("*** X509::DESTROY\n")
	if (x509) X509_free( x509 );

void fingerprint(X509 *x509)
	PPCODE:
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int  size = sizeof(buf);
	if (! X509_digest(x509, DIGEST_METHOD, buf, &size) || size==0) {
		XSRETURN_UNDEF;
	}

	mXPUSHs( newSVpv(buf, size) );
	XSRETURN(1);


################################################################################
# Destroy
################################################################################
MODULE = Net::TinySRTP	PACKAGE = Net::TinySRTP::EVP_PKEY

void DESTROY(EVP_PKEY *pkey)
	CODE:
        DEBUG_PRINT("*** EVP_PKEY::DESTROY\n")
	if (pkey) EVP_PKEY_free( pkey );


################################################################################
# Cipher
################################################################################
MODULE = Net::TinySRTP	PACKAGE = Net::TinySRTP

# RFC 3711 and 
void aes_cm_kdf(SV *_mkey, SV *_msalt, int label, int length=0, unsigned int index=0)
	PPCODE:
	if (!SvOK(_mkey) || !SvOK(_msalt)) XSRETURN_UNDEF;

	STRLEN mkey_len, msalt_len;
	const void *mkey  = SvPVbyte(_mkey,  mkey_len );
	const void *msalt = SvPVbyte(_msalt, msalt_len);
	if (mkey_len != 16 && mkey_len != 32 || 16<msalt_len) XSRETURN_UNDEF;

	char salt[16];
	memset(salt, 0, 16);
	memcpy(salt, msalt, msalt_len);
	salt[7]  ^= (label & 0xff);
	salt[8]  ^= (index>>24) & 0xff;
	salt[9]  ^= (index>>16) & 0xff;
	salt[10] ^= (index>> 8) & 0xff;
	salt[11] ^=  index      & 0xff;

	char key[mkey_len];
	memset(key, 0, mkey_len);
	int len=mkey_len;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (! ctx) XSRETURN_UNDEF;

	int ok=0;
	do {
		const EVP_CIPHER *aes = mkey_len==16 ? EVP_aes_128_ctr() : EVP_aes_256_ctr();

		if (1 != EVP_EncryptInit  (ctx, aes, mkey, salt)) break;
		if (1 != EVP_EncryptUpdate(ctx, key, &len, key, len)) break;
		ok=1;
	} while(false);
	EVP_CIPHER_CTX_free(ctx);

	if (!ok) XSRETURN_UNDEF;

	mXPUSHs( newSVpv(key, (length && length<len) ? length : len) );
	XSRETURN(1);


void aes_gcm_encrypt(SV *_key, SV *_iv, SV *_adata, SV *_plain)
	PPCODE:
	if (!SvOK(_key) || !SvOK(_iv)) XSRETURN_UNDEF;

	STRLEN key_len, iv_len, adata_len, plain_len;
	const void *key   = SvPVbyte(_key,   key_len  );
	const void *iv    = SvPVbyte(_iv,    iv_len   );
	const void *adata = SvPVbyte(_adata, adata_len);
	const void *plain = SvPVbyte(_plain, plain_len);
	if (key_len != 16 && key_len != 32 || iv_len!=12) XSRETURN_UNDEF;

	STRLEN xlen;
	SV *svbuf = newSV(0);
	SvPVbyte_force(svbuf, xlen);
	char *buf = SvGROW(svbuf, plain_len + AEAD_AUTH_TAG_LENGTH +1);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (! ctx) XSRETURN_UNDEF;

	int ok=0;
	do {
		const EVP_CIPHER *aes =key_len==16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();

		int len;
		if (1 != EVP_EncryptInit  (ctx, aes, key, iv)) break;
		if (adata_len
		 && 1 != EVP_EncryptUpdate(ctx, NULL, &len, adata, adata_len)) break;
		if (1 != EVP_EncryptUpdate(ctx, buf,  &len, plain, plain_len)) break;
		if (1 != EVP_EncryptFinal_ex(ctx, buf + len, &len)) break;
		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_AUTH_TAG_LENGTH, buf + plain_len)) break;

		ok=1;
	} while(false);
	EVP_CIPHER_CTX_free(ctx);

	if (!ok) XSRETURN_UNDEF;

	if (GIMME_V == G_ARRAY) {		// wantarray?
		SV *tag = newSVpv(buf+plain_len, AEAD_AUTH_TAG_LENGTH);
		
		buf[plain_len] = 0;
		SvCUR_set(svbuf, plain_len);

		mXPUSHs( svbuf );
		mXPUSHs( tag   );
		XSRETURN(2);
	} else {
		buf[plain_len + AEAD_AUTH_TAG_LENGTH] = 0;
		SvCUR_set(svbuf, plain_len + AEAD_AUTH_TAG_LENGTH);

		mXPUSHs( svbuf );
		XSRETURN(1);
	}

void aes_gcm_decrypt(SV *_key, SV *_iv, SV *_adata, SV *_cipher, SV *_tag)
	PPCODE:
	if (!SvOK(_key) || !SvOK(_iv)) XSRETURN_UNDEF;

	STRLEN key_len, iv_len, adata_len, cipher_len, tag_len;
	const void *key    = SvPVbyte(_key,    key_len   );
	const void *iv     = SvPVbyte(_iv,     iv_len    );
	const void *adata  = SvPVbyte(_adata,  adata_len );
	const void *cipher = SvPVbyte(_cipher, cipher_len);
	const void *tag    = SvPVbyte(_tag,    tag_len   );
	if (key_len != 16 && key_len != 32 || iv_len!=12 || tag_len!=AEAD_AUTH_TAG_LENGTH) XSRETURN_UNDEF;

	STRLEN xlen;
	SV *svbuf = newSV(0);
	SvPVbyte_force(svbuf, xlen);
	char *buf = SvGROW(svbuf, cipher_len + 1);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (! ctx) XSRETURN_UNDEF;

	int ok=0;
	do {
		const EVP_CIPHER *aes =key_len==16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm();

		int len;
		if (1 != EVP_DecryptInit  (ctx, aes, key, iv)) break;
		if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, AEAD_AUTH_TAG_LENGTH, (void *)tag)) break;
		if (adata_len
		 && 1 != EVP_DecryptUpdate(ctx, NULL, &len, adata,  adata_len )) break;
		if (1 != EVP_DecryptUpdate(ctx, buf,  &len, cipher, cipher_len)) break;
 		if (1 != EVP_DecryptFinal_ex(ctx, buf + len, &len)) break;

		ok=1;
	} while(false);
	EVP_CIPHER_CTX_free(ctx);

	if (!ok) XSRETURN_UNDEF;

	buf[cipher_len] = 0;
	SvCUR_set(svbuf, cipher_len);
	SvPOK_only(svbuf);

	mXPUSHs( svbuf );
	XSRETURN(1);



