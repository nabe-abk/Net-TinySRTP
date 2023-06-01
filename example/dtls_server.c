////////////////////////////////////////////////////////////////////////////////
// DTLS and SRTP key exchange server example with OpenSSL
////////////////////////////////////////////////////////////////////////////////
// Complie
//	gcc -o dtls_server dtls_server.c -lssl -lcrypto
// Run
//	./dtls_server port
//
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

const char *SSLProfiles = "SRTP_AEAD_AES_128_GCM";
#define KEY_LENGTH	(128/8)
#define SALT_LENGTH	(96/8)

#define SSL_COOKIE_METHOD	EVP_sha256()
#define SSL_COOKIE_BYTES	32
#define SSL_COOKIE_SECRET_BYTES	32

typedef struct srtp_key_info {
	unsigned char client_key[KEY_LENGTH];
	unsigned char server_key[KEY_LENGTH];
	unsigned char client_salt[SALT_LENGTH];
	unsigned char server_salt[SALT_LENGTH];
} srtp_key_info;

typedef union {
	sa_family_t     sin_family;
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
} u_sockaddr;


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

void print_hex(const char *head, unsigned char *buf, unsigned int size) {
	if (head) printf(head);
	for(unsigned int i=0; i<size; i++) {
		printf("%02x:", buf[i]);
	}
	printf("\n");
}

void print_finger(const X509 *x509) {
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned int  size = sizeof(buf);
	if (! X509_digest(x509, EVP_sha256(), buf, &size) || size==0) {
		printf("fingerprint fail\n");
	}
	print_hex(NULL, buf, size);
}

EVP_PKEY *generate_pkey() {
	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_group_name(pctx, "prime256v1");
	EVP_PKEY_keygen(pctx, &pkey);
	EVP_PKEY_CTX_free(pctx);

	return pkey;
}

int generate_keypair(SSL_CTX *ctx) {

	EVP_PKEY *pkey = generate_pkey();

	X509_REQ *req = X509_REQ_new();
	if (! X509_REQ_set_version(req, X509_VERSION_1)) {
		printf("failed to set version\n");
		return 1;
	}
	if (! X509_REQ_set_pubkey(req, pkey)) {
		printf("failed to set pubkey\n");
		return 1;
	}

	if (1) {
		X509_NAME *name = X509_NAME_new();
		X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (const unsigned char *)"JP",         -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"example.jp", -1, -1, 0);
		X509_REQ_set_subject_name(req, name);
	}

	if (! X509_REQ_sign(req, pkey, EVP_sha256())) {
		printf("failed to sign\n");
		return 1;
	}

	// X509_REQ to X509
	X509 *x509 = X509_new();
	if (1) {
		EVP_PKEY *pubkey = X509_REQ_get0_pubkey(req);
		X509_set_pubkey(x509, pubkey);

		X509_gmtime_adj(X509_getm_notBefore(x509), 0);
		X509_time_adj_ex(X509_getm_notAfter(x509), 30, 0, NULL);

		X509_set_subject_name(x509, X509_REQ_get_subject_name(req));
		X509_set_issuer_name (x509, X509_REQ_get_subject_name(req));
		X509_sign(x509, pkey, EVP_sha256());
	}

	SSL_CTX_use_PrivateKey(ctx, pkey);
	SSL_CTX_use_certificate(ctx, x509);

	printf("Local certificate fingerprint: ");
	print_finger(x509);
	return 0;
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

SSL_CTX *init_ssl_ctx() {
	SSL_CTX *ctx = SSL_CTX_new(DTLS_method());

	if (generate_keypair(ctx)) return NULL;

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);	// Require for get peer's cert
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb  (ctx, verify_cookie);

	if (SSL_CTX_set_tlsext_use_srtp(ctx, SSLProfiles))	// 0 is success
		printf("Fail SSL_CTX_set_tlsext_use_srtp()\n");

	return ctx;
}

void print_ssl_status(SSL *ssl) {
	X509 *x509 = SSL_get_peer_certificate(ssl);

	if (x509) {
		printf("Peer's fingerprint: ");
		print_finger(x509);
	} else {
		printf("Peer's cert not found!\n");
	}

	SRTP_PROTECTION_PROFILE *srtp_profile = SSL_get_selected_srtp_profile(ssl);

	if (srtp_profile) printf("%s\n", srtp_profile->name);

	srtp_key_info keyinfo;
 	SSL_export_keying_material(ssl, (unsigned char *)&keyinfo, sizeof(keyinfo), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0);

	print_hex("Server-key : ", keyinfo.server_key,  sizeof(keyinfo.server_key) );
	print_hex("Client-key : ", keyinfo.client_key,  sizeof(keyinfo.client_key) );
	print_hex("Server-salt: ", keyinfo.server_salt, sizeof(keyinfo.server_salt));
	print_hex("Client-salt: ", keyinfo.client_salt, sizeof(keyinfo.client_salt));
}


int server_single(int sock) {
	SSL_CTX *ctx = init_ssl_ctx();
	if (!ctx) return 10;

	BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);	// SSL_set_bio() is transfers ownership of bio to ssl.
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	BIO_ADDR *bio_addr = BIO_ADDR_new();
	int r = DTLSv1_listen(ssl, bio_addr);
	if (r!=1) {
		printf("Connection failed %d\n", r);
		ERR_print_errors_fp(stderr);
		return 1;
	}

	u_sockaddr cl_addr;
	if (! bio2sockaddr(bio_addr, &cl_addr)) {
		printf("Failed get client address\n");
		return 2;
	}

	connect(sock, &cl_addr.sa, sizeof(cl_addr.sa));
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, bio_addr);
	BIO_ADDR_free(bio_addr);

	if (cl_addr.sin_family == AF_INET)
		printf("Connection from %s:%d\n", inet_ntoa(cl_addr.s4.sin_addr), cl_addr.s4.sin_port);

	int ret = SSL_accept(ssl);
	if (ret<0) {
		printf("Connection failed\n");
		return 3;
	}

	print_ssl_status(ssl);

	return 0;
}

inline int is_dtls(const char *buf) {
	return 20<=*buf && *buf<64;
}

int server_no_connect(int sock, SSL_CTX *ctx) {
	BIO *rbio = BIO_new(BIO_s_mem());
	BIO *wbio = BIO_new(BIO_s_mem());
	if (!rbio || !wbio) return 11;

	BIO_set_mem_eof_return(wbio, -1);

	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, rbio, wbio);
//	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);	// Do not run with BIO_s_mem()

	SSL_set_accept_state(ssl);
	SSL_do_handshake(ssl);

	const int buf_size = 4096;
	char      buf[buf_size];
	struct    sockaddr_in peer;

	while(!SSL_is_init_finished(ssl)) {
		fd_set rfd;
		FD_ZERO(&rfd);
		FD_SET(sock, &rfd);

		int r = select(sock + 1, &rfd, NULL, NULL, NULL);
		if (r<0) {
			printf("select() failed!\n");
			return 20;
		}

		int peerlen = sizeof(peer);
		int len = recvfrom(sock, buf, buf_size, 0, (struct sockaddr *)&peer, &peerlen);
		if (len<0) {
			printf("packet receive error!\n");
			return 21;
		}
		if (! is_dtls(buf)) continue;

		// is DTLS
		BIO_write(rbio, buf, len);
		SSL_read(ssl, buf, 0);

		int pen_size = BIO_ctrl_pending(wbio);
		if (0<pen_size && pen_size<=buf_size) {
			int sends = BIO_read(wbio, buf, pen_size);
			if (0<sends)
				sendto(sock, buf, sends, 0, (struct sockaddr *)&peer, sizeof(peer));
		}
	}

	if (peer.sin_family == AF_INET)
		printf("Connection from %s:%d\n", inet_ntoa(peer.sin_addr), peer.sin_port);

	print_ssl_status(ssl);

	return 0;
}
int server_loop(int sock) {	// Do not use socket connect().
	SSL_CTX *ctx = init_ssl_ctx();
	if (!ctx) return 10;

	while(1) {
		int r = server_no_connect(sock, ctx);
		if (r) return r;
		printf("\n");
	}
}

int main(int argc, char **argv) {
	const char *ip;
	int port;
	int single_mode = 0;
	int p = 1;

	if (p<argc && !strncmp(argv[p], "-s", 2)) {
		printf("Set single mode\n");
		single_mode = 1;
		p++;
	}

	if (argc <= p) {
		printf("Require argument:\n");
		printf("\t%s [-s] port\n", argv[0]);
		return 0;
	}
	port = atoi(argv[p]);
	if (port<1) {
		printf("Invalid port: %d\n", port);
		return 1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind *:%d failed\n", port);
		return 3;
	}
	printf("Listen *:%d\n", port);

	return single_mode ? server_single(sock) : server_loop(sock);
}

