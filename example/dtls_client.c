////////////////////////////////////////////////////////////////////////////////
// DTLS and SRTP key exchange client example with OpenSSL
////////////////////////////////////////////////////////////////////////////////
// complie
//	gcc -o dtls_client dtls_client.c -lssl -lcrypto
//
// Run
//	./dtls_client ip port
//
////////////////////////////////////////////////////////////////////////////////
// OpenSSL server:
/* 
openssl ecparam -out server-key.pem -name prime256v1 -genkey
openssl req  -new -sha256 -key server-key.pem -out server.csr -subj "/CN=example.com"
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server-key.pem -out server-cert.pem

openssl s_server -dtls1_2 -key server-key.pem -cert server-cert.pem  -use_srtp SRTP_AEAD_AES_128_GCM -keymatexport "EXTRACTOR-dtls_srtp" -keymatexportlen 56 -port 3000
*/
//
////////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>

const char *SSLProfiles = "SRTP_AEAD_AES_128_GCM";
#define KEY_LENGTH	(128/8)
#define SALT_LENGTH	(96/8)

typedef struct srtp_key_info {
	unsigned char client_key[KEY_LENGTH];
	unsigned char server_key[KEY_LENGTH];
	unsigned char client_salt[SALT_LENGTH];
	unsigned char server_salt[SALT_LENGTH];
} srtp_key_info;


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

int client_simple(int sock, struct sockaddr_in *addr) {
	SSL_CTX *ctx = SSL_CTX_new(DTLS_method());

	if (generate_keypair(ctx)) return 10;

	connect(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in));

	BIO *bio = BIO_new_dgram(sock, BIO_NOCLOSE);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addr);

	if (SSL_CTX_set_tlsext_use_srtp(ctx, SSLProfiles))	// 0 is success
		printf("Fail SSL_CTX_set_tlsext_use_srtp()\n");

	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);	// SSL_set_bio() is transfers ownership of bio to ssl.
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	int r = SSL_connect(ssl);
	if (r!=1) {
		printf("Connection failed %d\n", r);
		return 1;
	}

	print_ssl_status(ssl);

	return 0;
}

inline int is_dtls(const char *buf) {
	return 20<=*buf && *buf<64;
}

int client_no_connect(int sock, struct sockaddr_in *addr) {

	SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
	if (generate_keypair(ctx)) return 10;

	BIO *rbio = BIO_new(BIO_s_mem());
	BIO *wbio = BIO_new(BIO_s_mem());
	if (!rbio || !wbio) return 11;

	BIO_set_mem_eof_return(wbio, -1);

	if (SSL_CTX_set_tlsext_use_srtp(ctx, SSLProfiles))	// 0 is success
		printf("Fail SSL_CTX_set_tlsext_use_srtp()\n");

	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, rbio, wbio);	// SSL_set_bio() is transfers ownership of bio to ssl.
	// SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	SSL_set_connect_state(ssl);
	SSL_do_handshake(ssl);

	const int buf_size = 4096;
	char      buf[buf_size];

	while(!SSL_is_init_finished(ssl)) {
		int pen_size = BIO_ctrl_pending(wbio);
		if (0<pen_size && pen_size<=buf_size) {
			int sends = BIO_read(wbio, buf, pen_size);
			if (0<sends)
				sendto(sock, buf, sends, 0, (struct sockaddr *)addr, sizeof(*addr));
		}

		fd_set rfd;
		FD_ZERO(&rfd);
		FD_SET(sock, &rfd);

		int r = select(sock + 1, &rfd, NULL, NULL, NULL);
		if (r<0) {
			printf("select() failed!\n");
			return 20;
		}

		struct sockaddr_in peer;
		int peerlen = sizeof(peer);
		int len = recvfrom(sock, buf, buf_size, 0, (struct sockaddr *)&peer, &peerlen);
		if (len<0) {
			printf("packet receive error!\n");
			return 21;
		}
		if (memcmp(&peer, addr, peerlen)) continue;	// other packet
		if (! is_dtls(buf)) continue;

		// is DTLS
		BIO_write(rbio, buf, len);
		SSL_read(ssl, buf, 0);
	}

	print_ssl_status(ssl);

	return 0;
}



int main(int argc, char **argv) {
	const char *ip;
	int port;

	if (argc<3) {
		printf("Require argument:\n");
		printf("\t%s ip port\n", argv[0]);
		return 0;
	}
	ip   = argv[1];
	port = atoi(argv[2]);
	if (port<1) {
		printf("Invalid port: %d\n", port);
		return 1;
	}

	printf("Connect to %s:%d\n", ip, port);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	// return client_simple(sock, &addr);
	return client_no_connect(sock, &addr);
}

