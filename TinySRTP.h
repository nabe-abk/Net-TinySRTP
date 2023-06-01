#ifndef _Net_TinySRTP_H
#define _Net_TinySRTP_H
////////////////////////////////////////////////////////////////////////////////
typedef unsigned char uchar;
typedef unsigned int  uint;

#include <openssl/ssl.h>

#define DIGEST_METHOD		EVP_sha256()

#define SSL_COOKIE_METHOD	EVP_sha256()
#define SSL_COOKIE_BYTES	32
#define SSL_COOKIE_SECRET_BYTES	32
#define HANDSHAKE_BUF_SIZE	1024

////////////////////////////////////////////////////////////////////////////////
// SRTP PROFILES
////////////////////////////////////////////////////////////////////////////////
#define USE_SRTP_AEAD_AES_128_GCM
//#define USE_SRTP_AEAD_AES_256_GCM

// RFC 7714
#ifdef	USE_SRTP_AEAD_AES_128_GCM
#define		SRTP_PROFILE_NAME	"SRTP_AEAD_AES_128_GCM"
#define		SRTP_KEY_LENGTH		(128/8)
#define		SRTP_SALT_LENGTH	(96/8)
#define		AEAD_AUTH_TAG_LENGTH	16
#define		SRTP_MAX_LIFETIME	(1<<48)
#endif

// RFC 7714
#ifdef	USE_SRTP_AEAD_AES_256_GCM
#define		SRTP_PROFILE_NAME	"SRTP_AEAD_AES_256_GCM"
#define		SRTP_KEY_LENGTH		(256/8)
#define		SRTP_SALT_LENGTH	(96/8)
#define		AEAD_AUTH_TAG_LENGTH	16
#define		SRTP_MAX_LIFETIME	(1<<48)
#endif

// RFC 5764: not support
#ifdef	USE_SRTP_AES128_CM_HMAC_SHA1_80
#define		SRTP_PROFILE_NAME	"SRTP_AES128_CM_SHA1_80"
#define		SRTP_KEY_LENGTH		(128/8)
#define		SRTP_SALT_LENGTH	(112/8)
#define		AEAD_AUTH_TAG_LENGTH
#define		SRTP_MAX_LIFETIME	(1<<32)
#define
#endif

typedef struct srtp_key_info {
	uchar remote_key [SRTP_KEY_LENGTH];
	uchar local_key  [SRTP_KEY_LENGTH];
	uchar remote_salt[SRTP_SALT_LENGTH];
	uchar local_salt [SRTP_SALT_LENGTH];
} srtp_key_info;

typedef union aes_gcm_ivbase {
	char	buf[SRTP_SALT_LENGTH];
	struct	{
		u_int16_t	zero1;
		u_int32_t	ssrc;
		u_int32_t	roc;
		u_int16_t	seq;
	} data;
} aes_gcm_iv;


typedef union {
	sa_family_t     sin_family;
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
} u_sockaddr;

/*
typedef enum {
    label_rtp_encryption  = 0x00,
    label_rtp_msg_auth    = 0x01,
    label_rtp_salt        = 0x02,
    label_rtcp_encryption = 0x03,
    label_rtcp_msg_auth   = 0x04,
    label_rtcp_salt       = 0x05
} srtp_prf_label;
*/

inline int is_dtls(const char *buf) {
	return 20<=*buf && *buf<64;
}

////////////////////////////////////////////////////////////////////////////////
#ifdef DEBUG
#	define DEBUG_PRINT(...)		fprintf(stderr, __VA_ARGS__);
#else
#	define DEBUG_PRINT(...)
#endif
////////////////////////////////////////////////////////////////////////////////
#endif
