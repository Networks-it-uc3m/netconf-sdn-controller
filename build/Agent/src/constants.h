

#define MAX_PATH  200
#define MAX_IP 40
#define MAX_KEY 1024

#define MAP_HASH_SIZE 32

#define CASE1_IPSECIKE 1
#define CASE2_IPSEC 2

//#define XPATH_MAX_LEN 100

#define SADB_REGISTER_MSG 1
#define SADB_ACQUIRE_MSG 2
#define SADB_EXPIRE_MSG 3

#define IPSEC_MODE_ANY        0
#define IPSEC_MODE_TRANSPORT  1
#define IPSEC_MODE_TUNNEL     2

#define IPSEC_PROTO_ESP 50

#define IPSEC_DF_BIT_CLEAR 0
#define IPSEC_DF_BIT_SET 1
#define IPSEC_DF_BIT_COPY 2

#define IPSEC_NLP_TCP  0
#define IPSEC_NLP_UDP 1
#define IPSEC_NLP_SCTP 2
#define IPSEC_NLP_DCCP  3
#define IPSEC_NLP_ICMP 4
#define IPSEC_NLP_IPv6_ICMP 5
#define IPSEC_NLP_MH 6
#define IPSEC_NLP_GRE 7

#define EALG_DESCBC_KEY_BITS	  64
#define EALG_3DESCBC_KEY_BITS	  192
#define EAL_BLOWFISH_KEY_BITS     192
#define EAL_AES_KEY_BITS          256
#define EAL_CASTCBC_KEY_BITS      128
#define EAL_AESCTR_KEY_BITS      512  
#define EAL_AES_CCM_ICV8_KEY_BITS  256
#define EAL_AES_CCM_ICV12_KEY_BITS 384
#define EAL_AES_CCM_ICV16_KEY_BITS 512
#define EAL_AES_GCM_ICV8_KEY_BITS 256  
#define EAL_AES_GCM_ICV12_KEY_BITS 384  
#define EAL_AES_GCM_ICV16_KEY_BITS 512  


#define AALG_MD5HMAC_KEY_BITS    160
#define AALG_SHA1HMAC_KEY_BITS   160

//#define SADB_SATYPE_AH  2
//#define SADB_SATYPE_ESP 3

#define IPSEC_DIR_INBOUND  1
#define IPSEC_DIR_OUTBOUND 2
#define IPSEC_DIR_FORWARD 3

#define IPSEC_LEVEL_DEFAULT     0       /* reference to system default */
#define IPSEC_LEVEL_USE         1       /* use SA if present. */
#define IPSEC_LEVEL_REQUIRE     2       /* require SA. */
#define IPSEC_LEVEL_UNIQUE      3       /* unique SA. */


#define IPSEC_POLICY_DISCARD 0
#define IPSEC_POLICY_PROTECT   2
#define IPSEC_POLICY_BYPASS  4

#define PFKEY_BUFFER_SIZE 4096
#define PFKEY_ALIGNMENT   8


#define PAD_AUTH_METHOD_PRE_SHARED 1
#define PAD_AUTH_PROTOCOL_IKE 1
#define IKE_AUTOSTARTUP_ADD 0
#define IKE_AUTOSTARTUP_ONDEMAND 1
#define IKE_AUTOSTARTUP_START 2


/* Message types */
#define SADB_RESERVED		0
#define SADB_GETSPI		1
#define SADB_UPDATE		2
#define SADB_ADD		3
#define SADB_DELETE		4
#define SADB_GET		5
#define SADB_ACQUIRE		6
#define SADB_REGISTER		7
#define SADB_EXPIRE		8
#define SADB_FLUSH		9
#define SADB_DUMP		10
#define SADB_X_PROMISC		11
#define SADB_X_PCHANGE		12
#define SADB_X_SPDUPDATE	13
#define SADB_X_SPDADD		14
#define SADB_X_SPDDELETE	15
#define SADB_X_SPDGET		16
#define SADB_X_SPDACQUIRE	17
#define SADB_X_SPDDUMP		18
#define SADB_X_SPDFLUSH		19
#define SADB_X_SPDSETIDX	20
#define SADB_X_SPDEXPIRE	21
#define SADB_X_SPDDELETE2	22
#define SADB_X_NAT_T_NEW_MAPPING	23
#define SADB_X_MIGRATE		24
#define SADB_MAX		24

/* Security Association flags */
#define SADB_SAFLAGS_PFS	1
#define SADB_SAFLAGS_NOPMTUDISC	0x20000000
#define SADB_SAFLAGS_DECAP_DSCP	0x40000000
#define SADB_SAFLAGS_NOECN	0x80000000

/* Security Association states */
#define SADB_SASTATE_LARVAL	0
#define SADB_SASTATE_MATURE	1
#define SADB_SASTATE_DYING	2
#define SADB_SASTATE_DEAD	3
#define SADB_SASTATE_MAX	3

/* Security Association types */
#define SADB_SATYPE_UNSPEC	0
#define SADB_SATYPE_AH		2
#define SADB_SATYPE_ESP		3
#define SADB_SATYPE_RSVP	5
#define SADB_SATYPE_OSPFV2	6
#define SADB_SATYPE_RIPV2	7
#define SADB_SATYPE_MIP		8
#define SADB_X_SATYPE_IPCOMP	9
#define SADB_SATYPE_MAX		9

/* Authentication algorithms */
#define SADB_AALG_NONE			0
#define SADB_AALG_MD5HMAC		2
#define SADB_AALG_SHA1HMAC		3
#define SADB_X_AALG_SHA2_256HMAC	5
#define SADB_X_AALG_SHA2_384HMAC	6
#define SADB_X_AALG_SHA2_512HMAC	7
#define SADB_X_AALG_RIPEMD160HMAC	8
#define SADB_X_AALG_AES_XCBC_MAC	9
#define SADB_X_AALG_NULL		251	/* kame */
#define SADB_AALG_MAX			251

/* Encryption algorithms */
#define SADB_EALG_NONE			0
#define SADB_EALG_DESCBC		2
#define SADB_EALG_3DESCBC		3 // Hasta 192 
#define SADB_X_EALG_CASTCBC		6 // key length 128bits
#define SADB_X_EALG_BLOWFISHCBC	7 // key length 32bits-448
#define SADB_EALG_NULL			11 
#define SADB_X_EALG_AESCBC		12 // key length 128/192/256 
#define SADB_X_EALG_AESCTR		13 // key length 128/192/256 
#define SADB_X_EALG_AES_CCM_ICV8	14 //key length 128/192/256 
#define SADB_X_EALG_AES_CCM_ICV12	15 //key length 128/192/256 
#define SADB_X_EALG_AES_CCM_ICV16	16 //key length 128/192/256 
#define SADB_X_EALG_AES_GCM_ICV8	18 //key length 128/192/256 
#define SADB_X_EALG_AES_GCM_ICV12	19 //key length 128/192/256 
#define SADB_X_EALG_AES_GCM_ICV16	20 //key length 128/192/256 
#define SADB_X_EALG_CAMELLIACBC		22 //key length 128/192/256 
#define SADB_X_EALG_NULL_AES_GMAC	23 // key length 128/192/256 
#define SADB_EALG_MAX                   253 /* last EALG */
/* private allocations should use 249-255 (RFC2407) */
#define SADB_X_EALG_SERPENTCBC  252     /* draft-ietf-ipsec-ciph-aes-cbc-00 */
#define SADB_X_EALG_TWOFISHCBC  253     /* draft-ietf-ipsec-ciph-aes-cbc-00 */

/* Compression algorithms */
#define SADB_X_CALG_NONE		0
#define SADB_X_CALG_OUI			1
#define SADB_X_CALG_DEFLATE		2
#define SADB_X_CALG_LZS			3
#define SADB_X_CALG_LZJH		4
#define SADB_X_CALG_MAX			4

/* Extension Header values */
#define SADB_EXT_RESERVED		0
#define SADB_EXT_SA			1
#define SADB_EXT_LIFETIME_CURRENT	2
#define SADB_EXT_LIFETIME_HARD		3
#define SADB_EXT_LIFETIME_SOFT		4
#define SADB_EXT_ADDRESS_SRC		5
#define SADB_EXT_ADDRESS_DST		6
#define SADB_EXT_ADDRESS_PROXY		7
#define SADB_EXT_KEY_AUTH		8
#define SADB_EXT_KEY_ENCRYPT		9
#define SADB_EXT_IDENTITY_SRC		10
#define SADB_EXT_IDENTITY_DST		11
#define SADB_EXT_SENSITIVITY		12
#define SADB_EXT_PROPOSAL		13
#define SADB_EXT_SUPPORTED_AUTH		14
#define SADB_EXT_SUPPORTED_ENCRYPT	15
#define SADB_EXT_SPIRANGE		16
#define SADB_X_EXT_KMPRIVATE		17
#define SADB_X_EXT_POLICY		18
#define SADB_X_EXT_SA2			19
/* The next four entries are for setting up NAT Traversal */
#define SADB_X_EXT_NAT_T_TYPE		20
#define SADB_X_EXT_NAT_T_SPORT		21
#define SADB_X_EXT_NAT_T_DPORT		22
#define SADB_X_EXT_NAT_T_OA		23
#define SADB_X_EXT_SEC_CTX		24
/* Used with MIGRATE to pass @ to IKE for negotiation */
#define SADB_X_EXT_KMADDRESS		25
#define SADB_X_EXT_FILTER		26
#define SADB_EXT_MAX			26

/* Identity Extension values */
#define SADB_IDENTTYPE_RESERVED	0
#define SADB_IDENTTYPE_PREFIX	1
#define SADB_IDENTTYPE_FQDN	2
#define SADB_IDENTTYPE_USERFQDN	3
#define SADB_IDENTTYPE_MAX	3


// #define SR_ERR_NOT_FOUND  1
// #define SR_ERR_OPERATION_FAILED 3
// #define SR_ERR_OK 0