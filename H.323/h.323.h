#include <string.h>
#include <time.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

using namespace std;
typedef signed char gint8;
typedef unsigned char guint8;
typedef signed short gint16;
typedef unsigned short guint16;
typedef signed int gint32;
typedef unsigned int guint32;
typedef char gchar;
typedef int gint;
typedef unsigned int guint;
typedef gint gboolean;
typedef signed long gint64;
typedef unsigned long guint64;

typedef struct _GSList  GSList;
typedef void *gpointer;
typedef unsigned long gsize;
typedef unsigned long   gulong;
typedef const void *gconstpointer;
typedef unsigned char   guchar;
typedef double  gdouble;


#define TRUE 1
#define True 1
#define FALSE 0
#define ASN1_CTX_SIGNATURE 0x41435458  /* "ACTX" */
#define TAP_PACKET_QUEUE_LEN 100
#define BoundsError		1
#define ReportedBoundsError	2
#define TypeError		3
#define DissectorError		4

#define BER_CLASS_UNI	0
#define BER_CLASS_APP	1
#define BER_CLASS_CON	2
#define BER_CLASS_PRI	3
#define BER_CLASS_ANY   99			/* dont check class nor tag */

#define BER_UNI_TAG_EOC					0	/* 'end-of-content' */
#define BER_UNI_TAG_BOOLEAN				1
#define BER_UNI_TAG_INTEGER				2
#define BER_UNI_TAG_BITSTRING		    3
#define BER_UNI_TAG_OCTETSTRING		    4
#define BER_UNI_TAG_NULL				5
#define BER_UNI_TAG_OID					6	/* OBJECT IDENTIFIER */
#define BER_UNI_TAG_ObjectDescriptor	7
#define BER_UNI_TAG_EXTERNAL			8
#define BER_UNI_TAG_REAL				9
#define BER_UNI_TAG_ENUMERATED		    10
#define BER_UNI_TAG_EMBEDDED_PDV	    11
#define BER_UNI_TAG_UTF8String		    12
#define BER_UNI_TAG_RELATIVE_OID	    13
/* UNIVERSAL 14-15	
 * Reserved for future editions of this
 * Recommendation | International Standard
 */
#define BER_UNI_TAG_SEQUENCE		    16	/* SEQUENCE, SEQUENCE OF */
#define BER_UNI_TAG_SET					17	/* SET, SET OF */
/* UNIVERSAL 18-22 Character string types */
#define BER_UNI_TAG_NumericString	    18
#define BER_UNI_TAG_PrintableString	    19
#define BER_UNI_TAG_TeletexString	    20  /* TeletextString, T61String */
#define BER_UNI_TAG_VideotexString	    21
#define BER_UNI_TAG_IA5String		    22
/* UNIVERSAL 23-24 Time types */
#define BER_UNI_TAG_UTCTime				23
#define BER_UNI_TAG_GeneralizedTime	    24
/* UNIVERSAL 25-30 Character string types */
#define BER_UNI_TAG_GraphicString	    25
#define BER_UNI_TAG_VisibleString	    26  /* VisibleString, ISO64String */
#define BER_UNI_TAG_GeneralString	    27
#define BER_UNI_TAG_UniversalString	    28
#define BER_UNI_TAG_CHARACTERSTRING	    29
#define BER_UNI_TAG_BMPString		    30
/* UNIVERSAL 31- ...
 * Reserved for addenda to this Recommendation | International Standard
 */



#define BER_FLAGS_OPTIONAL	0x00000001
#define BER_FLAGS_IMPLTAG	0x00000002
#define BER_FLAGS_NOOWNTAG	0x00000004
#define BER_FLAGS_NOTCHKTAG	0x00000008

#define             g_assert(expr)
#define             g_assert_not_reached()

#define array_length(x)	(sizeof x / sizeof x[0])
#define VALUE_STRING_EXT_INIT(x) { _match_strval_ext_init, 0, array_length(x)-1, x, #x }


#define BER_MAX_NESTING 500

#define EMEM_CANARY_SIZE 8
#define EMEM_CANARY_DATA_SIZE (EMEM_CANARY_SIZE * 2 - 1)

#define va_dcl va_list va_alist;
//#define va_start(ap) ap = (va_list)&va_alist
//#define va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
//#define va_end(ap) ap = (va_list)0

#define ENC_BIG_ENDIAN		0x00000000
#define ENC_LITTLE_ENDIAN	0x80000000

#define BUF_TOO_SMALL_ERR "[Buffer too small]"
#define	MAX_BYTE_STR_LEN	48

#define pntohs(p)   ((guint16)                       \
                     ((guint16)*((const guint8 *)(p)+0)<<8|  \
                      (guint16)*((const guint8 *)(p)+1)<<0))

#define NO_MORE_DATA_CHECK(nmdc_len) \
    if ((nmdc_len) == (curr_offset - offset)) return(nmdc_len);

/* To pass one of two strings, singular or plural */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

#define	Q931_UIL3_X25_PL	0x06
#define	Q931_UIL3_ISO_8208	0x07	/* X.25-based */
#define	Q931_UIL3_X223		0x08	/* X.25-based */
#define	Q931_UIL3_TR_9577	0x0B
#define	Q931_UIL3_USER_SPEC	0x10

#define	Q931_IE_SO_MASK	0x80	/* single-octet/variable-length mask */
/*
 * Single-octet IEs.
 */
#define	Q931_IE_SO_IDENTIFIER_MASK	0xf0	/* IE identifier mask */
#define	Q931_IE_SO_IDENTIFIER_SHIFT	4	/* IE identifier shift */
#define	Q931_IE_SO_IE_MASK		0x0F	/* IE mask */

#define	Q931_IE_SHIFT			0x90
#define	Q931_IE_SHIFT_NON_LOCKING	0x08	/* non-locking shift */
#define	Q931_IE_SHIFT_CODESET		0x07	/* codeset */

#define	Q931_IE_MORE_DATA_OR_SEND_COMP	0xA0	/* More Data or Sending Complete */
#define	Q931_IE_MORE_DATA		0xA0
#define	Q931_IE_SENDING_COMPLETE	0xA1

#define	Q931_IE_CONGESTION_LEVEL	0xB0
#define	Q931_IE_REPEAT_INDICATOR	0xD0

/*
 * Variable-length IEs.
 */
#define	Q931_IE_VL_EXTENSION		0x80	/* Extension flag */
#define	Q931_IT_RATE_MULTIRATE	0x18
#define	Q931_UIL2_USER_SPEC	0x10
#define	Q931_ITU_STANDARDIZED_CODING	0x00



#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

#define BER_TAG_ANY -1



#define MAX_NUMBER_OF_PPIDS     2

#ifndef NO_BOUND
#define NO_BOUND -1
#endif
/* field types */
enum ftenum {
	FT_NONE,	/* used for text labels with no value */
	FT_PROTOCOL,
	FT_BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
	FT_UINT8,
	FT_UINT16,
	FT_UINT24,	/* really a UINT32, but displayed as 3 hex-digits if FD_HEX*/
	FT_UINT32,
	FT_UINT64,
	FT_INT8,
	FT_INT16,
	FT_INT24,	/* same as for UINT24 */
	FT_INT32,
	FT_INT64,
	FT_FLOAT,
	FT_DOUBLE,
	FT_ABSOLUTE_TIME,
	FT_RELATIVE_TIME,
	FT_STRING,
	FT_STRINGZ,	/* for use with proto_tree_add_item() */
	FT_UINT_STRING,	/* for use with proto_tree_add_item() */
	/*FT_UCS2_LE, */    /* Unicode, 2 byte, Little Endian     */
	FT_ETHER,
	FT_BYTES,
	FT_UINT_BYTES,
	FT_IPv4,
	FT_IPv6,
	FT_IPXNET,
	FT_FRAMENUM,	/* a UINT32, but if selected lets you go to frame with that number */
	FT_PCRE,	/* a compiled Perl-Compatible Regular Expression object */
	FT_GUID,	/* GUID, UUID */
	FT_OID,		/* OBJECT IDENTIFIER */
	FT_EUI64,
	FT_NUM_TYPES /* last item number plus one */
};

typedef struct _emem_tree_node_t {
	struct _emem_tree_node_t *parent;
	struct _emem_tree_node_t *left;
	struct _emem_tree_node_t *right;
	struct {
#define EMEM_TREE_RB_COLOR_RED		0
#define EMEM_TREE_RB_COLOR_BLACK	1
		guint32 rb_color:1;
#define EMEM_TREE_NODE_IS_DATA		0
#define EMEM_TREE_NODE_IS_SUBTREE	1
		guint32 is_subtree:1;
	} u;
	guint32 key32;
	void *data;
} emem_tree_node_t;

typedef struct _emem_tree_t {
	struct _emem_tree_t *next;
	int type;
	const char *name;    /**< just a string to make debugging easier */
	emem_tree_node_t *tree;
	void *(*malloc)(size_t);
} emem_tree_t;


typedef enum {
	BASE_NONE,	/**< none */
	BASE_DEC,	/**< decimal */
	BASE_HEX,	/**< hexadecimal */
	BASE_OCT,	/**< octal */
	BASE_DEC_HEX,	/**< decimal (hexadecimal) */
	BASE_HEX_DEC,	/**< hexadecimal (decimal) */
	BASE_CUSTOM	/**< call custom routine (in ->strings) to format */
} base_display_e;

typedef enum {
	TVBUFF_REAL_DATA,
	TVBUFF_SUBSET,
	TVBUFF_COMPOSITE
} tvbuff_type;

typedef struct {
	GSList		*tvbs;

	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	guint		*start_offsets;
	guint		*end_offsets;

} tvb_comp_t;

typedef struct
{
	struct tvbuff *tvb;
	guint offset;
	guint length;

}  tvb_backing_t;

typedef struct tvbuff;
typedef struct tvbuff tvbuff_t;
typedef struct tvbuff{
	/* Doubly linked list pointers */
	tvbuff_t                *next;
	tvbuff_t                *previous;

	/* Record-keeping */
	tvbuff_type		type;
	gboolean		initialized;
	struct tvbuff		*ds_tvb;  /**< data source top-level tvbuff */

	/** TVBUFF_SUBSET and TVBUFF_COMPOSITE keep track
	 * of the other tvbuff's they use */
	union {
		tvb_backing_t	subset;
		tvb_comp_t	composite;
	} tvbuffs;

	/** We're either a TVBUFF_REAL_DATA or a
	 * TVBUFF_SUBSET that has a backing buffer that
	 * has real_data != NULL, or a TVBUFF_COMPOSITE
	 * which has flattened its data due to a call
	 * to tvb_get_ptr().
	 */
	const guint8		*real_data;

	/** Length of virtual buffer (and/or real_data). */
	guint			length;
          
	/** Reported length. */
	guint			reported_length;
          
	/* Offset from beginning of first TVBUFF_REAL. */
	gint			raw_offset;

	/** Func to call when actually freed */
//	tvbuff_free_cb_t	free_cb;
}tvbuff_t;

typedef enum {
  ASN1_ENC_BER,  /* X.690 - BER, CER, DER */
  ASN1_ENC_PER,  /* X.691 - PER */
  ASN1_ENC_ECN,  /* X.692 - ECN */
  ASN1_ENC_XER   /* X.693 - XER */
} asn1_enc_e;
#define ITEM_LABEL_LENGTH	240
/** string representation, if one of the proto_tree_add_..._format() functions used */
typedef struct _item_label_t {
	char representation[ITEM_LABEL_LENGTH];
} item_label_t;

typedef struct _fvalue_t {
	//ftype_t	*ftype;
	union {
		/* Put a few basic types in here */
		guint32		uinteger;
		gint32		sinteger;
		guint64		integer64;
		gdouble		floating;
		gchar		*string;
		guchar		*ustring;
		//GByteArray	*bytes;
		//ipv4_addr	ipv4;
		//ipv6_addr	ipv6;
		//e_guid_t	guid;
		//nstime_t	time;
		tvbuff_t	*tvb;
		//GRegex	        *re;
	} value;

	/* The following is provided for private use
	 * by the fvalue. */
	gboolean	fvalue_gboolean1;

} fvalue_t;

typedef struct field_info {
	//header_field_info	*hfinfo;          /**< pointer to registered field information */
	gint				 start;           /**< current start of data in field_info.ds_tvb */
	gint				 length;          /**< current data length of item in field_info.ds_tvb */
	gint				 appendix_start;  /**< start of appendix data */
	gint				 appendix_length; /**< length of appendix data */
	gint				 tree_type;       /**< one of ETT_ or -1 */
	item_label_t		*rep;             /**< string for GUI tree */
	guint32				 flags;           /**< bitfield like FI_GENERATED, ... */
	tvbuff_t			*ds_tvb;          /**< data source tvbuff */
	fvalue_t			 value;
} field_info;


typedef struct {
    //GHashTable  *interesting_hfids;
    gboolean    visible;
    gboolean    fake_protocols;
    gint        count;
} tree_data_t;

/** Each proto_ proto_item is one of these. */
typedef struct _proto_node {
	struct _proto_node *first_child;
	struct _proto_node *last_child;
	struct _proto_node *next;
	struct _proto_node *parent;
	field_info  *finfo;
	tree_data_t *tree_data;
} proto_node;


typedef struct _frame_data {
  GSList      *pfd;          /**< Per frame proto data */
  guint32      num;          /**< Frame number */
  guint32      interface_id; /**< identifier of the interface. */
  guint32      pkt_len;      /**< Packet length */
  guint32      cap_len;      /**< Amount actually captured */
  guint32      cum_bytes;    /**< Cumulative bytes into the capture */
  gint64       file_off;     /**< File offset */
  guint16      subnum;       /**< subframe number, for protocols that require this */
  gint16       lnk_t;        /**< Per-packet encapsulation/data-link type */
  struct {
    unsigned int passed_dfilter : 1; /**< 1 = display, 0 = no display */
    unsigned int dependent_of_displayed : 1; /**< 1 if a displayed frame depends on this frame */
    unsigned int encoding       : 2; /**< Character encoding (ASCII, EBCDIC...) */
    unsigned int visited        : 1; /**< Has this packet been visited yet? 1=Yes,0=No*/
    unsigned int marked         : 1; /**< 1 = marked by user, 0 = normal */
    unsigned int ref_time       : 1; /**< 1 = marked as a reference time frame, 0 = normal */
    unsigned int ignored        : 1; /**< 1 = ignore this frame, 0 = normal */
    unsigned int has_ts         : 1; /**< 1 = has time stamp, 0 = no time stamp */
    unsigned int has_if_id      : 1; /**< 1 = has interface ID, 0 = no interface ID */
  } flags;

  const void *color_filter;  /**< Per-packet matching color_filter_t object */

  //nstime_t     abs_ts;       /**< Absolute timestamp */
  //nstime_t     shift_offset; /**< How much the abs_tm of the frame is shifted */
  //nstime_t     rel_ts;       /**< Relative timestamp (yes, it can be negative) */
  //nstime_t     del_dis_ts;   /**< Delta timestamp to previous displayed frame (yes, it can be negative) */
  //nstime_t     del_cap_ts;   /**< Delta timestamp to previous captured frame (yes, it can be negative) */
  gchar        *opt_comment; /**< NULL if not available */
} frame_data;
  typedef enum {
  AT_NONE,               /* no link-layer address */
  AT_ETHER,              /* MAC (Ethernet, 802.x, FDDI) address */
  AT_IPv4,               /* IPv4 */
  AT_IPv6,               /* IPv6 */
  AT_IPX,                /* IPX */
  AT_SNA,                /* SNA */
  AT_ATALK,              /* Appletalk DDP */
  AT_VINES,              /* Banyan Vines */
  AT_OSI,                /* OSI NSAP */
  AT_ARCNET,             /* ARCNET */
  AT_FC,                 /* Fibre Channel */
  AT_SS7PC,              /* SS7 Point Code */
  AT_STRINGZ,            /* null-terminated string */
  AT_EUI64,              /* IEEE EUI-64 */
  AT_URI,                /* URI/URL/URN */
  AT_TIPC,               /* TIPC Address Zone,Subnetwork,Processor */
  AT_IB,                 /* Infiniband GID/LID */
  AT_USB                 /* USB Device address
                          * (0xffffffff represents the host) */
} address_type;

typedef struct _address {
  address_type  type;		/* type of address */
  int           len;		/* length of address, in bytes */
  const void	*data;		/* pointer to address data */
  
    /* private */
    void         *priv;
} address;

typedef enum {
  PT_NONE,		/* no port number */
  PT_SCTP,		/* SCTP */
  PT_TCP,		/* TCP */
  PT_UDP,		/* UDP */
  PT_DCCP,		/* DCCP */
  PT_IPX,		/* IPX sockets */
  PT_NCP,		/* NCP connection */
  PT_EXCHG,		/* Fibre Channel exchange */
  PT_DDP,		/* DDP AppleTalk connection */
  PT_SBCCS,		/* FICON */
  PT_IDP,		/* XNS IDP sockets */
  PT_TIPC,		/* TIPC PORT */
  PT_USB,		/* USB endpoint 0xffff means the host */
  PT_I2C,
  PT_IBQP		/* Infiniband QP number */
} port_type;
typedef guint           (*GHashFunc)            (gconstpointer  key);

struct _GHashTable
{
  gint             size;
  gint             mod;
  guint            mask;
  gint             nnodes;
  gint             noccupied;  /* nnodes + tombstones */

  gpointer        *keys;
  guint           *hashes;
  gpointer        *values;

  GHashFunc        hash_func;
  //GEqualFunc       key_equal_func;
  gint             ref_count;
#ifndef G_DISABLE_ASSERT
  /*
   * Tracks the structure of the hash table, not its contents: is only
   * incremented when a node is added or removed (is not incremented
   * when the key or data of a node is modified).
   */
  int              version;
#endif
  //GDestroyNotify   key_destroy_func;
  //GDestroyNotify   value_destroy_func;
};
typedef struct _GHashTable GHashTable;
struct GString {
  gchar  *str;
  gsize len;
  gsize allocated_len;
};

typedef struct _packet_info {
  const char *current_proto;	/* name of protocol currently being dissected */
  //column_info *cinfo;		/* Column formatting information */
  frame_data *fd;
  union wtap_pseudo_header *pseudo_header;
  GSList *data_src;		/* Frame data sources */
  address dl_src;		/* link-layer source address */
  address dl_dst;		/* link-layer destination address */
  address net_src;		/* network-layer source address */
  address net_dst;		/* network-layer destination address */
  address src;			/* source address (net if present, DL otherwise )*/
  address dst;			/* destination address (net if present, DL otherwise )*/
  guint32 ethertype;		/* Ethernet Type Code, if this is an Ethernet packet */
  guint32 ipproto;		/* IP protocol, if this is an IP packet */
  guint32 ipxptype;		/* IPX packet type, if this is an IPX packet */
  guint32 mpls_label;		/* last mpls label in label stack, if this is a MPLS packet */
  //circuit_type ctype;		/* type of circuit, for protocols with a VC identifier */
  guint32 circuit_id;		/* circuit ID, for protocols with a VC identifier */
  const char *noreassembly_reason;  /* reason why reassembly wasn't done, if any */
  gboolean fragmented;		/* TRUE if the protocol is only a fragment */
  struct {
    guint32 in_error_pkt:1;	/* TRUE if we're inside an {ICMP,CLNP,...} error packet */
    guint32 in_gre_pkt:1;	/* TRUE if we're encapsulated inside a GRE packet */
  } flags;
  port_type ptype;		/* type of the following two port numbers */
  guint32 srcport;		/* source port */
  guint32 destport;		/* destination port */
  guint32 match_uint;           /* matched uint for calling subdissector from table */
  const char *match_string;	/* matched string for calling subdissector from table */
  guint16 can_desegment;	
  guint16 saved_can_desegment;	
  int desegment_offset;		/* offset to stuff needing desegmentation */
#define DESEGMENT_ONE_MORE_SEGMENT 0x0fffffff
#define DESEGMENT_UNTIL_FIN        0x0ffffffe
  guint32 desegment_len;	
  guint16 want_pdu_tracking;	
  guint32 bytes_until_next_pdu;


  int     iplen;                /* total length of IP packet */
  int     iphdrlen;             /* length of IP header */
  guint8  ip_ttl;               /* IP time to live */
  int	  p2p_dir;              
  guint16 oxid;                 /* next 2 fields reqd to identify fibre */
  guint16 rxid;                 /* channel conversations */
  guint8  r_ctl;                /* R_CTL field in Fibre Channel Protocol */
  guint8  sof_eof;              
  guint16 src_idx;              /* Source port index (Cisco MDS-specific) */
  guint16 dst_idx;              /* Dest port index (Cisco MDS-specific) */
  guint16 vsan;                 /* Fibre channel/Cisco MDS-specific */

  /* Extra data for DCERPC handling and tracking of context ids */
  guint16 dcectxid;             /* Context ID (DCERPC-specific) */
  int     dcetransporttype;     
  guint16 dcetransportsalt;	/* fid: if transporttype==DCE_CN_TRANSPORT_SMBPIPE */

#define DECRYPT_GSSAPI_NORMAL	1
#define DECRYPT_GSSAPI_DCE	2
  guint16 decrypt_gssapi_tvb;
  tvbuff_t *gssapi_wrap_tvb;
  tvbuff_t *gssapi_encrypted_tvb;
  tvbuff_t *gssapi_decrypted_tvb;
  gboolean gssapi_data_encrypted;

  guint32 ppid;  /* SCTP PPI of current DATA chunk */
/* This is a valid PPID, but we use it to mark the end of the list */
#define LAST_PPID 0xffffffff
  guint32 ppids[MAX_NUMBER_OF_PPIDS]; 
 /* void    *private_data;*/	/* pointer to data passed from one dissector to another */
  GHashTable *private_table;	/* a hash table passed from one dissector to another */
  ///* TODO: Use emem_strbuf_t instead */
  GString *layer_names; 	/* layers of each protocol */
  guint16 link_number;
  guint8  annex_a_used;
  guint16 profinet_type; 	/* the type of PROFINET packet (0: not a PROFINET packet) */
  void *profinet_conv; 	    /* the PROFINET conversation data (NULL: not a PROFINET packet) */
  void *usb_conv_info;
  void *tcp_tree;		/* proto_tree for the tcp layer */

  const char *dcerpc_procedure_name;	/* Used by PIDL to store the name of the current dcerpc procedure */

  struct _sccp_msg_info_t* sccp_info;
  guint16 clnp_srcref;      /* clnp/cotp source reference (can't use srcport, this would confuse tpkt) */
  guint16 clnp_dstref;      /* clnp/cotp destination reference (can't use dstport, this would confuse tpkt) */

  guint16 zbee_cluster_id;  /* ZigBee cluster ID, an application-specific message identifier that
                             * happens to be included in the transport (APS) layer header.
                             */
  guint8 zbee_stack_vers;   
  int link_dir;		    /* 3GPP messages are sometime different UP link(UL) or Downlink(DL) */
  GSList* dependent_frames;	/* A list of frames which this one depends on */
} packet_info;
typedef struct _asn1_ctx_t {
  guint32 signature;
  asn1_enc_e encoding;
  gboolean aligned;
 packet_info *pinfo;
  //proto_item *created_item;
  struct _asn1_stack_frame_t *stack;
  void *value_ptr;
  void *private_data;
  struct {
    int hf_index;
    gboolean data_value_descr_present;
    gboolean direct_ref_present;
    gboolean indirect_ref_present;
    tvbuff_t *data_value_descriptor;
    const char *direct_reference;
    gint32 indirect_reference;
    gint encoding;  
      /* 
         0 : single-ASN1-type, 
         1 : octet-aligned, 
         2 : arbitrary 
      */
    tvbuff_t *single_asn1_type;
    tvbuff_t *octet_aligned;
    tvbuff_t *arbitrary;
    union {
      struct {
        int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* , int hf_index );
      } ber;
      struct {
        int (*type_cb)(tvbuff_t*, int, struct _asn1_ctx_t*,  int);
      } per;
    } u;
  } external;
  struct {
    int hf_index;
    gboolean data_value_descr_present;
    tvbuff_t *data_value_descriptor;
    gint identification;
      /* 
         0 : syntaxes, 
         1 : syntax, 
         2 : presentation-context-id,
         3 : context-negotiation,
         4 : transfer-syntax,
         5 : fixed
      */
    gint32 presentation_context_id;
    const char *abstract_syntax;
    const char *transfer_syntax;
    tvbuff_t *data_value;
    union {
      struct {
        int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* , int hf_index ); 
      } ber;
      struct {
        int (*type_cb)(tvbuff_t*, int, struct _asn1_ctx_t*, int);
      } per;
    } u;
  } embedded_pdv;
  struct _rose_ctx_t *rose_ctx;
} asn1_ctx_t;




typedef int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, int hf_index);
typedef struct _ber_sequence_t {
	const int *p_id;
	gint8	ber_class;
	gint32	tag;
	guint32	flags;
	ber_callback	func;
} ber_sequence_t;
struct _protocol;
#define GUINT_TO_POINTER(u) ((gpointer) (gulong) (u))
/** Structure for information about a protocol */











typedef proto_node proto_item;


typedef struct _gsm_map_tap_rec_t {
    gboolean		invoke;
    guint8		opr_code_idx;
    guint16		size;
} gsm_map_tap_rec_t;

typedef struct _tap_packet_t {
	int tap_id;
	//packet_info *pinfo;
	const void *tap_specific_data;
} tap_packet_t;

typedef struct _value_string {
  guint32  value;
  const gchar   *strptr;
}value_string;

//typedef struct stru *pstru;
typedef struct _GSList {
  gpointer data;
  GSList *next;
}GSList;


typedef int (*ber_type_fn)(gboolean, tvbuff_t*, int, asn1_ctx_t *actx, int);
typedef int (* dissect_function_t)( gboolean,
				    tvbuff_t *,
				    int ,
					asn1_ctx_t *,
				    //proto_tree *,
				    int);

typedef struct _ber_choice_t {
	guint32	value;
	const int *p_id;
	gint8	ber_class;
	gint32	tag;
	guint32	flags;
	ber_callback	func;
} ber_choice_t;


struct _protocol {
	const char *name;         /* long description */
	const char *short_name;   /* short description */
	const char *filter_name;  /* name of this protocol in filters */
	int         proto_id;     /* field ID for this protocol */
	//GList      *fields;       /* fields for this protocol */
	//GList      *last_field;   /* pointer to end of list of fields */
	gboolean    is_enabled;   /* TRUE if protocol is enabled */
	gboolean    can_toggle;   /* TRUE if is_enabled can be changed */
	gboolean    is_private;   /* TRUE is protocol is private */
};
typedef struct _protocol protocol_t;
typedef void (dissector_t)(tvbuff_t *, packet_info */*, proto_tree **/);
typedef int (*new_dissector_t)(tvbuff_t *, packet_info */**//*, proto_tree **/);
struct dissector_handle {
	const char	*name;		/* dissector name */
	gboolean	is_new;		/* TRUE if new-style dissector */
	union {
		dissector_t	old;
		new_dissector_t	NEW;
	} dissector;
	protocol_t	*protocol;
};

struct _value_string_ext;
typedef const value_string *(*_value_string_match2_t)(const guint32, const struct _value_string_ext *);
typedef struct _value_string_ext {
  _value_string_match2_t _vs_match2;
  guint32 _vs_first_value;    /* first value of the value_string array       */
  guint   _vs_num_entries;    /* number of entries in the value_string array */
                              /*  (excluding final {0, NULL})                */
  const value_string *_vs_p;  /* the value string array address              */
  const gchar *_vs_name;      /* vse "Name" (for error messages)             */
} value_string_ext;

/** Struct for boolean enumerations */
typedef struct true_false_string {
        const char      *true_string;	/**< The string presented when true  */
        const char      *false_string;	/**< The string presented when false */
} true_false_string;

typedef struct _emem_chunk_t {
	struct _emem_chunk_t *next;
	char		*buf;
	unsigned int	amount_free_init;
	unsigned int	amount_free;
	unsigned int	free_offset_init;
	unsigned int	free_offset;
	void		*canary_last;
} emem_chunk_t;
typedef struct _emem_header_t {
	emem_chunk_t *free_list;
	emem_chunk_t *used_list;

	//emem_tree_t *trees;		/* only used by se_mem allocator */

	guint8 canary[EMEM_CANARY_DATA_SIZE];
	void *(*memory_alloc)(size_t size, struct _emem_header_t *);

	/*
	 * Tools like Valgrind and ElectricFence don't work well with memchunks.
	 * Export the following environment variables to make {ep|se}_alloc() allocate each
	 * object individually.
	 *
	 * WIRESHARK_DEBUG_EP_NO_CHUNKS
	 * WIRESHARK_DEBUG_SE_NO_CHUNKS
	 */
	gboolean debug_use_chunks;

	/* Do we want to use canaries?
	 * Export the following environment variables to disable/enable canaries
	 *
	 * WIRESHARK_DEBUG_EP_NO_CANARY
	 * For SE memory use of canary is default off as the memory overhead
	 * is considerable.
	 * WIRESHARK_DEBUG_SE_USE_CANARY
	 */
	gboolean debug_use_canary;

	/*  Do we want to verify no one is using a pointer to an ep_ or se_
	 *  allocated thing where they shouldn't be?
	 *
	 * Export WIRESHARK_EP_VERIFY_POINTERS or WIRESHARK_SE_VERIFY_POINTERS
	 * to turn this on.
	 */
	gboolean debug_verify_pointers;

} emem_header_t;

typedef struct _asn_namedbit {
	guint32 bit;
	int *p_id;
	gint32 gb0;  /* the 1st bit of "bit group", -1 = the 1st bit of current byte */
	gint32 gb1;  /* last bit of "bit group", -1 = last bit of current byte */
	const gchar *tstr;  /* true string */
	const gchar *fstr;  /* false string */
} asn_namedbit;

struct tcap_private_t {
  gboolean acv; /* Is the Application Context Version present */
  void * oid;
  guint32 session_id;
  void * context;
  gchar *TransactionID_str;
};

struct _oid_bit_t {
	guint offset;
	int hfid;
};

typedef struct _oid_bits_info_t {
	guint num;
	gint ett;
	struct _oid_bit_t* data;
} oid_bits_info_t;

typedef enum _oid_key_type_t {
	OID_KEY_TYPE_WRONG,
	OID_KEY_TYPE_INTEGER,
	OID_KEY_TYPE_OID,
	OID_KEY_TYPE_STRING,
	OID_KEY_TYPE_BYTES,
	OID_KEY_TYPE_NSAP,
	OID_KEY_TYPE_IPADDR,
	OID_KEY_TYPE_IMPLIED_OID,
	OID_KEY_TYPE_IMPLIED_STRING,
	OID_KEY_TYPE_IMPLIED_BYTES,
	OID_KEY_TYPE_ETHER
} oid_key_type_t;

typedef struct _oid_value_type_t {
	enum ftenum ft_type;
	int display;
	gint8 ber_class;
	gint32 ber_tag;
	int min_len;
	int max_len;
	oid_key_type_t keytype;
	int keysize;
} oid_value_type_t;

typedef enum _oid_kind_t {
	OID_KIND_UNKNOWN = 0,
	OID_KIND_NODE,
	OID_KIND_SCALAR,
	OID_KIND_TABLE,
	OID_KIND_ROW,
	OID_KIND_COLUMN,
	OID_KIND_NOTIFICATION,
	OID_KIND_GROUP,
	OID_KIND_COMPLIANCE,
	OID_KIND_CAPABILITIES
} oid_kind_t;

typedef struct _oid_key_t {
	char* name;
	guint32 num_subids;
	oid_key_type_t key_type;
	int hfid;
	enum ftenum ft_type;
	int display;
	struct _oid_key_t* next;
} oid_key_t;

typedef struct _oid_info_t {
	guint32 subid;
	char* name;
	oid_kind_t kind;
	void* children; /**< an emem_tree_t* */
	const oid_value_type_t* value_type;
	int value_hfid;
	oid_key_t* key;
	oid_bits_info_t* bits;
	struct _oid_info_t* parent;
} oid_info_t;

typedef enum {
    HF_REF_TYPE_NONE,       /**< Field is not referenced */
    HF_REF_TYPE_INDIRECT,   /**< Field is indirectly referenced (only applicable for FT_PROTOCOL) via. its child */
    HF_REF_TYPE_DIRECT      /**< Field is directly referenced */
} hf_ref_type;
typedef struct _header_field_info header_field_info;
struct _header_field_info {
	/* ---------- set by dissector --------- */
	const char		*name;           /**< [FIELDNAME] full name of this field */
	const char		*abbrev;         /**< [FIELDABBREV] abbreviated name of this field */
	enum ftenum		 type;           /**< [FIELDTYPE] field type, one of FT_ (from ftypes.h) */
	int			 display;        /**< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask */
	const void		*strings;        /**< [FIELDCONVERT] value_string, range_string or true_false_string,
				                      typically converted by VALS(), RVALS() or TFS().
				                      If this is an FT_PROTOCOL then it points to the
				                      associated protocol_t structure */
	guint32			 bitmask;        /**< [BITMASK] bitmask of interesting bits */
	const char		*blurb;          /**< [FIELDDESCR] Brief description of field */

	/* ------- set by proto routines (prefilled by HFILL macro, see below) ------ */
	int					 id;             /**< Field ID */
	int					 parent;         /**< parent protocol tree */
	hf_ref_type			 ref_type;       /**< is this field referenced by a filter */
	int					 bitshift;       /**< bits to shift */
	header_field_info	*same_name_next; /**< Link to next hfinfo with same abbrev */
	header_field_info	*same_name_prev; /**< Link to previous hfinfo with same abbrev */
};

static const oid_value_type_t unknown_type =    { FT_BYTES,  BASE_NONE, BER_CLASS_ANY, BER_TAG_ANY,             0,  -1, OID_KEY_TYPE_WRONG,   0};
static oid_info_t oid_root = { 0, NULL, OID_KIND_UNKNOWN, NULL, &unknown_type, -2, NULL, NULL, NULL};

struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;
static dissector_handle_t dtap_handle;

static const value_string gsm_map_opr_code_strings[] = {

	{ 85, "sendRoutingInfoForLCS" },
	{ 83, "provideSubscriberLocation" },
	{ 86, "subscriberLocationReport" },

//* --- Module MAP-Group-Call-Operations --- --- ---                           */

	{ 39, "prepareGroupCall" },
	{ 40, "sendGroupCallEndSignal" },
	{ 41, "processGroupCallSignalling" },
	{ 42, "forwardGroupCallSignalling" },
	{ 84, "sendGroupCallInfo" },

//* --- Module MAP-ShortMessageServiceOperations --- --- ---                   */

	{ 45, "sendRoutingInfoForSM" },
	{ 46, "mo_ForwardSM" },
	{ 44, "mt_ForwardSM" },
	{ 47, "reportSM_DeliveryStatus" },
	{ 64, "alertServiceCentre" },
	{ 63, "informServiceCentre" },
	{ 66, "readyForSM" },
	{ 21, "mt_ForwardSM_VGCS" },

//* --- Module MAP-SupplementaryServiceOperations --- --- ---                  */

	{ 10, "registerSS" },
	{ 11, "eraseSS" },
	{ 12, "activateSS" },
	{ 13, "deactivateSS" },
	{ 14, "interrogateSS" },
	{ 59, "processUnstructuredSS_Request" },
	{ 60, "unstructuredSS_Request" },
	{ 61, "unstructuredSS_Notify" },
	{ 17, "registerPassword" },
	{ 18, "getPassword" },
	{ 72, "ss_InvocationNotification" },
	{ 76, "registerCC_Entry" },
	{ 77, "eraseCC_Entry" },

//* --- Module MAP-CallHandlingOperations --- --- ---                          */

	{ 22, "sendRoutingInfo" },
	{ 4, "provideRoamingNumber" },
	{ 6, "resumeCallHandling" },
	{ 73, "setReportingState" },
	{ 74, "statusReport" },
	{ 75, "remoteUserFree" },
	{ 87, "ist_Alert" },
	{ 88, "ist_Command" },
	{ 20, "releaseResources" },

//* --- Module MAP-OperationAndMaintenanceOperations --- --- ---               */

	{ 50, "activateTraceMode" },
	{ 51, "deactivateTraceMode" },
	{ 58, "sendIMSI" },

//* --- Module MAP-MobileServiceOperations --- --- ---                         */

	{ 2, "updateLocation" },
	{ 3, "cancelLocation" },
	{ 67, "purgeMS" },
	{ 55, "sendIdentification" },
	{ 23, "updateGprsLocation" },
	{ 70, "provideSubscriberInfo" },
	{ 71, "anyTimeInterrogation" },
	{ 62, "anyTimeSubscriptionInterrogation" },
	{ 65, "anyTimeModification" },
	{ 5, "noteSubscriberDataModified" },
	{ 68, "prepareHandover" },
	{ 29, "sendEndSignal" },
	{ 33, "processAccessSignalling" },
	{ 34, "forwardAccessSignalling" },
	{ 69, "prepareSubsequentHandover" },
	{ 56, "sendAuthenticationInfo" },
	{ 15, "authenticationFailureReport" },
	{ 43, "checkIMEI" },
	{ 7, "insertSubscriberData" },
	{ 8, "deleteSubscriberData" },
	{ 37, "reset" },
	{ 38, "forwardCheckSS_Indication" },
	{ 57, "restoreData" },
	{ 24, "sendRoutingInfoForGprs" },
	{ 25, "failureReport" },
	{ 26, "noteMsPresentForGprs" },
	{ 89, "noteMM_Event" },

	{ 19, "processUnstructuredSS_Data" },
	{ 16, "notifySS" },
	{ 125, "forwardChargeAdvice" },
	{ 120, "forwardCUG_Info" },
	{ 124, "buildMPTY" },
	{ 123, "holdMPTY" },
	{ 122, "retrieveMPTY" },
	{ 121, "splitMPTY" },
	{ 126, "explicitCT" },
	{ 119, "accessRegisterCCEntry" },
	{ 117, "callDeflection" },
	{ 118, "userUserService" },
	{ 116, "lcs_LocationNotification" },
	{ 115, "lcs_MOLR" },
	{ 114, "lcs_AreaEventRequest" },
	{ 113, "lcs_AreaEventReport" },
	{ 112, "lcs_AreaEventCancellation" },
	{ 111, "lcs_PeriodicLocationRequest" },
	{ 110, "lcs_LocationUpdate" },
	{ 109, "lcs_PeriodicLocationCancellation" },

    { 0, NULL }
};

typedef enum ftenum ftenum_t;
struct dissector_table {
	GHashTable	*hash_table;
	//GSList		*dissector_handles;
	const char	*ui_name;
	ftenum_t	type;
	int		base;
};
struct dissector_table;
typedef struct dissector_table *dissector_table_t;
static dissector_table_t sms_dissector_table;	/* SMS TPDU */

//extern const value_string nlpid_vals[];

typedef struct _sccp_msg_info_t {
	guint framenum;
	guint offset;
	guint type;
	
	union {
		struct {
			gchar* label;
			gchar* comment;
			struct _sccp_assoc_info_t* assoc;
			struct _sccp_msg_info_t* next;
		} co;
		struct {
			guint8* calling_gt;
			guint calling_ssn;
			guint8* called_gt;
			guint called_ssn;
		} ud;
	} data;
} sccp_msg_info_t;

typedef struct _range_string {
  guint32        value_min;
  guint32        value_max;
  const gchar   *strptr;
} range_string;

/* Initialize the protocol and registered fields */
static int proto_gsm_map = -1;
static int proto_gsm_map_dialogue = -1;

static int hf_gsm_map_old_Component_PDU = -1;
static int hf_gsm_map_getPassword = -1;
static int hf_gsm_map_currentPassword = -1;
static int hf_gsm_map_extension = -1;
static int hf_gsm_map_nature_of_number = -1;
static int hf_gsm_map_number_plan = -1;
static int hf_gsm_map_isdn_address_digits = -1;
static int hf_gsm_map_address_digits = -1;
static int hf_gsm_map_servicecentreaddress_digits = -1;
static int hf_gsm_map_imsi_digits = -1;
static int hf_gsm_map_TBCD_digits = -1;
static int hf_gsm_map_Ss_Status_unused = -1;
static int hf_gsm_map_Ss_Status_q_bit = -1;
static int hf_gsm_map_Ss_Status_p_bit = -1;
static int hf_gsm_map_Ss_Status_r_bit = -1;
static int hf_gsm_map_Ss_Status_a_bit = -1;
static int hf_gsm_map_notification_to_forwarding_party = -1;
static int hf_gsm_map_redirecting_presentation = -1;
static int hf_gsm_map_notification_to_calling_party = -1;
static int hf_gsm_map_forwarding_reason = -1;
static int hf_gsm_map_pdp_type_org = -1;
static int hf_gsm_map_etsi_pdp_type_number = -1;
static int hf_gsm_map_ietf_pdp_type_number = -1;
static int hf_gsm_map_ext_qos_subscribed_pri = -1;

static int hf_gsm_map_qos_traffic_cls = -1;
static int hf_gsm_map_qos_del_order = -1;
static int hf_gsm_map_qos_del_of_err_sdu = -1;
static int hf_gsm_map_qos_ber = -1;
static int hf_gsm_map_qos_sdu_err_rat = -1;
static int hf_gsm_map_qos_traff_hdl_pri = -1;
static int hf_gsm_map_qos_max_sdu = -1;
static int hf_gsm_map_max_brate_ulink = -1;
static int hf_gsm_map_max_brate_dlink = -1;
static int hf_gsm_map_qos_transfer_delay = -1;
static int hf_gsm_map_guaranteed_max_brate_ulink = -1;
static int hf_gsm_map_guaranteed_max_brate_dlink = -1;
static int hf_gsm_map_GSNAddress_IPv4 = -1;
static int hf_gsm_map_GSNAddress_IPv6 = -1;
static int hf_gsm_map_ranap_service_Handover = -1;
static int hf_gsm_map_IntegrityProtectionInformation = -1;
static int hf_gsm_map_EncryptionInformation = -1;
static int hf_gsm_map_PlmnContainer_PDU = -1;
static int hf_gsm_map_ss_SS_UserData = -1;
static int hf_gsm_map_cbs_coding_grp = -1;
static int hf_gsm_map_cbs_coding_grp0_lang = -1;
static int hf_gsm_map_cbs_coding_grp1_lang = -1;
static int hf_gsm_map_cbs_coding_grp2_lang = -1;
static int hf_gsm_map_cbs_coding_grp3_lang = -1;
static int hf_gsm_map_cbs_coding_grp4_7_comp = -1;
static int hf_gsm_map_cbs_coding_grp4_7_class_ind = -1;
static int hf_gsm_map_cbs_coding_grp4_7_char_set = -1;
static int hf_gsm_map_cbs_coding_grp4_7_class = -1;
static int hf_gsm_map_cbs_coding_grp15_mess_code = -1;
static int hf_gsm_map_cbs_coding_grp15_class = -1;
static int hf_gsm_map_tmsi = -1;
static int hf_gsm_map_ie_tag = -1;
static int hf_gsm_map_len = -1;
static int hf_gsm_map_disc_par = -1;
static int hf_gsm_map_dlci = -1;
static int hf_gsm_apn_str = -1;
static int hf_gsm_map_locationnumber_odd_even = -1;
static int hf_gsm_map_locationnumber_nai = -1;
static int hf_gsm_map_locationnumber_inn = -1;
static int hf_gsm_map_locationnumber_npi = -1; 
static int hf_gsm_map_locationnumber_apri = -1;
static int hf_gsm_map_locationnumber_screening_ind = -1;
static int hf_gsm_map_locationnumber_digits = -1;


/*--- Included file: packet-gsm_map-hf.c ---*/
////#line 1 "../../asn1/gsm_map/packet-gsm_map-hf.c"

/* --- Module MAP-ExtensionDataTypes --- --- ---                              */

static int hf_gsm_map_privateExtensionList = -1;  /* PrivateExtensionList */
static int hf_gsm_map_pcs_Extensions = -1;        /* PCS_Extensions */
static int hf_gsm_map_slr_Arg_PCS_Extensions = -1;  /* SLR_Arg_PCS_Extensions */
static int hf_gsm_map_PrivateExtensionList_item = -1;  /* PrivateExtension */
static int hf_gsm_map_extId = -1;                 /* T_extId */
static int hf_gsm_map_extType = -1;               /* T_extType */
static int hf_gsm_map_na_ESRK_Request = -1;       /* NULL */

/* --- Module MAP-CommonDataTypes --- --- ---                                 */

static int hf_gsm_map_gsm_map_ISDN_AddressString_PDU = -1;  /* ISDN_AddressString */
static int hf_gsm_map_protocolId = -1;            /* ProtocolId */
static int hf_gsm_map_signalInfo = -1;            /* SignalInfo */
static int hf_gsm_map_extensionContainer = -1;    /* ExtensionContainer */
static int hf_gsm_map_ext_ProtocolId = -1;        /* Ext_ProtocolId */
static int hf_gsm_map_accessNetworkProtocolId = -1;  /* AccessNetworkProtocolId */
static int hf_gsm_map_signalInfo_01 = -1;         /* LongSignalInfo */
static int hf_gsm_map_imsi = -1;                  /* IMSI */
static int hf_gsm_map_imsi_WithLMSI = -1;         /* IMSI_WithLMSI */
static int hf_gsm_map_lmsi = -1;                  /* LMSI */
static int hf_gsm_map_HLR_List_item = -1;         /* HLR_Id */
static int hf_gsm_map_naea_PreferredCIC = -1;     /* NAEA_CIC */
static int hf_gsm_map_msisdn = -1;                /* ISDN_AddressString */
static int hf_gsm_map_externalAddress = -1;       /* ISDN_AddressString */
static int hf_gsm_map_cellGlobalIdOrServiceAreaIdFixedLength = -1;  /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_gsm_map_laiFixedLength = -1;        /* LAIFixedLength */
static int hf_gsm_map_bearerService = -1;         /* BearerServiceCode */
static int hf_gsm_map_teleservice = -1;           /* TeleserviceCode */
static int hf_gsm_map_ext_BearerService = -1;     /* Ext_BearerServiceCode */
static int hf_gsm_map_ext_Teleservice = -1;       /* Ext_TeleserviceCode */
static int hf_gsm_map_maximumentitledPriority = -1;  /* EMLPP_Priority */
static int hf_gsm_map_defaultPriority = -1;       /* EMLPP_Priority */
static int hf_gsm_map_ss_Code = -1;               /* SS_Code */
static int hf_gsm_map_ss_Status = -1;             /* Ext_SS_Status */
static int hf_gsm_map_nbrSB = -1;                 /* MaxMC_Bearers */
static int hf_gsm_map_nbrUser = -1;               /* MC_Bearers */

/* --- Module MAP-SS-DataTypes --- --- ---                                    */

static int hf_gsm_map_ss_ss_Code = -1;            /* SS_Code */
static int hf_gsm_map_ss_basicService = -1;       /* BasicServiceCode */
static int hf_gsm_map_ss_forwardedToNumber = -1;  /* AddressString */
static int hf_gsm_map_ss_forwardedToSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_map_ss_noReplyConditionTime = -1;  /* NoReplyConditionTime */
static int hf_gsm_map_ss_defaultPriority = -1;    /* EMLPP_Priority */
static int hf_gsm_map_ss_nbrUser = -1;            /* MC_Bearers */
static int hf_gsm_map_ss_longFTN_Supported = -1;  /* NULL */
static int hf_gsm_map_ss_forwardingInfo = -1;     /* ForwardingInfo */
static int hf_gsm_map_ss_callBarringInfo = -1;    /* CallBarringInfo */
static int hf_gsm_map_ss_ss_Data = -1;            /* SS_Data */
static int hf_gsm_map_ss_forwardingFeatureList = -1;  /* ForwardingFeatureList */
static int hf_gsm_map_ss_ForwardingFeatureList_item = -1;  /* ForwardingFeature */
static int hf_gsm_map_ss_ss_Status = -1;          /* SS_Status */
static int hf_gsm_map_ss_forwardedToNumber_01 = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ss_forwardingOptions = -1;  /* ForwardingOptions */
static int hf_gsm_map_ss_longForwardedToNumber = -1;  /* FTN_AddressString */
static int hf_gsm_map_ss_callBarringFeatureList = -1;  /* CallBarringFeatureList */
static int hf_gsm_map_ss_CallBarringFeatureList_item = -1;  /* CallBarringFeature */
static int hf_gsm_map_ss_ss_SubscriptionOption = -1;  /* SS_SubscriptionOption */
static int hf_gsm_map_ss_basicServiceGroupList = -1;  /* BasicServiceGroupList */
static int hf_gsm_map_ss_cliRestrictionOption = -1;  /* CliRestrictionOption */
static int hf_gsm_map_ss_overrideCategory = -1;   /* OverrideCategory */
static int hf_gsm_map_ss_maximumEntitledPriority = -1;  /* EMLPP_Priority */
static int hf_gsm_map_ss_ccbs_FeatureList = -1;   /* CCBS_FeatureList */
static int hf_gsm_map_ss_nbrSB = -1;              /* MaxMC_Bearers */
static int hf_gsm_map_ss_nbrSN = -1;              /* MC_Bearers */
static int hf_gsm_map_ss_CCBS_FeatureList_item = -1;  /* CCBS_Feature */
static int hf_gsm_map_ss_ccbs_Index = -1;         /* CCBS_Index */
static int hf_gsm_map_ss_b_subscriberNumber = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ss_b_subscriberSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_map_ss_basicServiceGroup = -1;  /* BasicServiceCode */
static int hf_gsm_map_ss_genericServiceInfo = -1;  /* GenericServiceInfo */
static int hf_gsm_map_ss_ussd_DataCodingScheme = -1;  /* USSD_DataCodingScheme */
static int hf_gsm_map_ss_ussd_String = -1;        /* USSD_String */
static int hf_gsm_map_ss_alertingPattern = -1;    /* AlertingPattern */
static int hf_gsm_map_ss_msisdn = -1;             /* ISDN_AddressString */
static int hf_gsm_map_ss_SS_List_item = -1;       /* SS_Code */
static int hf_gsm_map_ss_BasicServiceGroupList_item = -1;  /* BasicServiceCode */
static int hf_gsm_map_ss_imsi = -1;               /* IMSI */
static int hf_gsm_map_ss_ss_Event = -1;           /* SS_Code */
static int hf_gsm_map_ss_ss_EventSpecification = -1;  /* SS_EventSpecification */
static int hf_gsm_map_ss_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_ss_ccbs_RequestState = -1;  /* CCBS_RequestState */
static int hf_gsm_map_ss_SS_EventSpecification_item = -1;  /* AddressString */
static int hf_gsm_map_ss_ccbs_Data = -1;          /* CCBS_Data */
static int hf_gsm_map_ss_ccbs_Feature = -1;       /* CCBS_Feature */
static int hf_gsm_map_ss_translatedB_Number = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ss_serviceIndicator = -1;   /* ServiceIndicator */
static int hf_gsm_map_ss_callInfo = -1;           /* ExternalSignalInfo */
static int hf_gsm_map_ss_networkSignalInfo = -1;  /* ExternalSignalInfo */
/* named bits */
static int hf_gsm_map_ss_ServiceIndicator_clir_invoked = -1;
static int hf_gsm_map_ss_ServiceIndicator_camel_invoked = -1;

/* --- Module MAP-ER-DataTypes --- --- ---                                    */

static int hf_gsm_map_er_roamingNotAllowedCause = -1;  /* RoamingNotAllowedCause */
static int hf_gsm_map_er_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_er_additionalRoamingNotAllowedCause = -1;  /* AdditionalRoamingNotAllowedCause */
static int hf_gsm_map_er_callBarringCause = -1;   /* CallBarringCause */
static int hf_gsm_map_er_extensibleCallBarredParam = -1;  /* ExtensibleCallBarredParam */
static int hf_gsm_map_er_unauthorisedMessageOriginator = -1;  /* NULL */
static int hf_gsm_map_er_cug_RejectCause = -1;    /* CUG_RejectCause */
static int hf_gsm_map_er_ss_Code = -1;            /* SS_Code */
static int hf_gsm_map_er_basicService = -1;       /* BasicServiceCode */
static int hf_gsm_map_er_ss_Status = -1;          /* SS_Status */
static int hf_gsm_map_er_sm_EnumeratedDeliveryFailureCause = -1;  /* SM_EnumeratedDeliveryFailureCause */
static int hf_gsm_map_er_diagnosticInfo = -1;     /* SignalInfo */
static int hf_gsm_map_er_absentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_er_additionalAbsentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_er_networkResource = -1;    /* NetworkResource */
static int hf_gsm_map_er_extensibleSystemFailureParam = -1;  /* ExtensibleSystemFailureParam */
static int hf_gsm_map_er_additionalNetworkResource = -1;  /* AdditionalNetworkResource */
static int hf_gsm_map_er_failureCauseParam = -1;  /* FailureCauseParam */
static int hf_gsm_map_er_shapeOfLocationEstimateNotSupported = -1;  /* NULL */
static int hf_gsm_map_er_neededLcsCapabilityNotSupportedInServingNode = -1;  /* NULL */
static int hf_gsm_map_er_unknownSubscriberDiagnostic = -1;  /* UnknownSubscriberDiagnostic */
static int hf_gsm_map_er_absentSubscriberReason = -1;  /* AbsentSubscriberReason */
static int hf_gsm_map_er_ccbs_Possible = -1;      /* NULL */
static int hf_gsm_map_er_ccbs_Busy = -1;          /* NULL */
static int hf_gsm_map_er_gprsConnectionSuspended = -1;  /* NULL */
static int hf_gsm_map_er_unauthorizedLCSClient_Diagnostic = -1;  /* UnauthorizedLCSClient_Diagnostic */
static int hf_gsm_map_er_positionMethodFailure_Diagnostic = -1;  /* PositionMethodFailure_Diagnostic */

/* --- Module MAP-SM-DataTypes --- --- ---                                    */

static int hf_gsm_map_sm_msisdn = -1;             /* ISDN_AddressString */
static int hf_gsm_map_sm_sm_RP_PRI = -1;          /* BOOLEAN */
static int hf_gsm_map_sm_serviceCentreAddress = -1;  /* AddressString */
static int hf_gsm_map_sm_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_sm_gprsSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_sm_RP_MTI = -1;          /* SM_RP_MTI */
static int hf_gsm_map_sm_sm_RP_SMEA = -1;         /* SM_RP_SMEA */
static int hf_gsm_map_sm_sm_deliveryNotIntended = -1;  /* SM_DeliveryNotIntended */
static int hf_gsm_map_sm_ip_sm_gwGuidanceIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_imsi = -1;               /* IMSI */
static int hf_gsm_map_sm_locationInfoWithLMSI = -1;  /* LocationInfoWithLMSI */
static int hf_gsm_map_sm_ip_sm_gwGuidance = -1;   /* IP_SM_GW_Guidance */
static int hf_gsm_map_sm_minimumDeliveryTimeValue = -1;  /* SM_DeliveryTimerValue */
static int hf_gsm_map_sm_recommendedDeliveryTimeValue = -1;  /* SM_DeliveryTimerValue */
static int hf_gsm_map_sm_networkNode_Number = -1;  /* ISDN_AddressString */
static int hf_gsm_map_sm_lmsi = -1;               /* LMSI */
static int hf_gsm_map_sm_gprsNodeIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_additional_Number = -1;  /* Additional_Number */
static int hf_gsm_map_sm_msc_Number = -1;         /* ISDN_AddressString */
static int hf_gsm_map_sm_sgsn_Number = -1;        /* ISDN_AddressString */
static int hf_gsm_map_sm_sm_RP_DA = -1;           /* SM_RP_DA */
static int hf_gsm_map_sm_sm_RP_OA = -1;           /* SM_RP_OA */
static int hf_gsm_map_sm_sm_RP_UI = -1;           /* SignalInfo */
static int hf_gsm_map_sm_moreMessagesToSend = -1;  /* NULL */
static int hf_gsm_map_sm_smDeliveryTimer = -1;    /* SM_DeliveryTimerValue */
static int hf_gsm_map_sm_smDeliveryStartTime = -1;  /* Time */
static int hf_gsm_map_sm_imsi_01 = -1;            /* T_imsi */
static int hf_gsm_map_sm_lmsi_01 = -1;            /* T_lmsi */
static int hf_gsm_map_sm_serviceCentreAddressDA = -1;  /* T_serviceCentreAddressDA */
static int hf_gsm_map_sm_noSM_RP_DA = -1;         /* NULL */
static int hf_gsm_map_sm_msisdn_01 = -1;          /* T_msisdn */
static int hf_gsm_map_sm_serviceCentreAddressOA = -1;  /* T_serviceCentreAddressOA */
static int hf_gsm_map_sm_noSM_RP_OA = -1;         /* NULL */
static int hf_gsm_map_sm_sm_DeliveryOutcome = -1;  /* SM_DeliveryOutcome */
static int hf_gsm_map_sm_absentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_sm_deliveryOutcomeIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_additionalSM_DeliveryOutcome = -1;  /* SM_DeliveryOutcome */
static int hf_gsm_map_sm_additionalAbsentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_sm_ip_sm_gw_Indicator = -1;  /* NULL */
static int hf_gsm_map_sm_ip_sm_gw_sm_deliveryOutcome = -1;  /* SM_DeliveryOutcome */
static int hf_gsm_map_sm_ip_sm_gw_absentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_sm_storedMSISDN = -1;       /* ISDN_AddressString */
static int hf_gsm_map_sm_mw_Status = -1;          /* MW_Status */
static int hf_gsm_map_sm_alertReason = -1;        /* AlertReason */
static int hf_gsm_map_sm_alertReasonIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_additionalAlertReasonIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_asciCallReference = -1;  /* ASCI_CallReference */
static int hf_gsm_map_sm_dispatcherList = -1;     /* DispatcherList */
static int hf_gsm_map_sm_ongoingCall = -1;        /* NULL */
static int hf_gsm_map_sm_DispatcherList_item = -1;  /* ISDN_AddressString */
/* named bits */
static int hf_gsm_map_sm_MW_Status_sc_AddressNotIncluded = -1;
static int hf_gsm_map_sm_MW_Status_mnrf_Set = -1;
static int hf_gsm_map_sm_MW_Status_mcef_Set = -1;
static int hf_gsm_map_sm_MW_Status_mnrg_Set = -1;

/* --- Module MAP-OM-DataTypes --- --- ---                                    */

static int hf_gsm_map_om_imsi = -1;               /* IMSI */
static int hf_gsm_map_om_traceReference = -1;     /* TraceReference */
static int hf_gsm_map_om_traceType = -1;          /* TraceType */
static int hf_gsm_map_om_omc_Id = -1;             /* AddressString */
static int hf_gsm_map_om_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_om_traceReference2 = -1;    /* TraceReference2 */
static int hf_gsm_map_om_traceDepthList = -1;     /* TraceDepthList */
static int hf_gsm_map_om_traceNE_TypeList = -1;   /* TraceNE_TypeList */
static int hf_gsm_map_om_traceInterfaceList = -1;  /* TraceInterfaceList */
static int hf_gsm_map_om_traceEventList = -1;     /* TraceEventList */
static int hf_gsm_map_om_traceCollectionEntity = -1;  /* GSN_Address */
static int hf_gsm_map_om_mdt_Configuration = -1;  /* MDT_Configuration */
static int hf_gsm_map_om_jobType = -1;            /* JobType */
static int hf_gsm_map_om_areaScope = -1;          /* AreaScope */
static int hf_gsm_map_om_listOfMeasurements = -1;  /* ListOfMeasurements */
static int hf_gsm_map_om_reportingTrigger = -1;   /* ReportingTrigger */
static int hf_gsm_map_om_reportInterval = -1;     /* ReportInterval */
static int hf_gsm_map_om_reportAmount = -1;       /* ReportAmount */
static int hf_gsm_map_om_eventThresholdRSRP = -1;  /* EventThresholdRSRP */
static int hf_gsm_map_om_eventThresholdRSRQ = -1;  /* EventThresholdRSRQ */
static int hf_gsm_map_om_loggingInterval = -1;    /* LoggingInterval */
static int hf_gsm_map_om_loggingDuration = -1;    /* LoggingDuration */
static int hf_gsm_map_om_cgi_List = -1;           /* CGI_List */
static int hf_gsm_map_om_e_utran_cgi_List = -1;   /* E_UTRAN_CGI_List */
static int hf_gsm_map_om_routingAreaId_List = -1;  /* RoutingAreaId_List */
static int hf_gsm_map_om_locationAreaId_List = -1;  /* LocationAreaId_List */
static int hf_gsm_map_om_trackingAreaId_List = -1;  /* TrackingAreaId_List */
static int hf_gsm_map_om_CGI_List_item = -1;      /* GlobalCellId */
static int hf_gsm_map_om_E_UTRAN_CGI_List_item = -1;  /* E_UTRAN_CGI */
static int hf_gsm_map_om_RoutingAreaId_List_item = -1;  /* RAIdentity */
static int hf_gsm_map_om_LocationAreaId_List_item = -1;  /* LAIFixedLength */
static int hf_gsm_map_om_TrackingAreaId_List_item = -1;  /* TA_Id */
static int hf_gsm_map_om_msc_s_TraceDepth = -1;   /* TraceDepth */
static int hf_gsm_map_om_mgw_TraceDepth = -1;     /* TraceDepth */
static int hf_gsm_map_om_sgsn_TraceDepth = -1;    /* TraceDepth */
static int hf_gsm_map_om_ggsn_TraceDepth = -1;    /* TraceDepth */
static int hf_gsm_map_om_rnc_TraceDepth = -1;     /* TraceDepth */
static int hf_gsm_map_om_bmsc_TraceDepth = -1;    /* TraceDepth */
static int hf_gsm_map_om_mme_TraceDepth = -1;     /* TraceDepth */
static int hf_gsm_map_om_sgw_TraceDepth = -1;     /* TraceDepth */
static int hf_gsm_map_om_pgw_TraceDepth = -1;     /* TraceDepth */
static int hf_gsm_map_om_eNB_TraceDepth = -1;     /* TraceDepth */
static int hf_gsm_map_om_msc_s_List = -1;         /* MSC_S_InterfaceList */
static int hf_gsm_map_om_mgw_List = -1;           /* MGW_InterfaceList */
static int hf_gsm_map_om_sgsn_List = -1;          /* SGSN_InterfaceList */
static int hf_gsm_map_om_ggsn_List = -1;          /* GGSN_InterfaceList */
static int hf_gsm_map_om_rnc_List = -1;           /* RNC_InterfaceList */
static int hf_gsm_map_om_bmsc_List = -1;          /* BMSC_InterfaceList */
static int hf_gsm_map_om_mme_List = -1;           /* MME_InterfaceList */
static int hf_gsm_map_om_sgw_List = -1;           /* SGW_InterfaceList */
static int hf_gsm_map_om_pgw_List = -1;           /* PGW_InterfaceList */
static int hf_gsm_map_om_eNB_List = -1;           /* ENB_InterfaceList */
static int hf_gsm_map_om_msc_s_List_01 = -1;      /* MSC_S_EventList */
static int hf_gsm_map_om_mgw_List_01 = -1;        /* MGW_EventList */
static int hf_gsm_map_om_sgsn_List_01 = -1;       /* SGSN_EventList */
static int hf_gsm_map_om_ggsn_List_01 = -1;       /* GGSN_EventList */
static int hf_gsm_map_om_bmsc_List_01 = -1;       /* BMSC_EventList */
static int hf_gsm_map_om_mme_List_01 = -1;        /* MME_EventList */
static int hf_gsm_map_om_sgw_List_01 = -1;        /* SGW_EventList */
static int hf_gsm_map_om_pgw_List_01 = -1;        /* PGW_EventList */
static int hf_gsm_map_om_traceRecordingSessionReference = -1;  /* TraceRecordingSessionReference */
static int hf_gsm_map_om_rnc_InterfaceList = -1;  /* RNC_InterfaceList */
static int hf_gsm_map_om_msc_s_InterfaceList = -1;  /* MSC_S_InterfaceList */
static int hf_gsm_map_om_msc_s_EventList = -1;    /* MSC_S_EventList */
static int hf_gsm_map_om_mgw_InterfaceList = -1;  /* MGW_InterfaceList */
static int hf_gsm_map_om_mgw_EventList = -1;      /* MGW_EventList */
static int hf_gsm_map_om_traceSupportIndicator = -1;  /* NULL */
/* named bits */
static int hf_gsm_map_om_TraceNE_TypeList_msc_s = -1;
static int hf_gsm_map_om_TraceNE_TypeList_mgw = -1;
static int hf_gsm_map_om_TraceNE_TypeList_sgsn = -1;
static int hf_gsm_map_om_TraceNE_TypeList_ggsn = -1;
static int hf_gsm_map_om_TraceNE_TypeList_rnc = -1;
static int hf_gsm_map_om_TraceNE_TypeList_bm_sc = -1;
static int hf_gsm_map_om_TraceNE_TypeList_mme = -1;
static int hf_gsm_map_om_TraceNE_TypeList_sgw = -1;
static int hf_gsm_map_om_TraceNE_TypeList_pgw = -1;
static int hf_gsm_map_om_TraceNE_TypeList_eNB = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_a = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_iu = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_mc = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_map_g = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_map_b = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_map_e = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_map_f = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_cap = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_map_d = -1;
static int hf_gsm_map_om_MSC_S_InterfaceList_map_c = -1;
static int hf_gsm_map_om_MGW_InterfaceList_mc = -1;
static int hf_gsm_map_om_MGW_InterfaceList_nb_up = -1;
static int hf_gsm_map_om_MGW_InterfaceList_iu_up = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_gb = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_iu = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_gn = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_map_gr = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_map_gd = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_map_gf = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_gs = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_ge = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_s3 = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_s4 = -1;
static int hf_gsm_map_om_SGSN_InterfaceList_s6d = -1;
static int hf_gsm_map_om_GGSN_InterfaceList_gn = -1;
static int hf_gsm_map_om_GGSN_InterfaceList_gi = -1;
static int hf_gsm_map_om_GGSN_InterfaceList_gmb = -1;
static int hf_gsm_map_om_RNC_InterfaceList_iu = -1;
static int hf_gsm_map_om_RNC_InterfaceList_iur = -1;
static int hf_gsm_map_om_RNC_InterfaceList_iub = -1;
static int hf_gsm_map_om_RNC_InterfaceList_uu = -1;
static int hf_gsm_map_om_BMSC_InterfaceList_gmb = -1;
static int hf_gsm_map_om_MME_InterfaceList_s1_mme = -1;
static int hf_gsm_map_om_MME_InterfaceList_s3 = -1;
static int hf_gsm_map_om_MME_InterfaceList_s6a = -1;
static int hf_gsm_map_om_MME_InterfaceList_s10 = -1;
static int hf_gsm_map_om_MME_InterfaceList_s11 = -1;
static int hf_gsm_map_om_SGW_InterfaceList_s4 = -1;
static int hf_gsm_map_om_SGW_InterfaceList_s5 = -1;
static int hf_gsm_map_om_SGW_InterfaceList_s8b = -1;
static int hf_gsm_map_om_SGW_InterfaceList_s11 = -1;
static int hf_gsm_map_om_SGW_InterfaceList_gxc = -1;
static int hf_gsm_map_om_PGW_InterfaceList_s2a = -1;
static int hf_gsm_map_om_PGW_InterfaceList_s2b = -1;
static int hf_gsm_map_om_PGW_InterfaceList_s2c = -1;
static int hf_gsm_map_om_PGW_InterfaceList_s5 = -1;
static int hf_gsm_map_om_PGW_InterfaceList_s6b = -1;
static int hf_gsm_map_om_PGW_InterfaceList_gx = -1;
static int hf_gsm_map_om_PGW_InterfaceList_s8b = -1;
static int hf_gsm_map_om_PGW_InterfaceList_sgi = -1;
static int hf_gsm_map_om_ENB_InterfaceList_s1_mme = -1;
static int hf_gsm_map_om_ENB_InterfaceList_x2 = -1;
static int hf_gsm_map_om_ENB_InterfaceList_uu = -1;
static int hf_gsm_map_om_MSC_S_EventList_mo_mtCall = -1;
static int hf_gsm_map_om_MSC_S_EventList_mo_mt_sms = -1;
static int hf_gsm_map_om_MSC_S_EventList_lu_imsiAttach_imsiDetach = -1;
static int hf_gsm_map_om_MSC_S_EventList_handovers = -1;
static int hf_gsm_map_om_MSC_S_EventList_ss = -1;
static int hf_gsm_map_om_MGW_EventList_context = -1;
static int hf_gsm_map_om_SGSN_EventList_pdpContext = -1;
static int hf_gsm_map_om_SGSN_EventList_mo_mt_sms = -1;
static int hf_gsm_map_om_SGSN_EventList_rau_gprsAttach_gprsDetach = -1;
static int hf_gsm_map_om_SGSN_EventList_mbmsContext = -1;
static int hf_gsm_map_om_GGSN_EventList_pdpContext = -1;
static int hf_gsm_map_om_GGSN_EventList_mbmsContext = -1;
static int hf_gsm_map_om_BMSC_EventList_mbmsMulticastServiceActivation = -1;
static int hf_gsm_map_om_MME_EventList_ue_initiatedPDNconectivityRequest = -1;
static int hf_gsm_map_om_MME_EventList_serviceRequestts = -1;
static int hf_gsm_map_om_MME_EventList_initialAttachTrackingAreaUpdateDetach = -1;
static int hf_gsm_map_om_MME_EventList_ue_initiatedPDNdisconnection = -1;
static int hf_gsm_map_om_MME_EventList_bearerActivationModificationDeletion = -1;
static int hf_gsm_map_om_MME_EventList_handover = -1;
static int hf_gsm_map_om_SGW_EventList_pdn_connectionCreation = -1;
static int hf_gsm_map_om_SGW_EventList_pdn_connectionTermination = -1;
static int hf_gsm_map_om_SGW_EventList_bearerActivationModificationDeletion = -1;
static int hf_gsm_map_om_PGW_EventList_pdn_connectionCreation = -1;
static int hf_gsm_map_om_PGW_EventList_pdn_connectionTermination = -1;
static int hf_gsm_map_om_PGW_EventList_bearerActivationModificationDeletion = -1;

/* --- Module MAP-MS-DataTypes --- --- ---                                    */

static int hf_gsm_map_ms_imsi = -1;               /* IMSI */
static int hf_gsm_map_ms_msc_Number = -1;         /* ISDN_AddressString */
static int hf_gsm_map_ms_vlr_Number = -1;         /* ISDN_AddressString */
static int hf_gsm_map_ms_lmsi = -1;               /* LMSI */
static int hf_gsm_map_ms_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_ms_vlr_Capability = -1;     /* VLR_Capability */
static int hf_gsm_map_ms_informPreviousNetworkEntity = -1;  /* NULL */
static int hf_gsm_map_ms_cs_LCS_NotSupportedByUE = -1;  /* NULL */
static int hf_gsm_map_ms_v_gmlc_Address = -1;     /* GSN_Address */
static int hf_gsm_map_ms_add_info = -1;           /* ADD_Info */
static int hf_gsm_map_ms_pagingArea = -1;         /* PagingArea */
static int hf_gsm_map_ms_skipSubscriberDataUpdate = -1;  /* NULL */
static int hf_gsm_map_ms_restorationIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_supportedCamelPhases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ms_solsaSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_istSupportIndicator = -1;  /* IST_SupportIndicator */
static int hf_gsm_map_ms_superChargerSupportedInServingNetworkEntity = -1;  /* SuperChargerInfo */
static int hf_gsm_map_ms_longFTN_Supported = -1;  /* NULL */
static int hf_gsm_map_ms_supportedLCS_CapabilitySets = -1;  /* SupportedLCS_CapabilitySets */
static int hf_gsm_map_ms_offeredCamel4CSIs = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_ms_supportedRAT_TypesIndicator = -1;  /* SupportedRAT_Types */
static int hf_gsm_map_ms_longGroupID_Supported = -1;  /* NULL */
static int hf_gsm_map_ms_mtRoamingForwardingSupported = -1;  /* NULL */
static int hf_gsm_map_ms_sendSubscriberData = -1;  /* NULL */
static int hf_gsm_map_ms_subscriberDataStored = -1;  /* AgeIndicator */
static int hf_gsm_map_ms_hlr_Number = -1;         /* ISDN_AddressString */
static int hf_gsm_map_ms_add_Capability = -1;     /* NULL */
static int hf_gsm_map_ms_pagingArea_Capability = -1;  /* NULL */
static int hf_gsm_map_ms_imeisv = -1;             /* IMEI */
static int hf_gsm_map_ms_PagingArea_item = -1;    /* LocationArea */
static int hf_gsm_map_ms_laiFixedLength = -1;     /* LAIFixedLength */
static int hf_gsm_map_ms_lac = -1;                /* LAC */
static int hf_gsm_map_ms_identity = -1;           /* Identity */
static int hf_gsm_map_ms_cancellationType = -1;   /* CancellationType */
static int hf_gsm_map_ms_typeOfUpdate = -1;       /* TypeOfUpdate */
static int hf_gsm_map_ms_mtrf_SupportedAndAuthorized = -1;  /* NULL */
static int hf_gsm_map_ms_mtrf_SupportedAndNotAuthorized = -1;  /* NULL */
static int hf_gsm_map_ms_newMSC_Number = -1;      /* ISDN_AddressString */
static int hf_gsm_map_ms_newVLR_Number = -1;      /* ISDN_AddressString */
static int hf_gsm_map_ms_new_lmsi = -1;           /* LMSI */
static int hf_gsm_map_ms_sgsn_Number = -1;        /* ISDN_AddressString */
static int hf_gsm_map_ms_freezeTMSI = -1;         /* NULL */
static int hf_gsm_map_ms_freezeP_TMSI = -1;       /* NULL */
static int hf_gsm_map_ms_freezeM_TMSI = -1;       /* NULL */
static int hf_gsm_map_ms_tmsi = -1;               /* TMSI */
static int hf_gsm_map_ms_numberOfRequestedVectors = -1;  /* NumberOfRequestedVectors */
static int hf_gsm_map_ms_segmentationProhibited = -1;  /* NULL */
static int hf_gsm_map_ms_previous_LAI = -1;       /* LAIFixedLength */
static int hf_gsm_map_ms_hopCounter = -1;         /* HopCounter */
static int hf_gsm_map_ms_authenticationSetList = -1;  /* AuthenticationSetList */
static int hf_gsm_map_ms_currentSecurityContext = -1;  /* CurrentSecurityContext */
static int hf_gsm_map_ms_tripletList = -1;        /* TripletList */
static int hf_gsm_map_ms_quintupletList = -1;     /* QuintupletList */
static int hf_gsm_map_ms_TripletList_item = -1;   /* AuthenticationTriplet */
static int hf_gsm_map_ms_QuintupletList_item = -1;  /* AuthenticationQuintuplet */
static int hf_gsm_map_ms_rand = -1;               /* RAND */
static int hf_gsm_map_ms_sres = -1;               /* SRES */
static int hf_gsm_map_ms_kc = -1;                 /* Kc */
static int hf_gsm_map_ms_xres = -1;               /* XRES */
static int hf_gsm_map_ms_ck = -1;                 /* CK */
static int hf_gsm_map_ms_ik = -1;                 /* IK */
static int hf_gsm_map_ms_autn = -1;               /* AUTN */
static int hf_gsm_map_ms_gsm_SecurityContextData = -1;  /* GSM_SecurityContextData */
static int hf_gsm_map_ms_umts_SecurityContextData = -1;  /* UMTS_SecurityContextData */
static int hf_gsm_map_ms_cksn = -1;               /* Cksn */
static int hf_gsm_map_ms_ksi = -1;                /* KSI */
static int hf_gsm_map_ms_failureCause = -1;       /* FailureCause */
static int hf_gsm_map_ms_re_attempt = -1;         /* BOOLEAN */
static int hf_gsm_map_ms_accessType = -1;         /* AccessType */
static int hf_gsm_map_ms_sgsn_Address = -1;       /* GSN_Address */
static int hf_gsm_map_ms_sgsn_Capability = -1;    /* SGSN_Capability */
static int hf_gsm_map_ms_ps_LCS_NotSupportedByUE = -1;  /* NULL */
static int hf_gsm_map_ms_eps_info = -1;           /* EPS_Info */
static int hf_gsm_map_ms_servingNodeTypeIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_usedRAT_Type = -1;       /* Used_RAT_Type */
static int hf_gsm_map_ms_gprsSubscriptionDataNotNeeded = -1;  /* NULL */
static int hf_gsm_map_ms_nodeTypeIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_areaRestricted = -1;     /* NULL */
static int hf_gsm_map_ms_ue_reachableIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_epsSubscriptionDataNotNeeded = -1;  /* NULL */
static int hf_gsm_map_ms_ue_srvcc_Capability = -1;  /* UE_SRVCC_Capability */
static int hf_gsm_map_ms_pdn_gw_update = -1;      /* PDN_GW_Update */
static int hf_gsm_map_ms_isr_Information = -1;    /* ISR_Information */
static int hf_gsm_map_ms_apn = -1;                /* APN */
static int hf_gsm_map_ms_pdn_gw_Identity = -1;    /* PDN_GW_Identity */
static int hf_gsm_map_ms_contextId = -1;          /* ContextId */
static int hf_gsm_map_ms_gprsEnhancementsSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_smsCallBarringSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_supportedFeatures = -1;  /* SupportedFeatures */
static int hf_gsm_map_ms_t_adsDataRetrieval = -1;  /* NULL */
static int hf_gsm_map_ms_homogeneousSupportOfIMSVoiceOverPSSessions = -1;  /* BOOLEAN */
static int hf_gsm_map_ms_sgsn_mmeSeparationSupported = -1;  /* NULL */
static int hf_gsm_map_ms_an_APDU = -1;            /* AccessNetworkSignalInfo */
static int hf_gsm_map_ms_integrityProtectionInfo = -1;  /* IntegrityProtectionInformation */
static int hf_gsm_map_ms_encryptionInfo = -1;     /* EncryptionInformation */
static int hf_gsm_map_ms_keyStatus = -1;          /* KeyStatus */
static int hf_gsm_map_ms_allowedGSM_Algorithms = -1;  /* AllowedGSM_Algorithms */
static int hf_gsm_map_ms_allowedUMTS_Algorithms = -1;  /* AllowedUMTS_Algorithms */
static int hf_gsm_map_ms_radioResourceInformation = -1;  /* RadioResourceInformation */
static int hf_gsm_map_ms_radioResourceList = -1;  /* RadioResourceList */
static int hf_gsm_map_ms_bssmap_ServiceHandover = -1;  /* BSSMAP_ServiceHandover */
static int hf_gsm_map_ms_ranap_ServiceHandover = -1;  /* RANAP_ServiceHandover */
static int hf_gsm_map_ms_bssmap_ServiceHandoverList = -1;  /* BSSMAP_ServiceHandoverList */
static int hf_gsm_map_ms_currentlyUsedCodec = -1;  /* Codec */
static int hf_gsm_map_ms_iuSupportedCodecsList = -1;  /* SupportedCodecsList */
static int hf_gsm_map_ms_rab_ConfigurationIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_iuSelectedCodec = -1;    /* Codec */
static int hf_gsm_map_ms_alternativeChannelType = -1;  /* RadioResourceInformation */
static int hf_gsm_map_ms_tracePropagationList = -1;  /* TracePropagationList */
static int hf_gsm_map_ms_aoipSupportedCodecsListAnchor = -1;  /* AoIPCodecsList */
static int hf_gsm_map_ms_aoipSelectedCodecTarget = -1;  /* AoIPCodec */
static int hf_gsm_map_ms_integrityProtectionAlgorithms = -1;  /* PermittedIntegrityProtectionAlgorithms */
static int hf_gsm_map_ms_encryptionAlgorithms = -1;  /* PermittedEncryptionAlgorithms */
static int hf_gsm_map_ms_targetCellId = -1;       /* GlobalCellId */
static int hf_gsm_map_ms_ho_NumberNotRequired = -1;  /* NULL */
static int hf_gsm_map_ms_targetRNCId = -1;        /* RNCId */
static int hf_gsm_map_ms_multipleBearerRequested = -1;  /* NULL */
static int hf_gsm_map_ms_rab_Id = -1;             /* RAB_Id */
static int hf_gsm_map_ms_asciCallReference = -1;  /* ASCI_CallReference */
static int hf_gsm_map_ms_geran_classmark = -1;    /* GERAN_Classmark */
static int hf_gsm_map_ms_iuCurrentlyUsedCodec = -1;  /* Codec */
static int hf_gsm_map_ms_uesbi_Iu = -1;           /* UESBI_Iu */
static int hf_gsm_map_ms_regionalSubscriptionData = -1;  /* ZoneCodeList */
static int hf_gsm_map_ms_globalCallReference = -1;  /* LCLS_GlobalCallReference */
static int hf_gsm_map_ms_lcls_Negotiation = -1;   /* LCLS_Negotiation */
static int hf_gsm_map_ms_BSSMAP_ServiceHandoverList_item = -1;  /* BSSMAP_ServiceHandoverInfo */
static int hf_gsm_map_ms_RadioResourceList_item = -1;  /* RadioResource */
static int hf_gsm_map_ms_handoverNumber = -1;     /* ISDN_AddressString */
static int hf_gsm_map_ms_relocationNumberList = -1;  /* RelocationNumberList */
static int hf_gsm_map_ms_multicallBearerInfo = -1;  /* MulticallBearerInfo */
static int hf_gsm_map_ms_multipleBearerNotSupported = -1;  /* NULL */
static int hf_gsm_map_ms_selectedUMTS_Algorithms = -1;  /* SelectedUMTS_Algorithms */
static int hf_gsm_map_ms_chosenRadioResourceInformation = -1;  /* ChosenRadioResourceInformation */
static int hf_gsm_map_ms_iuAvailableCodecsList = -1;  /* CodecList */
static int hf_gsm_map_ms_aoipAvailableCodecsListMap = -1;  /* AoIPCodecsList */
static int hf_gsm_map_ms_integrityProtectionAlgorithm = -1;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_gsm_map_ms_encryptionAlgorithm = -1;  /* ChosenEncryptionAlgorithm */
static int hf_gsm_map_ms_chosenChannelInfo = -1;  /* ChosenChannelInfo */
static int hf_gsm_map_ms_chosenSpeechVersion = -1;  /* ChosenSpeechVersion */
static int hf_gsm_map_ms_targetMSC_Number = -1;   /* ISDN_AddressString */
static int hf_gsm_map_ms_selectedRab_Id = -1;     /* RAB_Id */
static int hf_gsm_map_ms_selectedGSM_Algorithm = -1;  /* SelectedGSM_Algorithm */
static int hf_gsm_map_ms_iUSelectedCodec = -1;    /* Codec */
static int hf_gsm_map_ms_codec1 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec2 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec3 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec4 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec5 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec6 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec7 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_codec8 = -1;             /* AoIPCodec */
static int hf_gsm_map_ms_utranCodecList = -1;     /* CodecList */
static int hf_gsm_map_ms_geranCodecList = -1;     /* CodecList */
static int hf_gsm_map_ms_codec1_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec2_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec3_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec4_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec5_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec6_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec7_01 = -1;          /* Codec */
static int hf_gsm_map_ms_codec8_01 = -1;          /* Codec */
static int hf_gsm_map_ms_RelocationNumberList_item = -1;  /* RelocationNumber */
static int hf_gsm_map_ms_immediateResponsePreferred = -1;  /* NULL */
static int hf_gsm_map_ms_re_synchronisationInfo = -1;  /* Re_synchronisationInfo */
static int hf_gsm_map_ms_requestingNodeType = -1;  /* RequestingNodeType */
static int hf_gsm_map_ms_requestingPLMN_Id = -1;  /* PLMN_Id */
static int hf_gsm_map_ms_numberOfRequestedAdditional_Vectors = -1;  /* NumberOfRequestedVectors */
static int hf_gsm_map_ms_additionalVectorsAreForEPS = -1;  /* NULL */
static int hf_gsm_map_ms_auts = -1;               /* AUTS */
static int hf_gsm_map_ms_eps_AuthenticationSetList = -1;  /* EPS_AuthenticationSetList */
static int hf_gsm_map_ms_EPS_AuthenticationSetList_item = -1;  /* EPC_AV */
static int hf_gsm_map_ms_kasme = -1;              /* KASME */
static int hf_gsm_map_ms_imei = -1;               /* IMEI */
static int hf_gsm_map_ms_requestedEquipmentInfo = -1;  /* RequestedEquipmentInfo */
static int hf_gsm_map_ms_equipmentStatus = -1;    /* EquipmentStatus */
static int hf_gsm_map_ms_bmuef = -1;              /* UESBI_Iu */
static int hf_gsm_map_ms_uesbi_IuA = -1;          /* UESBI_IuA */
static int hf_gsm_map_ms_uesbi_IuB = -1;          /* UESBI_IuB */
static int hf_gsm_map_ms_CSG_SubscriptionDataList_item = -1;  /* CSG_SubscriptionData */
static int hf_gsm_map_ms_csg_Id = -1;             /* CSG_Id */
static int hf_gsm_map_ms_expirationDate = -1;     /* Time */
static int hf_gsm_map_ms_lipa_AllowedAPNList = -1;  /* LIPA_AllowedAPNList */
static int hf_gsm_map_ms_LIPA_AllowedAPNList_item = -1;  /* APN */
static int hf_gsm_map_ms_apn_oi_Replacement = -1;  /* APN_OI_Replacement */
static int hf_gsm_map_ms_rfsp_id = -1;            /* RFSP_ID */
static int hf_gsm_map_ms_ambr = -1;               /* AMBR */
static int hf_gsm_map_ms_apn_ConfigurationProfile = -1;  /* APN_ConfigurationProfile */
static int hf_gsm_map_ms_stn_sr = -1;             /* ISDN_AddressString */
static int hf_gsm_map_ms_mps_CSPriority = -1;     /* NULL */
static int hf_gsm_map_ms_mps_EPSPriority = -1;    /* NULL */
static int hf_gsm_map_ms_defaultContext = -1;     /* ContextId */
static int hf_gsm_map_ms_completeDataListIncluded = -1;  /* NULL */
static int hf_gsm_map_ms_epsDataList = -1;        /* EPS_DataList */
static int hf_gsm_map_ms_EPS_DataList_item = -1;  /* APN_Configuration */
static int hf_gsm_map_ms_pdn_Type = -1;           /* PDN_Type */
static int hf_gsm_map_ms_servedPartyIP_IPv4_Address = -1;  /* PDP_Address */
static int hf_gsm_map_ms_eps_qos_Subscribed = -1;  /* EPS_QoS_Subscribed */
static int hf_gsm_map_ms_pdn_gw_AllocationType = -1;  /* PDN_GW_AllocationType */
static int hf_gsm_map_ms_vplmnAddressAllowed = -1;  /* NULL */
static int hf_gsm_map_ms_chargingCharacteristics = -1;  /* ChargingCharacteristics */
static int hf_gsm_map_ms_specificAPNInfoList = -1;  /* SpecificAPNInfoList */
static int hf_gsm_map_ms_servedPartyIP_IPv6_Address = -1;  /* PDP_Address */
static int hf_gsm_map_ms_sipto_Permission = -1;   /* SIPTO_Permission */
static int hf_gsm_map_ms_lipa_Permission = -1;    /* LIPA_Permission */
static int hf_gsm_map_ms_qos_Class_Identifier = -1;  /* QoS_Class_Identifier */
static int hf_gsm_map_ms_allocation_Retention_Priority = -1;  /* Allocation_Retention_Priority */
static int hf_gsm_map_ms_max_RequestedBandwidth_UL = -1;  /* Bandwidth */
static int hf_gsm_map_ms_max_RequestedBandwidth_DL = -1;  /* Bandwidth */
static int hf_gsm_map_ms_SpecificAPNInfoList_item = -1;  /* SpecificAPNInfo */
static int hf_gsm_map_ms_priority_level = -1;     /* INTEGER */
static int hf_gsm_map_ms_pre_emption_capability = -1;  /* BOOLEAN */
static int hf_gsm_map_ms_pre_emption_vulnerability = -1;  /* BOOLEAN */
static int hf_gsm_map_ms_pdn_gw_ipv4_Address = -1;  /* PDP_Address */
static int hf_gsm_map_ms_pdn_gw_ipv6_Address = -1;  /* PDP_Address */
static int hf_gsm_map_ms_pdn_gw_name = -1;        /* FQDN */
static int hf_gsm_map_ms_gmlc_List = -1;          /* GMLC_List */
static int hf_gsm_map_ms_lcs_PrivacyExceptionList = -1;  /* LCS_PrivacyExceptionList */
static int hf_gsm_map_ms_molr_List = -1;          /* MOLR_List */
static int hf_gsm_map_ms_add_lcs_PrivacyExceptionList = -1;  /* LCS_PrivacyExceptionList */
static int hf_gsm_map_ms_GMLC_List_item = -1;     /* ISDN_AddressString */
static int hf_gsm_map_ms_GPRSDataList_item = -1;  /* PDP_Context */
static int hf_gsm_map_ms_pdp_ContextId = -1;      /* ContextId */
static int hf_gsm_map_ms_pdp_Type = -1;           /* PDP_Type */
static int hf_gsm_map_ms_pdp_Address = -1;        /* PDP_Address */
static int hf_gsm_map_ms_qos_Subscribed = -1;     /* QoS_Subscribed */
static int hf_gsm_map_ms_ext_QoS_Subscribed = -1;  /* Ext_QoS_Subscribed */
static int hf_gsm_map_ms_pdp_ChargingCharacteristics = -1;  /* ChargingCharacteristics */
static int hf_gsm_map_ms_ext2_QoS_Subscribed = -1;  /* Ext2_QoS_Subscribed */
static int hf_gsm_map_ms_ext3_QoS_Subscribed = -1;  /* Ext3_QoS_Subscribed */
static int hf_gsm_map_ms_ext4_QoS_Subscribed = -1;  /* Ext4_QoS_Subscribed */
static int hf_gsm_map_ms_ext_pdp_Type = -1;       /* Ext_PDP_Type */
static int hf_gsm_map_ms_ext_pdp_Address = -1;    /* PDP_Address */
static int hf_gsm_map_ms_gprsDataList = -1;       /* GPRSDataList */
static int hf_gsm_map_ms_gprs_CSI = -1;           /* GPRS_CSI */
static int hf_gsm_map_ms_mo_sms_CSI = -1;         /* SMS_CSI */
static int hf_gsm_map_ms_mt_sms_CSI = -1;         /* SMS_CSI */
static int hf_gsm_map_ms_mt_smsCAMELTDP_CriteriaList = -1;  /* MT_smsCAMELTDP_CriteriaList */
static int hf_gsm_map_ms_mg_csi = -1;             /* MG_CSI */
static int hf_gsm_map_ms_gprs_CamelTDPDataList = -1;  /* GPRS_CamelTDPDataList */
static int hf_gsm_map_ms_camelCapabilityHandling = -1;  /* CamelCapabilityHandling */
static int hf_gsm_map_ms_notificationToCSE = -1;  /* NULL */
static int hf_gsm_map_ms_csi_Active = -1;         /* NULL */
static int hf_gsm_map_ms_GPRS_CamelTDPDataList_item = -1;  /* GPRS_CamelTDPData */
static int hf_gsm_map_ms_gprs_TriggerDetectionPoint = -1;  /* GPRS_TriggerDetectionPoint */
static int hf_gsm_map_ms_serviceKey = -1;         /* ServiceKey */
static int hf_gsm_map_ms_gsmSCF_Address = -1;     /* ISDN_AddressString */
static int hf_gsm_map_ms_defaultSessionHandling = -1;  /* DefaultGPRS_Handling */
static int hf_gsm_map_ms_LSADataList_item = -1;   /* LSAData */
static int hf_gsm_map_ms_lsaIdentity = -1;        /* LSAIdentity */
static int hf_gsm_map_ms_lsaAttributes = -1;      /* LSAAttributes */
static int hf_gsm_map_ms_lsaActiveModeIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_lsaOnlyAccessIndicator = -1;  /* LSAOnlyAccessIndicator */
static int hf_gsm_map_ms_lsaDataList = -1;        /* LSADataList */
static int hf_gsm_map_ms_msisdn = -1;             /* ISDN_AddressString */
static int hf_gsm_map_ms_category = -1;           /* Category */
static int hf_gsm_map_ms_subscriberStatus = -1;   /* SubscriberStatus */
static int hf_gsm_map_ms_bearerServiceList = -1;  /* BearerServiceList */
static int hf_gsm_map_ms_teleserviceList = -1;    /* TeleserviceList */
static int hf_gsm_map_ms_provisionedSS = -1;      /* Ext_SS_InfoList */
static int hf_gsm_map_ms_odb_Data = -1;           /* ODB_Data */
static int hf_gsm_map_ms_roamingRestrictionDueToUnsupportedFeature = -1;  /* NULL */
static int hf_gsm_map_ms_vbsSubscriptionData = -1;  /* VBSDataList */
static int hf_gsm_map_ms_vgcsSubscriptionData = -1;  /* VGCSDataList */
static int hf_gsm_map_ms_vlrCamelSubscriptionInfo = -1;  /* VlrCamelSubscriptionInfo */
static int hf_gsm_map_ms_BearerServiceList_item = -1;  /* Ext_BearerServiceCode */
static int hf_gsm_map_ms_TeleserviceList_item = -1;  /* Ext_TeleserviceCode */
static int hf_gsm_map_ms_odb_GeneralData = -1;    /* ODB_GeneralData */
static int hf_gsm_map_ms_odb_HPLMN_Data = -1;     /* ODB_HPLMN_Data */
static int hf_gsm_map_ms_Ext_SS_InfoList_item = -1;  /* Ext_SS_Info */
static int hf_gsm_map_ms_forwardingInfo = -1;     /* Ext_ForwInfo */
static int hf_gsm_map_ms_callBarringInfo = -1;    /* Ext_CallBarInfo */
static int hf_gsm_map_ms_cug_Info = -1;           /* CUG_Info */
static int hf_gsm_map_ms_ss_Data = -1;            /* Ext_SS_Data */
static int hf_gsm_map_ms_emlpp_Info = -1;         /* EMLPP_Info */
static int hf_gsm_map_ms_ss_Code = -1;            /* SS_Code */
static int hf_gsm_map_ms_forwardingFeatureList = -1;  /* Ext_ForwFeatureList */
static int hf_gsm_map_ms_Ext_ForwFeatureList_item = -1;  /* Ext_ForwFeature */
static int hf_gsm_map_ms_basicService = -1;       /* Ext_BasicServiceCode */
static int hf_gsm_map_ms_ss_Status = -1;          /* Ext_SS_Status */
static int hf_gsm_map_ms_forwardedToNumber = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ms_forwardedToSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_map_ms_forwardingOptions = -1;  /* T_forwardingOptions */
static int hf_gsm_map_ms_noReplyConditionTime = -1;  /* Ext_NoRepCondTime */
static int hf_gsm_map_ms_longForwardedToNumber = -1;  /* FTN_AddressString */
static int hf_gsm_map_ms_callBarringFeatureList = -1;  /* Ext_CallBarFeatureList */
static int hf_gsm_map_ms_Ext_CallBarFeatureList_item = -1;  /* Ext_CallBarringFeature */
static int hf_gsm_map_ms_cug_SubscriptionList = -1;  /* CUG_SubscriptionList */
static int hf_gsm_map_ms_cug_FeatureList = -1;    /* CUG_FeatureList */
static int hf_gsm_map_ms_CUG_SubscriptionList_item = -1;  /* CUG_Subscription */
static int hf_gsm_map_ms_cug_Index = -1;          /* CUG_Index */
static int hf_gsm_map_ms_cug_Interlock = -1;      /* CUG_Interlock */
static int hf_gsm_map_ms_intraCUG_Options = -1;   /* IntraCUG_Options */
static int hf_gsm_map_ms_basicServiceGroupList = -1;  /* Ext_BasicServiceGroupList */
static int hf_gsm_map_ms_CUG_FeatureList_item = -1;  /* CUG_Feature */
static int hf_gsm_map_ms_Ext_BasicServiceGroupList_item = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_ms_preferentialCUG_Indicator = -1;  /* CUG_Index */
static int hf_gsm_map_ms_interCUG_Restrictions = -1;  /* InterCUG_Restrictions */
static int hf_gsm_map_ms_ss_SubscriptionOption = -1;  /* SS_SubscriptionOption */
static int hf_gsm_map_ms_LCS_PrivacyExceptionList_item = -1;  /* LCS_PrivacyClass */
static int hf_gsm_map_ms_notificationToMSUser = -1;  /* NotificationToMSUser */
static int hf_gsm_map_ms_externalClientList = -1;  /* ExternalClientList */
static int hf_gsm_map_ms_plmnClientList = -1;     /* PLMNClientList */
static int hf_gsm_map_ms_ext_externalClientList = -1;  /* Ext_ExternalClientList */
static int hf_gsm_map_ms_serviceTypeList = -1;    /* ServiceTypeList */
static int hf_gsm_map_ms_ExternalClientList_item = -1;  /* ExternalClient */
static int hf_gsm_map_ms_PLMNClientList_item = -1;  /* LCSClientInternalID */
static int hf_gsm_map_ms_Ext_ExternalClientList_item = -1;  /* ExternalClient */
static int hf_gsm_map_ms_clientIdentity = -1;     /* LCSClientExternalID */
static int hf_gsm_map_ms_gmlc_Restriction = -1;   /* GMLC_Restriction */
static int hf_gsm_map_ms_ServiceTypeList_item = -1;  /* ServiceType */
static int hf_gsm_map_ms_serviceTypeIdentity = -1;  /* LCSServiceTypeID */
static int hf_gsm_map_ms_MOLR_List_item = -1;     /* MOLR_Class */
static int hf_gsm_map_ms_ZoneCodeList_item = -1;  /* ZoneCode */
static int hf_gsm_map_ms_ss_List = -1;            /* SS_List */
static int hf_gsm_map_ms_regionalSubscriptionResponse = -1;  /* RegionalSubscriptionResponse */
static int hf_gsm_map_ms_basicServiceList = -1;   /* BasicServiceList */
static int hf_gsm_map_ms_regionalSubscriptionIdentifier = -1;  /* ZoneCode */
static int hf_gsm_map_ms_vbsGroupIndication = -1;  /* NULL */
static int hf_gsm_map_ms_vgcsGroupIndication = -1;  /* NULL */
static int hf_gsm_map_ms_camelSubscriptionInfoWithdraw = -1;  /* NULL */
static int hf_gsm_map_ms_gprsSubscriptionDataWithdraw = -1;  /* GPRSSubscriptionDataWithdraw */
static int hf_gsm_map_ms_roamingRestrictedInSgsnDueToUnsuppportedFeature = -1;  /* NULL */
static int hf_gsm_map_ms_lsaInformationWithdraw = -1;  /* LSAInformationWithdraw */
static int hf_gsm_map_ms_gmlc_ListWithdraw = -1;  /* NULL */
static int hf_gsm_map_ms_istInformationWithdraw = -1;  /* NULL */
static int hf_gsm_map_ms_specificCSI_Withdraw = -1;  /* SpecificCSI_Withdraw */
static int hf_gsm_map_ms_chargingCharacteristicsWithdraw = -1;  /* NULL */
static int hf_gsm_map_ms_stn_srWithdraw = -1;     /* NULL */
static int hf_gsm_map_ms_epsSubscriptionDataWithdraw = -1;  /* EPS_SubscriptionDataWithdraw */
static int hf_gsm_map_ms_apn_oi_replacementWithdraw = -1;  /* NULL */
static int hf_gsm_map_ms_csg_SubscriptionDeleted = -1;  /* NULL */
static int hf_gsm_map_ms_allGPRSData = -1;        /* NULL */
static int hf_gsm_map_ms_contextIdList = -1;      /* ContextIdList */
static int hf_gsm_map_ms_allEPS_Data = -1;        /* NULL */
static int hf_gsm_map_ms_ContextIdList_item = -1;  /* ContextId */
static int hf_gsm_map_ms_allLSAData = -1;         /* NULL */
static int hf_gsm_map_ms_lsaIdentityList = -1;    /* LSAIdentityList */
static int hf_gsm_map_ms_LSAIdentityList_item = -1;  /* LSAIdentity */
static int hf_gsm_map_ms_BasicServiceList_item = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_ms_o_CSI = -1;              /* O_CSI */
static int hf_gsm_map_ms_ss_CSI = -1;             /* SS_CSI */
static int hf_gsm_map_ms_o_BcsmCamelTDP_CriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_ms_tif_CSI = -1;            /* NULL */
static int hf_gsm_map_ms_m_CSI = -1;              /* M_CSI */
static int hf_gsm_map_ms_vt_CSI = -1;             /* T_CSI */
static int hf_gsm_map_ms_t_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_ms_d_CSI = -1;              /* D_CSI */
static int hf_gsm_map_ms_MT_smsCAMELTDP_CriteriaList_item = -1;  /* MT_smsCAMELTDP_Criteria */
static int hf_gsm_map_ms_sms_TriggerDetectionPoint = -1;  /* SMS_TriggerDetectionPoint */
static int hf_gsm_map_ms_tpdu_TypeCriterion = -1;  /* TPDU_TypeCriterion */
static int hf_gsm_map_ms_TPDU_TypeCriterion_item = -1;  /* MT_SMS_TPDU_Type */
static int hf_gsm_map_ms_dp_AnalysedInfoCriteriaList = -1;  /* DP_AnalysedInfoCriteriaList */
static int hf_gsm_map_ms_DP_AnalysedInfoCriteriaList_item = -1;  /* DP_AnalysedInfoCriterium */
static int hf_gsm_map_ms_dialledNumber = -1;      /* ISDN_AddressString */
static int hf_gsm_map_ms_defaultCallHandling = -1;  /* DefaultCallHandling */
static int hf_gsm_map_ms_ss_CamelData = -1;       /* SS_CamelData */
static int hf_gsm_map_ms_ss_EventList = -1;       /* SS_EventList */
static int hf_gsm_map_ms_SS_EventList_item = -1;  /* SS_Code */
static int hf_gsm_map_ms_o_BcsmCamelTDPDataList = -1;  /* O_BcsmCamelTDPDataList */
static int hf_gsm_map_ms_csiActive = -1;          /* NULL */
static int hf_gsm_map_ms_O_BcsmCamelTDPDataList_item = -1;  /* O_BcsmCamelTDPData */
static int hf_gsm_map_ms_o_BcsmTriggerDetectionPoint = -1;  /* O_BcsmTriggerDetectionPoint */
static int hf_gsm_map_ms_O_BcsmCamelTDPCriteriaList_item = -1;  /* O_BcsmCamelTDP_Criteria */
static int hf_gsm_map_ms_T_BCSM_CAMEL_TDP_CriteriaList_item = -1;  /* T_BCSM_CAMEL_TDP_Criteria */
static int hf_gsm_map_ms_destinationNumberCriteria = -1;  /* DestinationNumberCriteria */
static int hf_gsm_map_ms_basicServiceCriteria = -1;  /* BasicServiceCriteria */
static int hf_gsm_map_ms_callTypeCriteria = -1;   /* CallTypeCriteria */
static int hf_gsm_map_ms_o_CauseValueCriteria = -1;  /* O_CauseValueCriteria */
static int hf_gsm_map_ms_t_BCSM_TriggerDetectionPoint = -1;  /* T_BcsmTriggerDetectionPoint */
static int hf_gsm_map_ms_t_CauseValueCriteria = -1;  /* T_CauseValueCriteria */
static int hf_gsm_map_ms_matchType = -1;          /* MatchType */
static int hf_gsm_map_ms_destinationNumberList = -1;  /* DestinationNumberList */
static int hf_gsm_map_ms_destinationNumberLengthList = -1;  /* DestinationNumberLengthList */
static int hf_gsm_map_ms_DestinationNumberList_item = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ms_DestinationNumberLengthList_item = -1;  /* INTEGER_1_maxNumOfISDN_AddressDigits */
static int hf_gsm_map_ms_BasicServiceCriteria_item = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_ms_O_CauseValueCriteria_item = -1;  /* CauseValue */
static int hf_gsm_map_ms_T_CauseValueCriteria_item = -1;  /* CauseValue */
static int hf_gsm_map_ms_sms_CAMEL_TDP_DataList = -1;  /* SMS_CAMEL_TDP_DataList */
static int hf_gsm_map_ms_SMS_CAMEL_TDP_DataList_item = -1;  /* SMS_CAMEL_TDP_Data */
static int hf_gsm_map_ms_defaultSMS_Handling = -1;  /* DefaultSMS_Handling */
static int hf_gsm_map_ms_mobilityTriggers = -1;   /* MobilityTriggers */
static int hf_gsm_map_ms_MobilityTriggers_item = -1;  /* MM_Code */
static int hf_gsm_map_ms_t_BcsmCamelTDPDataList = -1;  /* T_BcsmCamelTDPDataList */
static int hf_gsm_map_ms_T_BcsmCamelTDPDataList_item = -1;  /* T_BcsmCamelTDPData */
static int hf_gsm_map_ms_t_BcsmTriggerDetectionPoint = -1;  /* T_BcsmTriggerDetectionPoint */
static int hf_gsm_map_ms_ggsn_Address = -1;       /* GSN_Address */
static int hf_gsm_map_ms_ggsn_Number = -1;        /* ISDN_AddressString */
static int hf_gsm_map_ms_mobileNotReachableReason = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_ms_hlr_List = -1;           /* HLR_List */
static int hf_gsm_map_ms_msNotReachable = -1;     /* NULL */
static int hf_gsm_map_ms_VBSDataList_item = -1;   /* VoiceBroadcastData */
static int hf_gsm_map_ms_VGCSDataList_item = -1;  /* VoiceGroupCallData */
static int hf_gsm_map_ms_groupId = -1;            /* GroupId */
static int hf_gsm_map_ms_additionalSubscriptions = -1;  /* AdditionalSubscriptions */
static int hf_gsm_map_ms_additionalInfo = -1;     /* AdditionalInfo */
static int hf_gsm_map_ms_longGroupId = -1;        /* Long_GroupId */
static int hf_gsm_map_ms_groupid = -1;            /* GroupId */
static int hf_gsm_map_ms_broadcastInitEntitlement = -1;  /* NULL */
static int hf_gsm_map_ms_requestedInfo = -1;      /* RequestedInfo */
static int hf_gsm_map_ms_callPriority = -1;       /* EMLPP_Priority */
static int hf_gsm_map_ms_subscriberInfo = -1;     /* SubscriberInfo */
static int hf_gsm_map_ms_locationInformation = -1;  /* LocationInformation */
static int hf_gsm_map_ms_subscriberState = -1;    /* SubscriberState */
static int hf_gsm_map_ms_locationInformationGPRS = -1;  /* LocationInformationGPRS */
static int hf_gsm_map_ms_ps_SubscriberState = -1;  /* PS_SubscriberState */
static int hf_gsm_map_ms_ms_Classmark2 = -1;      /* MS_Classmark2 */
static int hf_gsm_map_ms_gprs_MS_Class = -1;      /* GPRSMSClass */
static int hf_gsm_map_ms_mnpInfoRes = -1;         /* MNPInfoRes */
static int hf_gsm_map_ms_imsVoiceOverPS_SessionsIndication = -1;  /* IMS_VoiceOverPS_SessionsInd */
static int hf_gsm_map_ms_lastUE_ActivityTime = -1;  /* Time */
static int hf_gsm_map_ms_lastRAT_Type = -1;       /* Used_RAT_Type */
static int hf_gsm_map_ms_eps_SubscriberState = -1;  /* PS_SubscriberState */
static int hf_gsm_map_ms_locationInformationEPS = -1;  /* LocationInformationEPS */
static int hf_gsm_map_ms_routeingNumber = -1;     /* RouteingNumber */
static int hf_gsm_map_ms_numberPortabilityStatus = -1;  /* NumberPortabilityStatus */
static int hf_gsm_map_ms_mSNetworkCapability = -1;  /* MSNetworkCapability */
static int hf_gsm_map_ms_mSRadioAccessCapability = -1;  /* MSRadioAccessCapability */
static int hf_gsm_map_ms_locationInformation_01 = -1;  /* NULL */
static int hf_gsm_map_ms_subscriberState_01 = -1;  /* NULL */
static int hf_gsm_map_ms_currentLocation = -1;    /* NULL */
static int hf_gsm_map_ms_requestedDomain = -1;    /* DomainType */
static int hf_gsm_map_ms_imei_01 = -1;            /* NULL */
static int hf_gsm_map_ms_ms_classmark = -1;       /* NULL */
static int hf_gsm_map_ms_mnpRequestedInfo = -1;   /* NULL */
static int hf_gsm_map_ms_t_adsData = -1;          /* NULL */
static int hf_gsm_map_ms_requestedNodes = -1;     /* RequestedNodes */
static int hf_gsm_map_ms_servingNodeIndication = -1;  /* NULL */
static int hf_gsm_map_ms_ageOfLocationInformation = -1;  /* AgeOfLocationInformation */
static int hf_gsm_map_ms_geographicalInformation = -1;  /* GeographicalInformation */
static int hf_gsm_map_ms_vlr_number = -1;         /* ISDN_AddressString */
static int hf_gsm_map_ms_locationNumber = -1;     /* LocationNumber */
static int hf_gsm_map_ms_cellGlobalIdOrServiceAreaIdOrLAI = -1;  /* CellGlobalIdOrServiceAreaIdOrLAI */
static int hf_gsm_map_ms_selectedLSA_Id = -1;     /* LSAIdentity */
static int hf_gsm_map_ms_geodeticInformation = -1;  /* GeodeticInformation */
static int hf_gsm_map_ms_currentLocationRetrieved = -1;  /* NULL */
static int hf_gsm_map_ms_sai_Present = -1;        /* NULL */
static int hf_gsm_map_ms_userCSGInformation = -1;  /* UserCSGInformation */
static int hf_gsm_map_ms_e_utranCellGlobalIdentity = -1;  /* E_UTRAN_CGI */
static int hf_gsm_map_ms_trackingAreaIdentity = -1;  /* TA_Id */
static int hf_gsm_map_ms_mme_Name = -1;           /* DiameterIdentity */
static int hf_gsm_map_ms_routeingAreaIdentity = -1;  /* RAIdentity */
static int hf_gsm_map_ms_selectedLSAIdentity = -1;  /* LSAIdentity */
static int hf_gsm_map_ms_accessMode = -1;         /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ms_cmi = -1;                /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ms_assumedIdle = -1;        /* NULL */
static int hf_gsm_map_ms_camelBusy = -1;          /* NULL */
static int hf_gsm_map_ms_netDetNotReachable = -1;  /* NotReachableReason */
static int hf_gsm_map_ms_notProvidedFromVLR = -1;  /* NULL */
static int hf_gsm_map_ms_notProvidedFromSGSNorMME = -1;  /* NULL */
static int hf_gsm_map_ms_ps_Detached = -1;        /* NULL */
static int hf_gsm_map_ms_ps_AttachedNotReachableForPaging = -1;  /* NULL */
static int hf_gsm_map_ms_ps_AttachedReachableForPaging = -1;  /* NULL */
static int hf_gsm_map_ms_ps_PDP_ActiveNotReachableForPaging = -1;  /* PDP_ContextInfoList */
static int hf_gsm_map_ms_ps_PDP_ActiveReachableForPaging = -1;  /* PDP_ContextInfoList */
static int hf_gsm_map_ms_PDP_ContextInfoList_item = -1;  /* PDP_ContextInfo */
static int hf_gsm_map_ms_pdp_ContextIdentifier = -1;  /* ContextId */
static int hf_gsm_map_ms_pdp_ContextActive = -1;  /* NULL */
static int hf_gsm_map_ms_apn_Subscribed = -1;     /* APN */
static int hf_gsm_map_ms_apn_InUse = -1;          /* APN */
static int hf_gsm_map_ms_nsapi = -1;              /* NSAPI */
static int hf_gsm_map_ms_transactionId = -1;      /* TransactionId */
static int hf_gsm_map_ms_teid_ForGnAndGp = -1;    /* TEID */
static int hf_gsm_map_ms_teid_ForIu = -1;         /* TEID */
static int hf_gsm_map_ms_qos_Subscribed_01 = -1;  /* Ext_QoS_Subscribed */
static int hf_gsm_map_ms_qos_Requested = -1;      /* Ext_QoS_Subscribed */
static int hf_gsm_map_ms_qos_Negotiated = -1;     /* Ext_QoS_Subscribed */
static int hf_gsm_map_ms_chargingId = -1;         /* GPRSChargingID */
static int hf_gsm_map_ms_rnc_Address = -1;        /* GSN_Address */
static int hf_gsm_map_ms_qos2_Subscribed = -1;    /* Ext2_QoS_Subscribed */
static int hf_gsm_map_ms_qos2_Requested = -1;     /* Ext2_QoS_Subscribed */
static int hf_gsm_map_ms_qos2_Negotiated = -1;    /* Ext2_QoS_Subscribed */
static int hf_gsm_map_ms_qos3_Subscribed = -1;    /* Ext3_QoS_Subscribed */
static int hf_gsm_map_ms_qos3_Requested = -1;     /* Ext3_QoS_Subscribed */
static int hf_gsm_map_ms_qos3_Negotiated = -1;    /* Ext3_QoS_Subscribed */
static int hf_gsm_map_ms_qos4_Subscribed = -1;    /* Ext4_QoS_Subscribed */
static int hf_gsm_map_ms_qos4_Requested = -1;     /* Ext4_QoS_Subscribed */
static int hf_gsm_map_ms_qos4_Negotiated = -1;    /* Ext4_QoS_Subscribed */
static int hf_gsm_map_ms_subscriberIdentity = -1;  /* SubscriberIdentity */
static int hf_gsm_map_ms_requestedSubscriptionInfo = -1;  /* RequestedSubscriptionInfo */
static int hf_gsm_map_ms_callForwardingData = -1;  /* CallForwardingData */
static int hf_gsm_map_ms_callBarringData = -1;    /* CallBarringData */
static int hf_gsm_map_ms_odb_Info = -1;           /* ODB_Info */
static int hf_gsm_map_ms_camel_SubscriptionInfo = -1;  /* CAMEL_SubscriptionInfo */
static int hf_gsm_map_ms_supportedVLR_CAMEL_Phases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ms_supportedSGSN_CAMEL_Phases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ms_offeredCamel4CSIsInVLR = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_ms_offeredCamel4CSIsInSGSN = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_ms_msisdn_BS_List = -1;     /* MSISDN_BS_List */
static int hf_gsm_map_ms_csg_SubscriptionDataList = -1;  /* CSG_SubscriptionDataList */
static int hf_gsm_map_ms_cw_Data = -1;            /* CallWaitingData */
static int hf_gsm_map_ms_ch_Data = -1;            /* CallHoldData */
static int hf_gsm_map_ms_clip_Data = -1;          /* ClipData */
static int hf_gsm_map_ms_clir_Data = -1;          /* ClirData */
static int hf_gsm_map_ms_ect_data = -1;           /* EctData */
static int hf_gsm_map_ms_cwFeatureList = -1;      /* Ext_CwFeatureList */
static int hf_gsm_map_ms_Ext_CwFeatureList_item = -1;  /* Ext_CwFeature */
static int hf_gsm_map_ms_overrideCategory = -1;   /* OverrideCategory */
static int hf_gsm_map_ms_cliRestrictionOption = -1;  /* CliRestrictionOption */
static int hf_gsm_map_ms_requestedSS_Info = -1;   /* SS_ForBS_Code */
static int hf_gsm_map_ms_odb = -1;                /* NULL */
static int hf_gsm_map_ms_requestedCAMEL_SubscriptionInfo = -1;  /* RequestedCAMEL_SubscriptionInfo */
static int hf_gsm_map_ms_supportedVLR_CAMEL_Phases_01 = -1;  /* NULL */
static int hf_gsm_map_ms_supportedSGSN_CAMEL_Phases_01 = -1;  /* NULL */
static int hf_gsm_map_ms_additionalRequestedCAMEL_SubscriptionInfo = -1;  /* AdditionalRequestedCAMEL_SubscriptionInfo */
static int hf_gsm_map_ms_msisdn_BS_List_01 = -1;  /* NULL */
static int hf_gsm_map_ms_csg_SubscriptionDataRequested = -1;  /* NULL */
static int hf_gsm_map_ms_cw_Info = -1;            /* NULL */
static int hf_gsm_map_ms_clip_Info = -1;          /* NULL */
static int hf_gsm_map_ms_clir_Info = -1;          /* NULL */
static int hf_gsm_map_ms_hold_Info = -1;          /* NULL */
static int hf_gsm_map_ms_ect_Info = -1;           /* NULL */
static int hf_gsm_map_ms_MSISDN_BS_List_item = -1;  /* MSISDN_BS */
static int hf_gsm_map_ms_password = -1;           /* Password */
static int hf_gsm_map_ms_wrongPasswordAttemptsCounter = -1;  /* WrongPasswordAttemptsCounter */
static int hf_gsm_map_ms_t_CSI = -1;              /* T_CSI */
static int hf_gsm_map_ms_vt_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_ms_tif_CSI_NotificationToCSE = -1;  /* NULL */
static int hf_gsm_map_ms_specificCSIDeletedList = -1;  /* SpecificCSI_Withdraw */
static int hf_gsm_map_ms_o_IM_CSI = -1;           /* O_CSI */
static int hf_gsm_map_ms_o_IM_BcsmCamelTDP_CriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_ms_d_IM_CSI = -1;           /* D_CSI */
static int hf_gsm_map_ms_vt_IM_CSI = -1;          /* T_CSI */
static int hf_gsm_map_ms_vt_IM_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_ms_modificationRequestFor_CF_Info = -1;  /* ModificationRequestFor_CF_Info */
static int hf_gsm_map_ms_modificationRequestFor_CB_Info = -1;  /* ModificationRequestFor_CB_Info */
static int hf_gsm_map_ms_modificationRequestFor_CSI = -1;  /* ModificationRequestFor_CSI */
static int hf_gsm_map_ms_modificationRequestFor_ODB_data = -1;  /* ModificationRequestFor_ODB_data */
static int hf_gsm_map_ms_modificationRequestFor_IP_SM_GW_Data = -1;  /* ModificationRequestFor_IP_SM_GW_Data */
static int hf_gsm_map_ms_activationRequestForUE_reachability = -1;  /* RequestedServingNode */
static int hf_gsm_map_ms_modificationRequestFor_CSG = -1;  /* ModificationRequestFor_CSG */
static int hf_gsm_map_ms_modificationRequestFor_CW_Data = -1;  /* ModificationRequestFor_CW_Info */
static int hf_gsm_map_ms_modificationRequestFor_CLIP_Data = -1;  /* ModificationRequestFor_CLIP_Info */
static int hf_gsm_map_ms_modificationRequestFor_CLIR_Data = -1;  /* ModificationRequestFor_CLIR_Info */
static int hf_gsm_map_ms_modificationRequestFor_HOLD_Data = -1;  /* ModificationRequestFor_CH_Info */
static int hf_gsm_map_ms_modificationRequestFor_ECT_Data = -1;  /* ModificationRequestFor_ECT_Info */
static int hf_gsm_map_ms_modifyNotificationToCSE = -1;  /* ModificationInstruction */
static int hf_gsm_map_ms_ss_InfoFor_CSE = -1;     /* Ext_SS_InfoFor_CSE */
static int hf_gsm_map_ms_serviceCentreAddress = -1;  /* AddressString */
static int hf_gsm_map_ms_forwardedToNumber_01 = -1;  /* AddressString */
static int hf_gsm_map_ms_odb_data = -1;           /* ODB_Data */
static int hf_gsm_map_ms_requestedCamel_SubscriptionInfo = -1;  /* RequestedCAMEL_SubscriptionInfo */
static int hf_gsm_map_ms_modifyCSI_State = -1;    /* ModificationInstruction */
static int hf_gsm_map_ms_modifyRegistrationStatus = -1;  /* ModificationInstruction */
static int hf_gsm_map_ms_forwardingInfoFor_CSE = -1;  /* Ext_ForwardingInfoFor_CSE */
static int hf_gsm_map_ms_callBarringInfoFor_CSE = -1;  /* Ext_CallBarringInfoFor_CSE */
static int hf_gsm_map_ms_allInformationSent = -1;  /* NULL */
static int hf_gsm_map_ms_ue_reachable = -1;       /* ServingNode */
static int hf_gsm_map_ms_eventMet = -1;           /* MM_Code */
static int hf_gsm_map_ms_supportedCAMELPhases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ms_offeredCamel4Functionalities = -1;  /* OfferedCamel4Functionalities */
static int hf_gsm_map_ms_naea_PreferredCI = -1;   /* NAEA_PreferredCI */
static int hf_gsm_map_ms_gprsSubscriptionData = -1;  /* GPRSSubscriptionData */
static int hf_gsm_map_ms_roamingRestrictedInSgsnDueToUnsupportedFeature = -1;  /* NULL */
static int hf_gsm_map_ms_networkAccessMode = -1;  /* NetworkAccessMode */
static int hf_gsm_map_ms_lsaInformation = -1;     /* LSAInformation */
static int hf_gsm_map_ms_lmu_Indicator = -1;      /* NULL */
static int hf_gsm_map_ms_lcsInformation = -1;     /* LCSInformation */
static int hf_gsm_map_ms_istAlertTimer = -1;      /* IST_AlertTimerValue */
static int hf_gsm_map_ms_superChargerSupportedInHLR = -1;  /* AgeIndicator */
static int hf_gsm_map_ms_mc_SS_Info = -1;         /* MC_SS_Info */
static int hf_gsm_map_ms_cs_AllocationRetentionPriority = -1;  /* CS_AllocationRetentionPriority */
static int hf_gsm_map_ms_sgsn_CAMEL_SubscriptionInfo = -1;  /* SGSN_CAMEL_SubscriptionInfo */
static int hf_gsm_map_ms_accessRestrictionData = -1;  /* AccessRestrictionData */
static int hf_gsm_map_ms_ics_Indicator = -1;      /* BOOLEAN */
static int hf_gsm_map_ms_eps_SubscriptionData = -1;  /* EPS_SubscriptionData */
static int hf_gsm_map_ms_ue_ReachabilityRequestIndicator = -1;  /* NULL */
static int hf_gsm_map_ms_subscribedPeriodicRAUTAUtimer = -1;  /* SubscribedPeriodicRAUTAUtimer */
static int hf_gsm_map_ms_vplmnLIPAAllowed = -1;   /* NULL */
static int hf_gsm_map_ms_mdtUserConsent = -1;     /* BOOLEAN */
static int hf_gsm_map_ms_subscribedPeriodicLAUtimer = -1;  /* SubscribedPeriodicLAUtimer */
/* named bits */
static int hf_gsm_map_ms_SupportedRAT_Types_utran = -1;
static int hf_gsm_map_ms_SupportedRAT_Types_geran = -1;
static int hf_gsm_map_ms_SupportedRAT_Types_gan = -1;
static int hf_gsm_map_ms_SupportedRAT_Types_i_hspa_evolution = -1;
static int hf_gsm_map_ms_SupportedRAT_Types_e_utran = -1;
static int hf_gsm_map_ms_SupportedLCS_CapabilitySets_lcsCapabilitySet1 = -1;
static int hf_gsm_map_ms_SupportedLCS_CapabilitySets_lcsCapabilitySet2 = -1;
static int hf_gsm_map_ms_SupportedLCS_CapabilitySets_lcsCapabilitySet3 = -1;
static int hf_gsm_map_ms_SupportedLCS_CapabilitySets_lcsCapabilitySet4 = -1;
static int hf_gsm_map_ms_SupportedLCS_CapabilitySets_lcsCapabilitySet5 = -1;
static int hf_gsm_map_ms_ISR_Information_updateMME = -1;
static int hf_gsm_map_ms_ISR_Information_cancelSGSN = -1;
static int hf_gsm_map_ms_ISR_Information_initialAttachIndicator = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_apn = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_HPLMN_APN = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_VPLMN_APN = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_og = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_international_og = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_int_og_not_to_HPLMN_country = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_interzonal_og = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_interzonal_og_not_to_HPLMN_country = -1;
static int hf_gsm_map_ms_SupportedFeatures_odb_all_interzonal_og_and_internat_og_not_to_HPLMN_country = -1;
static int hf_gsm_map_ms_SupportedFeatures_regSub = -1;
static int hf_gsm_map_ms_SupportedFeatures_trace = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_all_PrivExcep = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_universal = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_CallSessionRelated = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_CallSessionUnrelated = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_PLMN_operator = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_ServiceType = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_all_MOLR_SS = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_basicSelfLocation = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_autonomousSelfLocation = -1;
static int hf_gsm_map_ms_SupportedFeatures_lcs_transferToThirdParty = -1;
static int hf_gsm_map_ms_SupportedFeatures_sm_mo_pp = -1;
static int hf_gsm_map_ms_SupportedFeatures_barring_OutgoingCalls = -1;
static int hf_gsm_map_ms_SupportedFeatures_baoc = -1;
static int hf_gsm_map_ms_SupportedFeatures_boic = -1;
static int hf_gsm_map_ms_SupportedFeatures_boicExHC = -1;
static int hf_gsm_map_ms_LCLS_Negotiation_permission_indicator = -1;
static int hf_gsm_map_ms_LCLS_Negotiation_forward_data_sending_indicator = -1;
static int hf_gsm_map_ms_LCLS_Negotiation_backward_sending_indicator = -1;
static int hf_gsm_map_ms_LCLS_Negotiation_forward_data_reception_indicator = -1;
static int hf_gsm_map_ms_LCLS_Negotiation_backward_data_reception_indicator = -1;
static int hf_gsm_map_ms_RequestedEquipmentInfo_equipmentStatus = -1;
static int hf_gsm_map_ms_RequestedEquipmentInfo_bmuef = -1;
static int hf_gsm_map_ms_AccessRestrictionData_utranNotAllowed = -1;
static int hf_gsm_map_ms_AccessRestrictionData_geranNotAllowed = -1;
static int hf_gsm_map_ms_AccessRestrictionData_ganNotAllowed = -1;
static int hf_gsm_map_ms_AccessRestrictionData_i_hspa_evolutionNotAllowed = -1;
static int hf_gsm_map_ms_AccessRestrictionData_e_utranNotAllowed = -1;
static int hf_gsm_map_ms_AccessRestrictionData_ho_toNon3GPP_AccessNotAllowed = -1;
static int hf_gsm_map_ms_ODB_GeneralData_allOG_CallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_internationalOGCallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_internationalOGCallsNotToHPLMN_CountryBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_interzonalOGCallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_interzonalOGCallsNotToHPLMN_CountryBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_interzonalOGCallsAndInternationalOGCallsNotToHPLMN_CountryBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_premiumRateInformationOGCallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_premiumRateEntertainementOGCallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_ss_AccessBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_allECT_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_chargeableECT_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_internationalECT_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_interzonalECT_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_doublyChargeableECT_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_multipleECT_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_allPacketOrientedServicesBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamerAccessToHPLMN_AP_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamerAccessToVPLMN_AP_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamingOutsidePLMNOG_CallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_allIC_CallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamingOutsidePLMNIC_CallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamingOutsidePLMNICountryIC_CallsBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamingOutsidePLMN_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_roamingOutsidePLMN_CountryBarred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_registrationAllCF_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_registrationCFNotToHPLMN_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_registrationInterzonalCF_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_registrationInterzonalCFNotToHPLMN_Barred = -1;
static int hf_gsm_map_ms_ODB_GeneralData_registrationInternationalCF_Barred = -1;
static int hf_gsm_map_ms_ODB_HPLMN_Data_plmn_SpecificBarringType1 = -1;
static int hf_gsm_map_ms_ODB_HPLMN_Data_plmn_SpecificBarringType2 = -1;
static int hf_gsm_map_ms_ODB_HPLMN_Data_plmn_SpecificBarringType3 = -1;
static int hf_gsm_map_ms_ODB_HPLMN_Data_plmn_SpecificBarringType4 = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_o_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_ss_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_tif_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_d_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_vt_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_mo_sms_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_m_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_gprs_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_t_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_mt_sms_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_mg_csi = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_o_IM_CSI = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_d_IM_CSI = -1;
static int hf_gsm_map_ms_SpecificCSI_Withdraw_vt_IM_CSI = -1;
static int hf_gsm_map_ms_SupportedCamelPhases_phase1 = -1;
static int hf_gsm_map_ms_SupportedCamelPhases_phase2 = -1;
static int hf_gsm_map_ms_SupportedCamelPhases_phase3 = -1;
static int hf_gsm_map_ms_SupportedCamelPhases_phase4 = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_o_csi = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_d_csi = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_vt_csi = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_t_csi = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_mt_sms_csi = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_mg_csi = -1;
static int hf_gsm_map_ms_OfferedCamel4CSIs_psi_enhancements = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_initiateCallAttempt = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_splitLeg = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_moveLeg = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_disconnectLeg = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_entityReleased = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_dfc_WithArgument = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_playTone = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_dtmf_MidCall = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_chargingIndicator = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_alertingDP = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_locationAtAlerting = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_changeOfPositionDP = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_or_Interactions = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_warningToneEnhancements = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_cf_Enhancements = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_subscribedEnhancedDialledServices = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_serviceChangeDP = -1;
static int hf_gsm_map_ms_OfferedCamel4Functionalities_collectInformation = -1;
static int hf_gsm_map_ms_AdditionalSubscriptions_privilegedUplinkRequest = -1;
static int hf_gsm_map_ms_AdditionalSubscriptions_emergencyUplinkRequest = -1;
static int hf_gsm_map_ms_AdditionalSubscriptions_emergencyReset = -1;
static int hf_gsm_map_ms_RequestedNodes_mme = -1;
static int hf_gsm_map_ms_RequestedNodes_sgsn = -1;
static int hf_gsm_map_ms_RequestedServingNode_mmeAndSgsn = -1;
static int hf_gsm_map_ms_ServingNode_mme = -1;
static int hf_gsm_map_ms_ServingNode_sgsn = -1;

/* --- Module MAP-CH-DataTypes --- --- ---                                    */

static int hf_gsm_map_ch_cug_Interlock = -1;      /* CUG_Interlock */
static int hf_gsm_map_ch_cug_OutgoingAccess = -1;  /* NULL */
static int hf_gsm_map_ch_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_ch_msisdn = -1;             /* ISDN_AddressString */
static int hf_gsm_map_ch_cug_CheckInfo = -1;      /* CUG_CheckInfo */
static int hf_gsm_map_ch_numberOfForwarding = -1;  /* NumberOfForwarding */
static int hf_gsm_map_ch_interrogationType = -1;  /* InterrogationType */
static int hf_gsm_map_ch_or_Interrogation = -1;   /* NULL */
static int hf_gsm_map_ch_or_Capability = -1;      /* OR_Phase */
static int hf_gsm_map_ch_gmsc_OrGsmSCF_Address = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ch_callReferenceNumber = -1;  /* CallReferenceNumber */
static int hf_gsm_map_ch_forwardingReason = -1;   /* ForwardingReason */
static int hf_gsm_map_ch_basicServiceGroup = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_ch_networkSignalInfo = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_ch_camelInfo = -1;          /* CamelInfo */
static int hf_gsm_map_ch_suppressionOfAnnouncement = -1;  /* SuppressionOfAnnouncement */
static int hf_gsm_map_ch_alertingPattern = -1;    /* AlertingPattern */
static int hf_gsm_map_ch_ccbs_Call = -1;          /* NULL */
static int hf_gsm_map_ch_supportedCCBS_Phase = -1;  /* SupportedCCBS_Phase */
static int hf_gsm_map_ch_additionalSignalInfo = -1;  /* Ext_ExternalSignalInfo */
static int hf_gsm_map_ch_istSupportIndicator = -1;  /* IST_SupportIndicator */
static int hf_gsm_map_ch_pre_pagingSupported = -1;  /* NULL */
static int hf_gsm_map_ch_callDiversionTreatmentIndicator = -1;  /* CallDiversionTreatmentIndicator */
static int hf_gsm_map_ch_longFTN_Supported = -1;  /* NULL */
static int hf_gsm_map_ch_suppress_VT_CSI = -1;    /* NULL */
static int hf_gsm_map_ch_suppressIncomingCallBarring = -1;  /* NULL */
static int hf_gsm_map_ch_gsmSCF_InitiatedCall = -1;  /* NULL */
static int hf_gsm_map_ch_basicServiceGroup2 = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_ch_networkSignalInfo2 = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_ch_suppressMTSS = -1;       /* SuppressMTSS */
static int hf_gsm_map_ch_mtRoamingRetrySupported = -1;  /* NULL */
static int hf_gsm_map_ch_callPriority = -1;       /* EMLPP_Priority */
static int hf_gsm_map_ch_imsi = -1;               /* IMSI */
static int hf_gsm_map_ch_extendedRoutingInfo = -1;  /* ExtendedRoutingInfo */
static int hf_gsm_map_ch_cugSubscriptionFlag = -1;  /* NULL */
static int hf_gsm_map_ch_subscriberInfo = -1;     /* SubscriberInfo */
static int hf_gsm_map_ch_ss_List = -1;            /* SS_List */
static int hf_gsm_map_ch_basicService = -1;       /* Ext_BasicServiceCode */
static int hf_gsm_map_ch_forwardingInterrogationRequired = -1;  /* NULL */
static int hf_gsm_map_ch_vmsc_Address = -1;       /* ISDN_AddressString */
static int hf_gsm_map_ch_naea_PreferredCI = -1;   /* NAEA_PreferredCI */
static int hf_gsm_map_ch_ccbs_Indicators = -1;    /* CCBS_Indicators */
static int hf_gsm_map_ch_numberPortabilityStatus = -1;  /* NumberPortabilityStatus */
static int hf_gsm_map_ch_istAlertTimer = -1;      /* IST_AlertTimerValue */
static int hf_gsm_map_ch_supportedCamelPhasesInVMSC = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ch_offeredCamel4CSIsInVMSC = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_ch_routingInfo2 = -1;       /* RoutingInfo */
static int hf_gsm_map_ch_ss_List2 = -1;           /* SS_List */
static int hf_gsm_map_ch_basicService2 = -1;      /* Ext_BasicServiceCode */
static int hf_gsm_map_ch_allowedServices = -1;    /* AllowedServices */
static int hf_gsm_map_ch_unavailabilityCause = -1;  /* UnavailabilityCause */
static int hf_gsm_map_ch_releaseResourcesSupported = -1;  /* NULL */
static int hf_gsm_map_ch_gsm_BearerCapability = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_ch_ccbs_Possible = -1;      /* NULL */
static int hf_gsm_map_ch_keepCCBS_CallIndicator = -1;  /* NULL */
static int hf_gsm_map_ch_roamingNumber = -1;      /* ISDN_AddressString */
static int hf_gsm_map_ch_forwardingData = -1;     /* ForwardingData */
static int hf_gsm_map_ch_forwardedToNumber = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ch_forwardedToSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_map_ch_forwardingOptions = -1;  /* ForwardingOptions */
static int hf_gsm_map_ch_longForwardedToNumber = -1;  /* FTN_AddressString */
static int hf_gsm_map_ch_msc_Number = -1;         /* ISDN_AddressString */
static int hf_gsm_map_ch_lmsi = -1;               /* LMSI */
static int hf_gsm_map_ch_gmsc_Address = -1;       /* ISDN_AddressString */
static int hf_gsm_map_ch_supportedCamelPhasesInInterrogatingNode = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ch_orNotSupportedInGMSC = -1;  /* NULL */
static int hf_gsm_map_ch_offeredCamel4CSIsInInterrogatingNode = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_ch_pagingArea = -1;         /* PagingArea */
static int hf_gsm_map_ch_mtrf_Indicator = -1;     /* NULL */
static int hf_gsm_map_ch_oldMSC_Number = -1;      /* ISDN_AddressString */
static int hf_gsm_map_ch_o_CSI = -1;              /* O_CSI */
static int hf_gsm_map_ch_uu_Data = -1;            /* UU_Data */
static int hf_gsm_map_ch_allInformationSent = -1;  /* NULL */
static int hf_gsm_map_ch_d_csi = -1;              /* D_CSI */
static int hf_gsm_map_ch_o_BcsmCamelTDPCriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_ch_mtRoamingRetry = -1;     /* NULL */
static int hf_gsm_map_ch_uuIndicator = -1;        /* UUIndicator */
static int hf_gsm_map_ch_uui = -1;                /* UUI */
static int hf_gsm_map_ch_uusCFInteraction = -1;   /* NULL */
static int hf_gsm_map_ch_supportedCamelPhases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_ch_suppress_T_CSI = -1;     /* NULL */
static int hf_gsm_map_ch_offeredCamel4CSIs = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_ch_routingInfo = -1;        /* RoutingInfo */
static int hf_gsm_map_ch_camelRoutingInfo = -1;   /* CamelRoutingInfo */
static int hf_gsm_map_ch_gmscCamelSubscriptionInfo = -1;  /* GmscCamelSubscriptionInfo */
static int hf_gsm_map_ch_t_CSI = -1;              /* T_CSI */
static int hf_gsm_map_ch_o_BcsmCamelTDP_CriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_ch_t_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_ch_ccbs_Monitoring = -1;    /* ReportingState */
static int hf_gsm_map_ch_ccbs_SubscriberStatus = -1;  /* CCBS_SubscriberStatus */
static int hf_gsm_map_ch_eventReportData = -1;    /* EventReportData */
static int hf_gsm_map_ch_callReportdata = -1;     /* CallReportData */
static int hf_gsm_map_ch_monitoringMode = -1;     /* MonitoringMode */
static int hf_gsm_map_ch_callOutcome = -1;        /* CallOutcome */
static int hf_gsm_map_ch_callInfo = -1;           /* ExternalSignalInfo */
static int hf_gsm_map_ch_ccbs_Feature = -1;       /* CCBS_Feature */
static int hf_gsm_map_ch_translatedB_Number = -1;  /* ISDN_AddressString */
static int hf_gsm_map_ch_replaceB_Number = -1;    /* NULL */
static int hf_gsm_map_ch_ruf_Outcome = -1;        /* RUF_Outcome */
static int hf_gsm_map_ch_istInformationWithdraw = -1;  /* NULL */
static int hf_gsm_map_ch_callTerminationIndicator = -1;  /* CallTerminationIndicator */
static int hf_gsm_map_ch_msrn = -1;               /* ISDN_AddressString */
/* named bits */
static int hf_gsm_map_ch_SuppressMTSS_suppressCUG = -1;
static int hf_gsm_map_ch_SuppressMTSS_suppressCCBS = -1;
static int hf_gsm_map_ch_AllowedServices_firstServiceAllowed = -1;
static int hf_gsm_map_ch_AllowedServices_secondServiceAllowed = -1;

/* --- Module MAP-LCS-DataTypes --- --- ---                                   */

static int hf_gsm_map_lcs_gsm_map_lcs_LCS_ClientID_PDU = -1;  /* LCS_ClientID */
static int hf_gsm_map_lcs_mlcNumber = -1;         /* ISDN_AddressString */
static int hf_gsm_map_lcs_targetMS = -1;          /* SubscriberIdentity */
static int hf_gsm_map_lcs_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_lcs_lcsLocationInfo = -1;   /* LCSLocationInfo */
static int hf_gsm_map_lcs_v_gmlc_Address = -1;    /* GSN_Address */
static int hf_gsm_map_lcs_h_gmlc_Address = -1;    /* GSN_Address */
static int hf_gsm_map_lcs_ppr_Address = -1;       /* GSN_Address */
static int hf_gsm_map_lcs_additional_v_gmlc_Address = -1;  /* GSN_Address */
static int hf_gsm_map_lcs_networkNode_Number = -1;  /* ISDN_AddressString */
static int hf_gsm_map_lcs_lmsi = -1;              /* LMSI */
static int hf_gsm_map_lcs_gprsNodeIndicator = -1;  /* NULL */
static int hf_gsm_map_lcs_additional_Number = -1;  /* Additional_Number */
static int hf_gsm_map_lcs_supportedLCS_CapabilitySets = -1;  /* SupportedLCS_CapabilitySets */
static int hf_gsm_map_lcs_additional_LCS_CapabilitySets = -1;  /* SupportedLCS_CapabilitySets */
static int hf_gsm_map_lcs_mme_Name = -1;          /* DiameterIdentity */
static int hf_gsm_map_lcs_aaa_Server_Name = -1;   /* DiameterIdentity */
static int hf_gsm_map_lcs_locationType = -1;      /* LocationType */
static int hf_gsm_map_lcs_mlc_Number = -1;        /* ISDN_AddressString */
static int hf_gsm_map_lcs_lcs_ClientID = -1;      /* LCS_ClientID */
static int hf_gsm_map_lcs_privacyOverride = -1;   /* NULL */
static int hf_gsm_map_lcs_imsi = -1;              /* IMSI */
static int hf_gsm_map_lcs_msisdn = -1;            /* ISDN_AddressString */
static int hf_gsm_map_lcs_imei = -1;              /* IMEI */
static int hf_gsm_map_lcs_lcs_Priority = -1;      /* LCS_Priority */
static int hf_gsm_map_lcs_lcs_QoS = -1;           /* LCS_QoS */
static int hf_gsm_map_lcs_supportedGADShapes = -1;  /* SupportedGADShapes */
static int hf_gsm_map_lcs_lcs_ReferenceNumber = -1;  /* LCS_ReferenceNumber */
static int hf_gsm_map_lcs_lcsServiceTypeID = -1;  /* LCSServiceTypeID */
static int hf_gsm_map_lcs_lcsCodeword = -1;       /* LCSCodeword */
static int hf_gsm_map_lcs_lcs_PrivacyCheck = -1;  /* LCS_PrivacyCheck */
static int hf_gsm_map_lcs_areaEventInfo = -1;     /* AreaEventInfo */
static int hf_gsm_map_lcs_mo_lrShortCircuitIndicator = -1;  /* NULL */
static int hf_gsm_map_lcs_periodicLDRInfo = -1;   /* PeriodicLDRInfo */
static int hf_gsm_map_lcs_reportingPLMNList = -1;  /* ReportingPLMNList */
static int hf_gsm_map_lcs_locationEstimateType = -1;  /* LocationEstimateType */
static int hf_gsm_map_lcs_deferredLocationEventType = -1;  /* DeferredLocationEventType */
static int hf_gsm_map_lcs_lcsClientType = -1;     /* LCSClientType */
static int hf_gsm_map_lcs_lcsClientExternalID = -1;  /* LCSClientExternalID */
static int hf_gsm_map_lcs_lcsClientDialedByMS = -1;  /* AddressString */
static int hf_gsm_map_lcs_lcsClientInternalID = -1;  /* LCSClientInternalID */
static int hf_gsm_map_lcs_lcsClientName = -1;     /* LCSClientName */
static int hf_gsm_map_lcs_lcsAPN = -1;            /* APN */
static int hf_gsm_map_lcs_lcsRequestorID = -1;    /* LCSRequestorID */
static int hf_gsm_map_lcs_dataCodingScheme = -1;  /* USSD_DataCodingScheme */
static int hf_gsm_map_lcs_nameString = -1;        /* NameString */
static int hf_gsm_map_lcs_lcs_FormatIndicator = -1;  /* LCS_FormatIndicator */
static int hf_gsm_map_lcs_requestorIDString = -1;  /* RequestorIDString */
static int hf_gsm_map_lcs_horizontal_accuracy = -1;  /* Horizontal_Accuracy */
static int hf_gsm_map_lcs_verticalCoordinateRequest = -1;  /* NULL */
static int hf_gsm_map_lcs_vertical_accuracy = -1;  /* Vertical_Accuracy */
static int hf_gsm_map_lcs_responseTime = -1;      /* ResponseTime */
static int hf_gsm_map_lcs_velocityRequest = -1;   /* NULL */
static int hf_gsm_map_lcs_responseTimeCategory = -1;  /* ResponseTimeCategory */
static int hf_gsm_map_lcs_lcsCodewordString = -1;  /* LCSCodewordString */
static int hf_gsm_map_lcs_callSessionUnrelated = -1;  /* PrivacyCheckRelatedAction */
static int hf_gsm_map_lcs_callSessionRelated = -1;  /* PrivacyCheckRelatedAction */
static int hf_gsm_map_lcs_areaDefinition = -1;    /* AreaDefinition */
static int hf_gsm_map_lcs_occurrenceInfo = -1;    /* OccurrenceInfo */
static int hf_gsm_map_lcs_intervalTime = -1;      /* IntervalTime */
static int hf_gsm_map_lcs_areaList = -1;          /* AreaList */
static int hf_gsm_map_lcs_AreaList_item = -1;     /* Area */
static int hf_gsm_map_lcs_areaType = -1;          /* AreaType */
static int hf_gsm_map_lcs_areaIdentification = -1;  /* AreaIdentification */
static int hf_gsm_map_lcs_reportingAmount = -1;   /* ReportingAmount */
static int hf_gsm_map_lcs_reportingInterval = -1;  /* ReportingInterval */
static int hf_gsm_map_lcs_plmn_ListPrioritized = -1;  /* NULL */
static int hf_gsm_map_lcs_plmn_List = -1;         /* PLMNList */
static int hf_gsm_map_lcs_PLMNList_item = -1;     /* ReportingPLMN */
static int hf_gsm_map_lcs_plmn_Id = -1;           /* PLMN_Id */
static int hf_gsm_map_lcs_ran_Technology = -1;    /* RAN_Technology */
static int hf_gsm_map_lcs_ran_PeriodicLocationSupport = -1;  /* NULL */
static int hf_gsm_map_lcs_locationEstimate = -1;  /* Ext_GeographicalInformation */
static int hf_gsm_map_lcs_ageOfLocationEstimate = -1;  /* AgeOfLocationInformation */
static int hf_gsm_map_lcs_add_LocationEstimate = -1;  /* Add_GeographicalInformation */
static int hf_gsm_map_lcs_deferredmt_lrResponseIndicator = -1;  /* NULL */
static int hf_gsm_map_lcs_geranPositioningData = -1;  /* PositioningDataInformation */
static int hf_gsm_map_lcs_utranPositioningData = -1;  /* UtranPositioningDataInfo */
static int hf_gsm_map_lcs_cellIdOrSai = -1;       /* CellGlobalIdOrServiceAreaIdOrLAI */
static int hf_gsm_map_lcs_sai_Present = -1;       /* NULL */
static int hf_gsm_map_lcs_accuracyFulfilmentIndicator = -1;  /* AccuracyFulfilmentIndicator */
static int hf_gsm_map_lcs_velocityEstimate = -1;  /* VelocityEstimate */
static int hf_gsm_map_lcs_geranGANSSpositioningData = -1;  /* GeranGANSSpositioningData */
static int hf_gsm_map_lcs_utranGANSSpositioningData = -1;  /* UtranGANSSpositioningData */
static int hf_gsm_map_lcs_targetServingNodeForHandover = -1;  /* ServingNodeAddress */
static int hf_gsm_map_lcs_lcs_Event = -1;         /* LCS_Event */
static int hf_gsm_map_lcs_na_ESRD = -1;           /* ISDN_AddressString */
static int hf_gsm_map_lcs_na_ESRK = -1;           /* ISDN_AddressString */
static int hf_gsm_map_lcs_slr_ArgExtensionContainer = -1;  /* SLR_ArgExtensionContainer */
static int hf_gsm_map_lcs_deferredmt_lrData = -1;  /* Deferredmt_lrData */
static int hf_gsm_map_lcs_pseudonymIndicator = -1;  /* NULL */
static int hf_gsm_map_lcs_sequenceNumber = -1;    /* SequenceNumber */
static int hf_gsm_map_lcs_terminationCause = -1;  /* TerminationCause */
static int hf_gsm_map_lcs_msc_Number = -1;        /* ISDN_AddressString */
static int hf_gsm_map_lcs_sgsn_Number = -1;       /* ISDN_AddressString */
static int hf_gsm_map_lcs_mme_Number = -1;        /* DiameterIdentity */
/* named bits */
static int hf_gsm_map_lcs_DeferredLocationEventType_msAvailable = -1;
static int hf_gsm_map_lcs_DeferredLocationEventType_enteringIntoArea = -1;
static int hf_gsm_map_lcs_DeferredLocationEventType_leavingFromArea = -1;
static int hf_gsm_map_lcs_DeferredLocationEventType_beingInsideArea = -1;
static int hf_gsm_map_lcs_DeferredLocationEventType_periodicLDR = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_ellipsoidPoint = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_ellipsoidPointWithUncertaintyCircle = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_ellipsoidPointWithUncertaintyEllipse = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_polygon = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_ellipsoidPointWithAltitude = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_ellipsoidPointWithAltitudeAndUncertaintyElipsoid = -1;
static int hf_gsm_map_lcs_SupportedGADShapes_ellipsoidArc = -1;

/* --- Module MAP-GR-DataTypes --- --- ---                                    */

static int hf_gsm_map_gr_teleservice = -1;        /* Ext_TeleserviceCode */
static int hf_gsm_map_gr_asciCallReference = -1;  /* ASCI_CallReference */
static int hf_gsm_map_gr_codec_Info = -1;         /* CODEC_Info */
static int hf_gsm_map_gr_cipheringAlgorithm = -1;  /* CipheringAlgorithm */
static int hf_gsm_map_gr_groupKeyNumber_Vk_Id = -1;  /* GroupKeyNumber */
static int hf_gsm_map_gr_groupKey = -1;           /* Kc */
static int hf_gsm_map_gr_priority = -1;           /* EMLPP_Priority */
static int hf_gsm_map_gr_uplinkFree = -1;         /* NULL */
static int hf_gsm_map_gr_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_gr_vstk = -1;               /* VSTK */
static int hf_gsm_map_gr_vstk_rand = -1;          /* VSTK_RAND */
static int hf_gsm_map_gr_talkerChannelParameter = -1;  /* NULL */
static int hf_gsm_map_gr_uplinkReplyIndicator = -1;  /* NULL */
static int hf_gsm_map_gr_groupCallNumber = -1;    /* ISDN_AddressString */
static int hf_gsm_map_gr_imsi = -1;               /* IMSI */
static int hf_gsm_map_gr_talkerPriority = -1;     /* TalkerPriority */
static int hf_gsm_map_gr_additionalInfo = -1;     /* AdditionalInfo */
static int hf_gsm_map_gr_uplinkRequestAck = -1;   /* NULL */
static int hf_gsm_map_gr_uplinkReleaseIndication = -1;  /* NULL */
static int hf_gsm_map_gr_uplinkRejectCommand = -1;  /* NULL */
static int hf_gsm_map_gr_uplinkSeizedCommand = -1;  /* NULL */
static int hf_gsm_map_gr_uplinkReleaseCommand = -1;  /* NULL */
static int hf_gsm_map_gr_stateAttributes = -1;    /* StateAttributes */
static int hf_gsm_map_gr_emergencyModeResetCommandFlag = -1;  /* NULL */
static int hf_gsm_map_gr_sm_RP_UI = -1;           /* SignalInfo */
static int hf_gsm_map_gr_an_APDU = -1;            /* AccessNetworkSignalInfo */
static int hf_gsm_map_gr_uplinkRequest = -1;      /* NULL */
static int hf_gsm_map_gr_releaseGroupCall = -1;   /* NULL */
static int hf_gsm_map_gr_downlinkAttached = -1;   /* NULL */
static int hf_gsm_map_gr_uplinkAttached = -1;     /* NULL */
static int hf_gsm_map_gr_dualCommunication = -1;  /* NULL */
static int hf_gsm_map_gr_callOriginator = -1;     /* NULL */
static int hf_gsm_map_gr_requestedInfo = -1;      /* RequestedInfo */
static int hf_gsm_map_gr_groupId = -1;            /* Long_GroupId */
static int hf_gsm_map_gr_cellId = -1;             /* GlobalCellId */
static int hf_gsm_map_gr_tmsi = -1;               /* TMSI */
static int hf_gsm_map_gr_cksn = -1;               /* Cksn */
static int hf_gsm_map_gr_anchorMSC_Address = -1;  /* ISDN_AddressString */
static int hf_gsm_map_gr_additionalSubscriptions = -1;  /* AdditionalSubscriptions */
static int hf_gsm_map_gr_kc = -1;                 /* Kc */

/* --- Module MAP-DialogueInformation --- --- ---                             */

static int hf_gsm_map_dialogue_gsm_map_dialogue_MAP_DialoguePDU_PDU = -1;  /* MAP_DialoguePDU */
static int hf_gsm_map_dialogue_map_open = -1;     /* MAP_OpenInfo */
static int hf_gsm_map_dialogue_map_accept = -1;   /* MAP_AcceptInfo */
static int hf_gsm_map_dialogue_map_close = -1;    /* MAP_CloseInfo */
static int hf_gsm_map_dialogue_map_refuse = -1;   /* MAP_RefuseInfo */
static int hf_gsm_map_dialogue_map_userAbort = -1;  /* MAP_UserAbortInfo */
static int hf_gsm_map_dialogue_map_providerAbort = -1;  /* MAP_ProviderAbortInfo */
static int hf_gsm_map_dialogue_destinationReference = -1;  /* AddressString */
static int hf_gsm_map_dialogue_originationReference = -1;  /* AddressString */
static int hf_gsm_map_dialogue_extensionContainer = -1;  /* ExtensionContainer */
static int hf_gsm_map_dialogue_reason = -1;       /* Reason */
static int hf_gsm_map_dialogue_alternativeApplicationContext = -1;  /* OBJECT_IDENTIFIER */
static int hf_gsm_map_dialogue_map_UserAbortChoice = -1;  /* MAP_UserAbortChoice */
static int hf_gsm_map_dialogue_userSpecificReason = -1;  /* NULL */
static int hf_gsm_map_dialogue_userResourceLimitation = -1;  /* NULL */
static int hf_gsm_map_dialogue_resourceUnavailable = -1;  /* ResourceUnavailableReason */
static int hf_gsm_map_dialogue_applicationProcedureCancellation = -1;  /* ProcedureCancellationReason */
static int hf_gsm_map_dialogue_map_ProviderAbortReason = -1;  /* MAP_ProviderAbortReason */

/* --- Module DummyMAP --- --- ---                                            */

static int hf_gsm_old_invoke = -1;                /* Invoke */
static int hf_gsm_old_returnResultLast = -1;      /* ReturnResult */
static int hf_gsm_old_returnError = -1;           /* ReturnError */
static int hf_gsm_old_reject = -1;                /* Reject */
static int hf_gsm_old_returnResultNotLast = -1;   /* ReturnResult */
static int hf_gsm_old_invokeID = -1;              /* InvokeIdType */
static int hf_gsm_old_linkedID = -1;              /* InvokeIdType */
static int hf_gsm_old_opCode = -1;                /* MAP_OPERATION */
static int hf_gsm_old_invokeparameter = -1;       /* InvokeParameter */
static int hf_gsm_old_resultretres = -1;          /* T_resultretres */
static int hf_gsm_old_returnparameter = -1;       /* ReturnResultParameter */
static int hf_gsm_old_errorCode = -1;             /* MAP_ERROR */
static int hf_gsm_old_parameter = -1;             /* ReturnErrorParameter */
static int hf_gsm_old_invokeIDRej = -1;           /* T_invokeIDRej */
static int hf_gsm_old_derivable = -1;             /* InvokeIdType */
static int hf_gsm_old_not_derivable = -1;         /* NULL */
static int hf_gsm_old_problem = -1;               /* T_problem */
static int hf_gsm_old_generalProblem = -1;        /* GeneralProblem */
static int hf_gsm_old_invokeProblem = -1;         /* InvokeProblem */
static int hf_gsm_old_returnResultProblem = -1;   /* ReturnResultProblem */
static int hf_gsm_old_returnErrorProblem = -1;    /* ReturnErrorProblem */
static int hf_gsm_old_localValue = -1;            /* OperationLocalvalue */
static int hf_gsm_old_globalValue = -1;           /* OBJECT_IDENTIFIER */
static int hf_gsm_old_localValue_01 = -1;         /* LocalErrorcode */
static int hf_gsm_old_protocolId = -1;            /* ProtocolId */
static int hf_gsm_old_signalInfo = -1;            /* SignalInfo */
static int hf_gsm_old_extensionContainer = -1;    /* ExtensionContainer */
static int hf_gsm_old_gsm_BearerCapability = -1;  /* ExternalSignalInfo */
static int hf_gsm_old_isdn_BearerCapability = -1;  /* ExternalSignalInfo */
static int hf_gsm_old_call_Direction = -1;        /* CallDirection */
static int hf_gsm_old_b_Subscriber_Address = -1;  /* ISDN_AddressString */
static int hf_gsm_old_chosenChannel = -1;         /* ExternalSignalInfo */
static int hf_gsm_old_lowerLayerCompatibility = -1;  /* ExternalSignalInfo */
static int hf_gsm_old_highLayerCompatibility = -1;  /* ExternalSignalInfo */
static int hf_gsm_old_sIWFSNumber = -1;           /* ISDN_AddressString */
static int hf_gsm_old_imsi = -1;                  /* IMSI */
static int hf_gsm_old_vlr_Number = -1;            /* ISDN_AddressString */
static int hf_gsm_old_targetCellId = -1;          /* GlobalCellId */
static int hf_gsm_old_ho_NumberNotRequired = -1;  /* NULL */
static int hf_gsm_old_bss_APDU = -1;              /* Bss_APDU */
static int hf_gsm_old_handoverNumber = -1;        /* ISDN_AddressString */
static int hf_gsm_old_SendAuthenticationInfoResOld_item = -1;  /* SendAuthenticationInfoResOld_item */
static int hf_gsm_old_rand = -1;                  /* RAND */
static int hf_gsm_old_sres = -1;                  /* SRES */
static int hf_gsm_old_kc = -1;                    /* Kc */
static int hf_gsm_old_tripletList = -1;           /* TripletListold */
static int hf_gsm_old_TripletListold_item = -1;   /* AuthenticationTriplet_v2 */
static int hf_gsm_old_channelType = -1;           /* ExternalSignalInfo */
static int hf_gsm_old_securityHeader = -1;        /* SecurityHeader */
static int hf_gsm_old_protectedPayload = -1;      /* ProtectedPayload */
static int hf_gsm_old_securityParametersIndex = -1;  /* SecurityParametersIndex */
static int hf_gsm_old_originalComponentIdentifier = -1;  /* OriginalComponentIdentifier */
static int hf_gsm_old_initialisationVector = -1;  /* InitialisationVector */
static int hf_gsm_old_operationCode = -1;         /* OperationCode */
static int hf_gsm_old_errorCode_01 = -1;          /* ErrorCode */
static int hf_gsm_old_userInfo = -1;              /* NULL */
static int hf_gsm_old_localValue_02 = -1;         /* INTEGER */
static int hf_gsm_old_msisdn = -1;                /* ISDN_AddressString */
static int hf_gsm_old_category = -1;              /* Category */
static int hf_gsm_old_basicService = -1;          /* BasicServiceCode */
static int hf_gsm_old_operatorSS_Code = -1;       /* T_operatorSS_Code */
static int hf_gsm_old_operatorSS_Code_item = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_gsm_old_sm_RP_DA = -1;              /* SM_RP_DAold */
static int hf_gsm_old_sm_RP_OA = -1;              /* SM_RP_OAold */
static int hf_gsm_old_sm_RP_UI = -1;              /* SignalInfo */
static int hf_gsm_old_moreMessagesToSend = -1;    /* NULL */
static int hf_gsm_old_imsi_01 = -1;               /* T_imsi */
static int hf_gsm_old_lmsi = -1;                  /* T_lmsi */
static int hf_gsm_old_serviceCentreAddressDA = -1;  /* T_serviceCentreAddressDA */
static int hf_gsm_old_noSM_RP_DA = -1;            /* NULL */
static int hf_gsm_old_msisdn_01 = -1;             /* T_msisdn */
static int hf_gsm_old_serviceCentreAddressOA = -1;  /* T_serviceCentreAddressOA */
static int hf_gsm_old_noSM_RP_OA = -1;            /* NULL */
static int hf_gsm_old_cug_CheckInfo = -1;         /* CUG_CheckInfo */
static int hf_gsm_old_numberOfForwarding = -1;    /* NumberOfForwarding */
static int hf_gsm_old_networkSignalInfo = -1;     /* ExternalSignalInfo */
static int hf_gsm_old_routingInfo = -1;           /* RoutingInfo */
static int hf_gsm_old_originatingEntityNumber = -1;  /* ISDN_AddressString */
static int hf_gsm_old_msisdn_02 = -1;             /* AddressString */

/* --- Module SS-DataTypes --- --- ---                                        */

static int hf_gsm_ss_ss_Code = -1;                /* SS_Code */
static int hf_gsm_ss_ss_Status = -1;              /* SS_Status */
static int hf_gsm_ss_ss_Notification = -1;        /* SS_Notification */
static int hf_gsm_ss_callIsWaiting_Indicator = -1;  /* NULL */
static int hf_gsm_ss_callOnHold_Indicator = -1;   /* CallOnHold_Indicator */
static int hf_gsm_ss_mpty_Indicator = -1;         /* NULL */
static int hf_gsm_ss_cug_Index = -1;              /* CUG_Index */
static int hf_gsm_ss_clirSuppressionRejected = -1;  /* NULL */
static int hf_gsm_ss_ect_Indicator = -1;          /* ECT_Indicator */
static int hf_gsm_ss_nameIndicator = -1;          /* NameIndicator */
static int hf_gsm_ss_ccbs_Feature = -1;           /* CCBS_Feature */
static int hf_gsm_ss_alertingPattern = -1;        /* AlertingPattern */
static int hf_gsm_ss_multicall_Indicator = -1;    /* Multicall_Indicator */
static int hf_gsm_ss_chargingInformation = -1;    /* ChargingInformation */
static int hf_gsm_ss_e1 = -1;                     /* E1 */
static int hf_gsm_ss_e2 = -1;                     /* E2 */
static int hf_gsm_ss_e3 = -1;                     /* E3 */
static int hf_gsm_ss_e4 = -1;                     /* E4 */
static int hf_gsm_ss_e5 = -1;                     /* E5 */
static int hf_gsm_ss_e6 = -1;                     /* E6 */
static int hf_gsm_ss_e7 = -1;                     /* E7 */
static int hf_gsm_ss_suppressPrefCUG = -1;        /* NULL */
static int hf_gsm_ss_suppressOA = -1;             /* NULL */
static int hf_gsm_ss_ect_CallState = -1;          /* ECT_CallState */
static int hf_gsm_ss_rdn = -1;                    /* RDN */
static int hf_gsm_ss_callingName = -1;            /* Name */
static int hf_gsm_ss_namePresentationAllowed = -1;  /* NameSet */
static int hf_gsm_ss_presentationRestricted = -1;  /* NULL */
static int hf_gsm_ss_nameUnavailable = -1;        /* NULL */
static int hf_gsm_ss_namePresentationRestricted = -1;  /* NameSet */
static int hf_gsm_ss_dataCodingScheme = -1;       /* USSD_DataCodingScheme */
static int hf_gsm_ss_lengthInCharacters = -1;     /* INTEGER */
static int hf_gsm_ss_nameString = -1;             /* USSD_String */
static int hf_gsm_ss_presentationAllowedAddress = -1;  /* RemotePartyNumber */
static int hf_gsm_ss_numberNotAvailableDueToInterworking = -1;  /* NULL */
static int hf_gsm_ss_presentationRestrictedAddress = -1;  /* RemotePartyNumber */
static int hf_gsm_ss_partyNumber = -1;            /* ISDN_AddressString */
static int hf_gsm_ss_partyNumberSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_ss_deflectedToNumber = -1;      /* AddressString */
static int hf_gsm_ss_deflectedToSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_ss_uUS_Service = -1;            /* UUS_Service */
static int hf_gsm_ss_uUS_Required = -1;           /* BOOLEAN */
static int hf_gsm_ss_notificationType = -1;       /* NotificationToMSUser */
static int hf_gsm_ss_locationType = -1;           /* LocationType */
static int hf_gsm_ss_lcsClientExternalID = -1;    /* LCSClientExternalID */
static int hf_gsm_ss_lcsClientName = -1;          /* LCSClientName */
static int hf_gsm_ss_lcsRequestorID = -1;         /* LCSRequestorID */
static int hf_gsm_ss_lcsCodeword = -1;            /* LCSCodeword */
static int hf_gsm_ss_lcsServiceTypeID = -1;       /* LCSServiceTypeID */
static int hf_gsm_ss_verificationResponse = -1;   /* VerificationResponse */
static int hf_gsm_ss_molr_Type = -1;              /* MOLR_Type */
static int hf_gsm_ss_locationMethod = -1;         /* LocationMethod */
static int hf_gsm_ss_lcs_QoS = -1;                /* LCS_QoS */
static int hf_gsm_ss_mlc_Number = -1;             /* ISDN_AddressString */
static int hf_gsm_ss_gpsAssistanceData = -1;      /* GPSAssistanceData */
static int hf_gsm_ss_supportedGADShapes = -1;     /* SupportedGADShapes */
static int hf_gsm_ss_ageOfLocationInfo = -1;      /* AgeOfLocationInformation */
static int hf_gsm_ss_pseudonymIndicator = -1;     /* NULL */
static int hf_gsm_ss_h_gmlc_address = -1;         /* GSN_Address */
static int hf_gsm_ss_locationEstimate = -1;       /* Ext_GeographicalInformation */
static int hf_gsm_ss_velocityEstimate = -1;       /* VelocityEstimate */
static int hf_gsm_ss_referenceNumber = -1;        /* LCS_ReferenceNumber */
static int hf_gsm_ss_periodicLDRInfo = -1;        /* PeriodicLDRInfo */
static int hf_gsm_ss_locationUpdateRequest = -1;  /* NULL */
static int hf_gsm_ss_sequenceNumber = -1;         /* SequenceNumber */
static int hf_gsm_ss_terminationCause = -1;       /* TerminationCause */
static int hf_gsm_ss_mo_lrShortCircuit = -1;      /* NULL */
static int hf_gsm_ss_ganssAssistanceData = -1;    /* GANSSAssistanceData */
static int hf_gsm_ss_multiplePositioningProtocolPDUs = -1;  /* MultiplePositioningProtocolPDUs */
static int hf_gsm_ss_MultiplePositioningProtocolPDUs_item = -1;  /* PositioningProtocolPDU */
static int hf_gsm_ss_decipheringKeys = -1;        /* DecipheringKeys */
static int hf_gsm_ss_add_LocationEstimate = -1;   /* Add_GeographicalInformation */
static int hf_gsm_ss_reportingPLMNList = -1;      /* ReportingPLMNList */
static int hf_gsm_ss_deferredLocationEventType = -1;  /* DeferredLocationEventType */
static int hf_gsm_ss_areaEventInfo = -1;          /* AreaEventInfo */
static int hf_gsm_ss_qoS = -1;                    /* LCS_QoS */

/*--- End of included file: packet-gsm_map-hf.c ---*/
////#line 152 "../../asn1/gsm_map/packet-gsm_map-template.c"

/* Initialize the subtree pointers */
static gint ett_gsm_map = -1;
static gint ett_gsm_map_InvokeId = -1;
static gint ett_gsm_map_InvokePDU = -1;
static gint ett_gsm_map_ReturnResultPDU = -1;
static gint ett_gsm_map_ReturnErrorPDU = -1;
static gint ett_gsm_map_ReturnResult_result = -1;
static gint ett_gsm_map_ReturnError_result = -1;
static gint ett_gsm_map_GSMMAPPDU = -1;
static gint ett_gsm_map_ext_qos_subscribed = -1;
static gint ett_gsm_map_pdptypenumber = -1;
static gint ett_gsm_map_RAIdentity = -1;
static gint ett_gsm_map_LAIFixedLength = -1;
static gint ett_gsm_map_isdn_address_string = -1;
static gint ett_gsm_map_geo_desc = -1;
static gint ett_gsm_map_LongSignalInfo = -1;
static gint ett_gsm_map_RadioResourceInformation =-1;
static gint ett_gsm_map_MSNetworkCapability =-1;
static gint ett_gsm_map_MSRadioAccessCapability = -1;
static gint ett_gsm_map_externalsignalinfo = -1;
static gint ett_gsm_map_cbs_data_coding = -1;
static gint ett_gsm_map_GlobalCellId = -1;
static gint ett_gsm_map_GeographicalInformation = -1;
static gint ett_gsm_map_apn_str = -1;
static gint ett_gsm_map_LocationNumber = -1;


/*--- Included file: packet-gsm_map-ett.c ---*/
////#line 1 "../../asn1/gsm_map/packet-gsm_map-ett.c"

/* --- Module MAP-ExtensionDataTypes --- --- ---                              */

static gint ett_gsm_map_ExtensionContainer = -1;
static gint ett_gsm_map_SLR_ArgExtensionContainer = -1;
static gint ett_gsm_map_PrivateExtensionList = -1;
static gint ett_gsm_map_PrivateExtension = -1;
static gint ett_gsm_map_PCS_Extensions = -1;
static gint ett_gsm_map_SLR_Arg_PCS_Extensions = -1;

/* --- Module MAP-CommonDataTypes --- --- ---                                 */

static gint ett_gsm_map_ExternalSignalInfo = -1;
static gint ett_gsm_map_Ext_ExternalSignalInfo = -1;
static gint ett_gsm_map_AccessNetworkSignalInfo = -1;
static gint ett_gsm_map_Identity = -1;
static gint ett_gsm_map_IMSI_WithLMSI = -1;
static gint ett_gsm_map_HLR_List = -1;
static gint ett_gsm_map_NAEA_PreferredCI = -1;
static gint ett_gsm_map_SubscriberIdentity = -1;
static gint ett_gsm_map_LCSClientExternalID = -1;
static gint ett_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI = -1;
static gint ett_gsm_map_BasicServiceCode = -1;
static gint ett_gsm_map_Ext_BasicServiceCode = -1;
static gint ett_gsm_map_EMLPP_Info = -1;
static gint ett_gsm_map_MC_SS_Info = -1;

/* --- Module MAP-SS-DataTypes --- --- ---                                    */

static gint ett_gsm_map_ss_RegisterSS_Arg = -1;
static gint ett_gsm_map_ss_SS_Info = -1;
static gint ett_gsm_map_ss_ForwardingInfo = -1;
static gint ett_gsm_map_ss_ForwardingFeatureList = -1;
static gint ett_gsm_map_ss_ForwardingFeature = -1;
static gint ett_gsm_map_ss_CallBarringInfo = -1;
static gint ett_gsm_map_ss_CallBarringFeatureList = -1;
static gint ett_gsm_map_ss_CallBarringFeature = -1;
static gint ett_gsm_map_ss_SS_Data = -1;
static gint ett_gsm_map_ss_SS_SubscriptionOption = -1;
static gint ett_gsm_map_ss_SS_ForBS_Code = -1;
static gint ett_gsm_map_ss_GenericServiceInfo = -1;
static gint ett_gsm_map_ss_CCBS_FeatureList = -1;
static gint ett_gsm_map_ss_CCBS_Feature = -1;
static gint ett_gsm_map_ss_InterrogateSS_Res = -1;
static gint ett_gsm_map_ss_USSD_Arg = -1;
static gint ett_gsm_map_ss_USSD_Res = -1;
static gint ett_gsm_map_ss_SS_List = -1;
static gint ett_gsm_map_ss_BasicServiceGroupList = -1;
static gint ett_gsm_map_ss_SS_InvocationNotificationArg = -1;
static gint ett_gsm_map_ss_SS_InvocationNotificationRes = -1;
static gint ett_gsm_map_ss_SS_EventSpecification = -1;
static gint ett_gsm_map_ss_RegisterCC_EntryArg = -1;
static gint ett_gsm_map_ss_CCBS_Data = -1;
static gint ett_gsm_map_ss_ServiceIndicator = -1;
static gint ett_gsm_map_ss_RegisterCC_EntryRes = -1;
static gint ett_gsm_map_ss_EraseCC_EntryArg = -1;
static gint ett_gsm_map_ss_EraseCC_EntryRes = -1;

/* --- Module MAP-ER-DataTypes --- --- ---                                    */

static gint ett_gsm_map_er_RoamingNotAllowedParam = -1;
static gint ett_gsm_map_er_CallBarredParam = -1;
static gint ett_gsm_map_er_ExtensibleCallBarredParam = -1;
static gint ett_gsm_map_er_CUG_RejectParam = -1;
static gint ett_gsm_map_er_SS_IncompatibilityCause = -1;
static gint ett_gsm_map_er_SM_DeliveryFailureCause = -1;
static gint ett_gsm_map_er_AbsentSubscriberSM_Param = -1;
static gint ett_gsm_map_er_SystemFailureParam = -1;
static gint ett_gsm_map_er_ExtensibleSystemFailureParam = -1;
static gint ett_gsm_map_er_DataMissingParam = -1;
static gint ett_gsm_map_er_UnexpectedDataParam = -1;
static gint ett_gsm_map_er_FacilityNotSupParam = -1;
static gint ett_gsm_map_er_OR_NotAllowedParam = -1;
static gint ett_gsm_map_er_UnknownSubscriberParam = -1;
static gint ett_gsm_map_er_NumberChangedParam = -1;
static gint ett_gsm_map_er_UnidentifiedSubParam = -1;
static gint ett_gsm_map_er_IllegalSubscriberParam = -1;
static gint ett_gsm_map_er_IllegalEquipmentParam = -1;
static gint ett_gsm_map_er_BearerServNotProvParam = -1;
static gint ett_gsm_map_er_TeleservNotProvParam = -1;
static gint ett_gsm_map_er_TracingBufferFullParam = -1;
static gint ett_gsm_map_er_NoRoamingNbParam = -1;
static gint ett_gsm_map_er_AbsentSubscriberParam = -1;
static gint ett_gsm_map_er_BusySubscriberParam = -1;
static gint ett_gsm_map_er_NoSubscriberReplyParam = -1;
static gint ett_gsm_map_er_ForwardingViolationParam = -1;
static gint ett_gsm_map_er_ForwardingFailedParam = -1;
static gint ett_gsm_map_er_ATI_NotAllowedParam = -1;
static gint ett_gsm_map_er_ATSI_NotAllowedParam = -1;
static gint ett_gsm_map_er_ATM_NotAllowedParam = -1;
static gint ett_gsm_map_er_IllegalSS_OperationParam = -1;
static gint ett_gsm_map_er_SS_NotAvailableParam = -1;
static gint ett_gsm_map_er_SS_SubscriptionViolationParam = -1;
static gint ett_gsm_map_er_InformationNotAvailableParam = -1;
static gint ett_gsm_map_er_SubBusyForMT_SMS_Param = -1;
static gint ett_gsm_map_er_MessageWaitListFullParam = -1;
static gint ett_gsm_map_er_ResourceLimitationParam = -1;
static gint ett_gsm_map_er_NoGroupCallNbParam = -1;
static gint ett_gsm_map_er_IncompatibleTerminalParam = -1;
static gint ett_gsm_map_er_ShortTermDenialParam = -1;
static gint ett_gsm_map_er_LongTermDenialParam = -1;
static gint ett_gsm_map_er_UnauthorizedRequestingNetwork_Param = -1;
static gint ett_gsm_map_er_UnauthorizedLCSClient_Param = -1;
static gint ett_gsm_map_er_PositionMethodFailure_Param = -1;
static gint ett_gsm_map_er_UnknownOrUnreachableLCSClient_Param = -1;
static gint ett_gsm_map_er_MM_EventNotSupported_Param = -1;
static gint ett_gsm_map_er_TargetCellOutsideGCA_Param = -1;
static gint ett_gsm_map_er_OngoingGroupCallParam = -1;

/* --- Module MAP-SM-DataTypes --- --- ---                                    */

static gint ett_gsm_map_sm_RoutingInfoForSM_Arg = -1;
static gint ett_gsm_map_sm_RoutingInfoForSM_Res = -1;
static gint ett_gsm_map_sm_IP_SM_GW_Guidance = -1;
static gint ett_gsm_map_sm_LocationInfoWithLMSI = -1;
static gint ett_gsm_map_sm_Additional_Number = -1;
static gint ett_gsm_map_sm_MO_ForwardSM_Arg = -1;
static gint ett_gsm_map_sm_MO_ForwardSM_Res = -1;
static gint ett_gsm_map_sm_MT_ForwardSM_Arg = -1;
static gint ett_gsm_map_sm_MT_ForwardSM_Res = -1;
static gint ett_gsm_map_sm_SM_RP_DA = -1;
static gint ett_gsm_map_sm_SM_RP_OA = -1;
static gint ett_gsm_map_sm_ReportSM_DeliveryStatusArg = -1;
static gint ett_gsm_map_sm_ReportSM_DeliveryStatusRes = -1;
static gint ett_gsm_map_sm_AlertServiceCentreArg = -1;
static gint ett_gsm_map_sm_InformServiceCentreArg = -1;
static gint ett_gsm_map_sm_MW_Status = -1;
static gint ett_gsm_map_sm_ReadyForSM_Arg = -1;
static gint ett_gsm_map_sm_ReadyForSM_Res = -1;
static gint ett_gsm_map_sm_MT_ForwardSM_VGCS_Arg = -1;
static gint ett_gsm_map_sm_MT_ForwardSM_VGCS_Res = -1;
static gint ett_gsm_map_sm_DispatcherList = -1;

/* --- Module MAP-OM-DataTypes --- --- ---                                    */

static gint ett_gsm_map_om_ActivateTraceModeArg = -1;
static gint ett_gsm_map_om_MDT_Configuration = -1;
static gint ett_gsm_map_om_AreaScope = -1;
static gint ett_gsm_map_om_CGI_List = -1;
static gint ett_gsm_map_om_E_UTRAN_CGI_List = -1;
static gint ett_gsm_map_om_RoutingAreaId_List = -1;
static gint ett_gsm_map_om_LocationAreaId_List = -1;
static gint ett_gsm_map_om_TrackingAreaId_List = -1;
static gint ett_gsm_map_om_TraceDepthList = -1;
static gint ett_gsm_map_om_TraceNE_TypeList = -1;
static gint ett_gsm_map_om_TraceInterfaceList = -1;
static gint ett_gsm_map_om_MSC_S_InterfaceList = -1;
static gint ett_gsm_map_om_MGW_InterfaceList = -1;
static gint ett_gsm_map_om_SGSN_InterfaceList = -1;
static gint ett_gsm_map_om_GGSN_InterfaceList = -1;
static gint ett_gsm_map_om_RNC_InterfaceList = -1;
static gint ett_gsm_map_om_BMSC_InterfaceList = -1;
static gint ett_gsm_map_om_MME_InterfaceList = -1;
static gint ett_gsm_map_om_SGW_InterfaceList = -1;
static gint ett_gsm_map_om_PGW_InterfaceList = -1;
static gint ett_gsm_map_om_ENB_InterfaceList = -1;
static gint ett_gsm_map_om_TraceEventList = -1;
static gint ett_gsm_map_om_MSC_S_EventList = -1;
static gint ett_gsm_map_om_MGW_EventList = -1;
static gint ett_gsm_map_om_SGSN_EventList = -1;
static gint ett_gsm_map_om_GGSN_EventList = -1;
static gint ett_gsm_map_om_BMSC_EventList = -1;
static gint ett_gsm_map_om_MME_EventList = -1;
static gint ett_gsm_map_om_SGW_EventList = -1;
static gint ett_gsm_map_om_PGW_EventList = -1;
static gint ett_gsm_map_om_TracePropagationList = -1;
static gint ett_gsm_map_om_ActivateTraceModeRes = -1;
static gint ett_gsm_map_om_DeactivateTraceModeArg = -1;
static gint ett_gsm_map_om_DeactivateTraceModeRes = -1;

/* --- Module MAP-MS-DataTypes --- --- ---                                    */

static gint ett_gsm_map_ms_UpdateLocationArg = -1;
static gint ett_gsm_map_ms_VLR_Capability = -1;
static gint ett_gsm_map_ms_SupportedRAT_Types = -1;
static gint ett_gsm_map_ms_SuperChargerInfo = -1;
static gint ett_gsm_map_ms_SupportedLCS_CapabilitySets = -1;
static gint ett_gsm_map_ms_UpdateLocationRes = -1;
static gint ett_gsm_map_ms_ADD_Info = -1;
static gint ett_gsm_map_ms_PagingArea = -1;
static gint ett_gsm_map_ms_LocationArea = -1;
static gint ett_gsm_map_ms_CancelLocationArg_U = -1;
static gint ett_gsm_map_ms_CancelLocationRes = -1;
static gint ett_gsm_map_ms_PurgeMS_Arg_U = -1;
static gint ett_gsm_map_ms_PurgeMS_Res = -1;
static gint ett_gsm_map_ms_SendIdentificationArg = -1;
static gint ett_gsm_map_ms_SendIdentificationRes_U = -1;
static gint ett_gsm_map_ms_AuthenticationSetList = -1;
static gint ett_gsm_map_ms_TripletList = -1;
static gint ett_gsm_map_ms_QuintupletList = -1;
static gint ett_gsm_map_ms_AuthenticationTriplet = -1;
static gint ett_gsm_map_ms_AuthenticationQuintuplet = -1;
static gint ett_gsm_map_ms_CurrentSecurityContext = -1;
static gint ett_gsm_map_ms_GSM_SecurityContextData = -1;
static gint ett_gsm_map_ms_UMTS_SecurityContextData = -1;
static gint ett_gsm_map_ms_AuthenticationFailureReportArg = -1;
static gint ett_gsm_map_ms_AuthenticationFailureReportRes = -1;
static gint ett_gsm_map_ms_UpdateGprsLocationArg = -1;
static gint ett_gsm_map_ms_EPS_Info = -1;
static gint ett_gsm_map_ms_PDN_GW_Update = -1;
static gint ett_gsm_map_ms_ISR_Information = -1;
static gint ett_gsm_map_ms_SGSN_Capability = -1;
static gint ett_gsm_map_ms_SupportedFeatures = -1;
static gint ett_gsm_map_ms_UpdateGprsLocationRes = -1;
static gint ett_gsm_map_ms_ForwardAccessSignalling_Arg_U = -1;
static gint ett_gsm_map_ms_AllowedUMTS_Algorithms = -1;
static gint ett_gsm_map_ms_PrepareHO_Arg_U = -1;
static gint ett_gsm_map_ms_LCLS_Negotiation = -1;
static gint ett_gsm_map_ms_BSSMAP_ServiceHandoverList = -1;
static gint ett_gsm_map_ms_BSSMAP_ServiceHandoverInfo = -1;
static gint ett_gsm_map_ms_RadioResourceList = -1;
static gint ett_gsm_map_ms_RadioResource = -1;
static gint ett_gsm_map_ms_PrepareHO_Res_U = -1;
static gint ett_gsm_map_ms_SelectedUMTS_Algorithms = -1;
static gint ett_gsm_map_ms_ChosenRadioResourceInformation = -1;
static gint ett_gsm_map_ms_PrepareSubsequentHO_Arg_U = -1;
static gint ett_gsm_map_ms_PrepareSubsequentHO_Res_U = -1;
static gint ett_gsm_map_ms_ProcessAccessSignalling_Arg_U = -1;
static gint ett_gsm_map_ms_AoIPCodecsList = -1;
static gint ett_gsm_map_ms_SupportedCodecsList = -1;
static gint ett_gsm_map_ms_CodecList = -1;
static gint ett_gsm_map_ms_SendEndSignal_Arg_U = -1;
static gint ett_gsm_map_ms_SendEndSignal_Res = -1;
static gint ett_gsm_map_ms_RelocationNumberList = -1;
static gint ett_gsm_map_ms_RelocationNumber = -1;
static gint ett_gsm_map_ms_SendAuthenticationInfoArg = -1;
static gint ett_gsm_map_ms_Re_synchronisationInfo = -1;
static gint ett_gsm_map_ms_SendAuthenticationInfoRes_U = -1;
static gint ett_gsm_map_ms_EPS_AuthenticationSetList = -1;
static gint ett_gsm_map_ms_EPC_AV = -1;
static gint ett_gsm_map_ms_CheckIMEI_Arg = -1;
static gint ett_gsm_map_ms_CheckIMEI_Res = -1;
static gint ett_gsm_map_ms_RequestedEquipmentInfo = -1;
static gint ett_gsm_map_ms_UESBI_Iu = -1;
static gint ett_gsm_map_ms_InsertSubscriberDataArg = -1;
static gint ett_gsm_map_ms_CSG_SubscriptionDataList = -1;
static gint ett_gsm_map_ms_CSG_SubscriptionData = -1;
static gint ett_gsm_map_ms_LIPA_AllowedAPNList = -1;
static gint ett_gsm_map_ms_EPS_SubscriptionData = -1;
static gint ett_gsm_map_ms_APN_ConfigurationProfile = -1;
static gint ett_gsm_map_ms_EPS_DataList = -1;
static gint ett_gsm_map_ms_APN_Configuration = -1;
static gint ett_gsm_map_ms_EPS_QoS_Subscribed = -1;
static gint ett_gsm_map_ms_AMBR = -1;
static gint ett_gsm_map_ms_SpecificAPNInfoList = -1;
static gint ett_gsm_map_ms_SpecificAPNInfo = -1;
static gint ett_gsm_map_ms_Allocation_Retention_Priority = -1;
static gint ett_gsm_map_ms_PDN_GW_Identity = -1;
static gint ett_gsm_map_ms_AccessRestrictionData = -1;
static gint ett_gsm_map_ms_LCSInformation = -1;
static gint ett_gsm_map_ms_GMLC_List = -1;
static gint ett_gsm_map_ms_GPRSDataList = -1;
static gint ett_gsm_map_ms_PDP_Context = -1;
static gint ett_gsm_map_ms_GPRSSubscriptionData = -1;
static gint ett_gsm_map_ms_SGSN_CAMEL_SubscriptionInfo = -1;
static gint ett_gsm_map_ms_GPRS_CSI = -1;
static gint ett_gsm_map_ms_GPRS_CamelTDPDataList = -1;
static gint ett_gsm_map_ms_GPRS_CamelTDPData = -1;
static gint ett_gsm_map_ms_LSADataList = -1;
static gint ett_gsm_map_ms_LSAData = -1;
static gint ett_gsm_map_ms_LSAInformation = -1;
static gint ett_gsm_map_ms_SubscriberData = -1;
static gint ett_gsm_map_ms_BearerServiceList = -1;
static gint ett_gsm_map_ms_TeleserviceList = -1;
static gint ett_gsm_map_ms_ODB_Data = -1;
static gint ett_gsm_map_ms_ODB_GeneralData = -1;
static gint ett_gsm_map_ms_ODB_HPLMN_Data = -1;
static gint ett_gsm_map_ms_Ext_SS_InfoList = -1;
static gint ett_gsm_map_ms_Ext_SS_Info = -1;
static gint ett_gsm_map_ms_Ext_ForwInfo = -1;
static gint ett_gsm_map_ms_Ext_ForwFeatureList = -1;
static gint ett_gsm_map_ms_Ext_ForwFeature = -1;
static gint ett_gsm_map_ms_Ext_CallBarInfo = -1;
static gint ett_gsm_map_ms_Ext_CallBarFeatureList = -1;
static gint ett_gsm_map_ms_Ext_CallBarringFeature = -1;
static gint ett_gsm_map_ms_CUG_Info = -1;
static gint ett_gsm_map_ms_CUG_SubscriptionList = -1;
static gint ett_gsm_map_ms_CUG_Subscription = -1;
static gint ett_gsm_map_ms_CUG_FeatureList = -1;
static gint ett_gsm_map_ms_Ext_BasicServiceGroupList = -1;
static gint ett_gsm_map_ms_CUG_Feature = -1;
static gint ett_gsm_map_ms_Ext_SS_Data = -1;
static gint ett_gsm_map_ms_LCS_PrivacyExceptionList = -1;
static gint ett_gsm_map_ms_LCS_PrivacyClass = -1;
static gint ett_gsm_map_ms_ExternalClientList = -1;
static gint ett_gsm_map_ms_PLMNClientList = -1;
static gint ett_gsm_map_ms_Ext_ExternalClientList = -1;
static gint ett_gsm_map_ms_ExternalClient = -1;
static gint ett_gsm_map_ms_ServiceTypeList = -1;
static gint ett_gsm_map_ms_ServiceType = -1;
static gint ett_gsm_map_ms_MOLR_List = -1;
static gint ett_gsm_map_ms_MOLR_Class = -1;
static gint ett_gsm_map_ms_ZoneCodeList = -1;
static gint ett_gsm_map_ms_InsertSubscriberDataRes = -1;
static gint ett_gsm_map_ms_DeleteSubscriberDataArg = -1;
static gint ett_gsm_map_ms_SpecificCSI_Withdraw = -1;
static gint ett_gsm_map_ms_GPRSSubscriptionDataWithdraw = -1;
static gint ett_gsm_map_ms_EPS_SubscriptionDataWithdraw = -1;
static gint ett_gsm_map_ms_ContextIdList = -1;
static gint ett_gsm_map_ms_LSAInformationWithdraw = -1;
static gint ett_gsm_map_ms_LSAIdentityList = -1;
static gint ett_gsm_map_ms_BasicServiceList = -1;
static gint ett_gsm_map_ms_DeleteSubscriberDataRes = -1;
static gint ett_gsm_map_ms_VlrCamelSubscriptionInfo = -1;
static gint ett_gsm_map_ms_MT_smsCAMELTDP_CriteriaList = -1;
static gint ett_gsm_map_ms_MT_smsCAMELTDP_Criteria = -1;
static gint ett_gsm_map_ms_TPDU_TypeCriterion = -1;
static gint ett_gsm_map_ms_D_CSI = -1;
static gint ett_gsm_map_ms_DP_AnalysedInfoCriteriaList = -1;
static gint ett_gsm_map_ms_DP_AnalysedInfoCriterium = -1;
static gint ett_gsm_map_ms_SS_CSI = -1;
static gint ett_gsm_map_ms_SS_CamelData = -1;
static gint ett_gsm_map_ms_SS_EventList = -1;
static gint ett_gsm_map_ms_O_CSI = -1;
static gint ett_gsm_map_ms_O_BcsmCamelTDPDataList = -1;
static gint ett_gsm_map_ms_O_BcsmCamelTDPData = -1;
static gint ett_gsm_map_ms_O_BcsmCamelTDPCriteriaList = -1;
static gint ett_gsm_map_ms_T_BCSM_CAMEL_TDP_CriteriaList = -1;
static gint ett_gsm_map_ms_O_BcsmCamelTDP_Criteria = -1;
static gint ett_gsm_map_ms_T_BCSM_CAMEL_TDP_Criteria = -1;
static gint ett_gsm_map_ms_DestinationNumberCriteria = -1;
static gint ett_gsm_map_ms_DestinationNumberList = -1;
static gint ett_gsm_map_ms_DestinationNumberLengthList = -1;
static gint ett_gsm_map_ms_BasicServiceCriteria = -1;
static gint ett_gsm_map_ms_O_CauseValueCriteria = -1;
static gint ett_gsm_map_ms_T_CauseValueCriteria = -1;
static gint ett_gsm_map_ms_SupportedCamelPhases = -1;
static gint ett_gsm_map_ms_OfferedCamel4CSIs = -1;
static gint ett_gsm_map_ms_OfferedCamel4Functionalities = -1;
static gint ett_gsm_map_ms_SMS_CSI = -1;
static gint ett_gsm_map_ms_SMS_CAMEL_TDP_DataList = -1;
static gint ett_gsm_map_ms_SMS_CAMEL_TDP_Data = -1;
static gint ett_gsm_map_ms_M_CSI = -1;
static gint ett_gsm_map_ms_MG_CSI = -1;
static gint ett_gsm_map_ms_MobilityTriggers = -1;
static gint ett_gsm_map_ms_T_CSI = -1;
static gint ett_gsm_map_ms_T_BcsmCamelTDPDataList = -1;
static gint ett_gsm_map_ms_T_BcsmCamelTDPData = -1;
static gint ett_gsm_map_ms_SendRoutingInfoForGprsArg = -1;
static gint ett_gsm_map_ms_SendRoutingInfoForGprsRes = -1;
static gint ett_gsm_map_ms_FailureReportArg = -1;
static gint ett_gsm_map_ms_FailureReportRes = -1;
static gint ett_gsm_map_ms_NoteMsPresentForGprsArg = -1;
static gint ett_gsm_map_ms_NoteMsPresentForGprsRes = -1;
static gint ett_gsm_map_ms_ResetArg = -1;
static gint ett_gsm_map_ms_RestoreDataArg = -1;
static gint ett_gsm_map_ms_RestoreDataRes = -1;
static gint ett_gsm_map_ms_VBSDataList = -1;
static gint ett_gsm_map_ms_VGCSDataList = -1;
static gint ett_gsm_map_ms_VoiceGroupCallData = -1;
static gint ett_gsm_map_ms_AdditionalSubscriptions = -1;
static gint ett_gsm_map_ms_VoiceBroadcastData = -1;
static gint ett_gsm_map_ms_ProvideSubscriberInfoArg = -1;
static gint ett_gsm_map_ms_ProvideSubscriberInfoRes = -1;
static gint ett_gsm_map_ms_SubscriberInfo = -1;
static gint ett_gsm_map_ms_MNPInfoRes = -1;
static gint ett_gsm_map_ms_GPRSMSClass = -1;
static gint ett_gsm_map_ms_RequestedInfo = -1;
static gint ett_gsm_map_ms_RequestedNodes = -1;
static gint ett_gsm_map_ms_LocationInformation = -1;
static gint ett_gsm_map_ms_LocationInformationEPS = -1;
static gint ett_gsm_map_ms_LocationInformationGPRS = -1;
static gint ett_gsm_map_ms_UserCSGInformation = -1;
static gint ett_gsm_map_ms_SubscriberState = -1;
static gint ett_gsm_map_ms_PS_SubscriberState = -1;
static gint ett_gsm_map_ms_PDP_ContextInfoList = -1;
static gint ett_gsm_map_ms_PDP_ContextInfo = -1;
static gint ett_gsm_map_ms_AnyTimeInterrogationArg = -1;
static gint ett_gsm_map_ms_AnyTimeInterrogationRes = -1;
static gint ett_gsm_map_ms_AnyTimeSubscriptionInterrogationArg = -1;
static gint ett_gsm_map_ms_AnyTimeSubscriptionInterrogationRes = -1;
static gint ett_gsm_map_ms_CallWaitingData = -1;
static gint ett_gsm_map_ms_Ext_CwFeatureList = -1;
static gint ett_gsm_map_ms_Ext_CwFeature = -1;
static gint ett_gsm_map_ms_ClipData = -1;
static gint ett_gsm_map_ms_ClirData = -1;
static gint ett_gsm_map_ms_CallHoldData = -1;
static gint ett_gsm_map_ms_EctData = -1;
static gint ett_gsm_map_ms_RequestedSubscriptionInfo = -1;
static gint ett_gsm_map_ms_MSISDN_BS_List = -1;
static gint ett_gsm_map_ms_MSISDN_BS = -1;
static gint ett_gsm_map_ms_CallForwardingData = -1;
static gint ett_gsm_map_ms_CallBarringData = -1;
static gint ett_gsm_map_ms_ODB_Info = -1;
static gint ett_gsm_map_ms_CAMEL_SubscriptionInfo = -1;
static gint ett_gsm_map_ms_AnyTimeModificationArg = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CW_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CH_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_ECT_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CLIR_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CLIP_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CSG = -1;
static gint ett_gsm_map_ms_RequestedServingNode = -1;
static gint ett_gsm_map_ms_ServingNode = -1;
static gint ett_gsm_map_ms_AnyTimeModificationRes = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CF_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CB_Info = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_ODB_data = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_CSI = -1;
static gint ett_gsm_map_ms_ModificationRequestFor_IP_SM_GW_Data = -1;
static gint ett_gsm_map_ms_NoteSubscriberDataModifiedArg = -1;
static gint ett_gsm_map_ms_NoteSubscriberDataModifiedRes = -1;
static gint ett_gsm_map_ms_NoteMM_EventArg = -1;
static gint ett_gsm_map_ms_NoteMM_EventRes = -1;
static gint ett_gsm_map_ms_Ext_SS_InfoFor_CSE = -1;
static gint ett_gsm_map_ms_Ext_ForwardingInfoFor_CSE = -1;
static gint ett_gsm_map_ms_Ext_CallBarringInfoFor_CSE = -1;

/* --- Module MAP-CH-DataTypes --- --- ---                                    */

static gint ett_gsm_map_ch_CUG_CheckInfo = -1;
static gint ett_gsm_map_ch_SendRoutingInfoArg = -1;
static gint ett_gsm_map_ch_SuppressMTSS = -1;
static gint ett_gsm_map_ch_SendRoutingInfoRes_U = -1;
static gint ett_gsm_map_ch_AllowedServices = -1;
static gint ett_gsm_map_ch_CCBS_Indicators = -1;
static gint ett_gsm_map_ch_RoutingInfo = -1;
static gint ett_gsm_map_ch_ForwardingData = -1;
static gint ett_gsm_map_ch_ProvideRoamingNumberArg = -1;
static gint ett_gsm_map_ch_ProvideRoamingNumberRes = -1;
static gint ett_gsm_map_ch_ResumeCallHandlingArg = -1;
static gint ett_gsm_map_ch_UU_Data = -1;
static gint ett_gsm_map_ch_ResumeCallHandlingRes = -1;
static gint ett_gsm_map_ch_CamelInfo = -1;
static gint ett_gsm_map_ch_ExtendedRoutingInfo = -1;
static gint ett_gsm_map_ch_CamelRoutingInfo = -1;
static gint ett_gsm_map_ch_GmscCamelSubscriptionInfo = -1;
static gint ett_gsm_map_ch_SetReportingStateArg = -1;
static gint ett_gsm_map_ch_SetReportingStateRes = -1;
static gint ett_gsm_map_ch_StatusReportArg = -1;
static gint ett_gsm_map_ch_EventReportData = -1;
static gint ett_gsm_map_ch_CallReportData = -1;
static gint ett_gsm_map_ch_StatusReportRes = -1;
static gint ett_gsm_map_ch_RemoteUserFreeArg = -1;
static gint ett_gsm_map_ch_RemoteUserFreeRes = -1;
static gint ett_gsm_map_ch_IST_AlertArg = -1;
static gint ett_gsm_map_ch_IST_AlertRes = -1;
static gint ett_gsm_map_ch_IST_CommandArg = -1;
static gint ett_gsm_map_ch_IST_CommandRes = -1;
static gint ett_gsm_map_ch_ReleaseResourcesArg = -1;
static gint ett_gsm_map_ch_ReleaseResourcesRes = -1;

/* --- Module MAP-LCS-DataTypes --- --- ---                                   */

static gint ett_gsm_map_lcs_RoutingInfoForLCS_Arg = -1;
static gint ett_gsm_map_lcs_RoutingInfoForLCS_Res = -1;
static gint ett_gsm_map_lcs_LCSLocationInfo = -1;
static gint ett_gsm_map_lcs_ProvideSubscriberLocation_Arg = -1;
static gint ett_gsm_map_lcs_LocationType = -1;
static gint ett_gsm_map_lcs_DeferredLocationEventType = -1;
static gint ett_gsm_map_lcs_LCS_ClientID = -1;
static gint ett_gsm_map_lcs_LCSClientName = -1;
static gint ett_gsm_map_lcs_LCSRequestorID = -1;
static gint ett_gsm_map_lcs_LCS_QoS = -1;
static gint ett_gsm_map_lcs_ResponseTime = -1;
static gint ett_gsm_map_lcs_SupportedGADShapes = -1;
static gint ett_gsm_map_lcs_LCSCodeword = -1;
static gint ett_gsm_map_lcs_LCS_PrivacyCheck = -1;
static gint ett_gsm_map_lcs_AreaEventInfo = -1;
static gint ett_gsm_map_lcs_AreaDefinition = -1;
static gint ett_gsm_map_lcs_AreaList = -1;
static gint ett_gsm_map_lcs_Area = -1;
static gint ett_gsm_map_lcs_PeriodicLDRInfo = -1;
static gint ett_gsm_map_lcs_ReportingPLMNList = -1;
static gint ett_gsm_map_lcs_PLMNList = -1;
static gint ett_gsm_map_lcs_ReportingPLMN = -1;
static gint ett_gsm_map_lcs_ProvideSubscriberLocation_Res = -1;
static gint ett_gsm_map_lcs_SubscriberLocationReport_Arg = -1;
static gint ett_gsm_map_lcs_Deferredmt_lrData = -1;
static gint ett_gsm_map_lcs_ServingNodeAddress = -1;
static gint ett_gsm_map_lcs_SubscriberLocationReport_Res = -1;

/* --- Module MAP-GR-DataTypes --- --- ---                                    */

static gint ett_gsm_map_gr_PrepareGroupCallArg = -1;
static gint ett_gsm_map_gr_PrepareGroupCallRes = -1;
static gint ett_gsm_map_gr_SendGroupCallEndSignalArg = -1;
static gint ett_gsm_map_gr_SendGroupCallEndSignalRes = -1;
static gint ett_gsm_map_gr_ForwardGroupCallSignallingArg = -1;
static gint ett_gsm_map_gr_ProcessGroupCallSignallingArg = -1;
static gint ett_gsm_map_gr_StateAttributes = -1;
static gint ett_gsm_map_gr_SendGroupCallInfoArg = -1;
static gint ett_gsm_map_gr_SendGroupCallInfoRes = -1;

/* --- Module MAP-DialogueInformation --- --- ---                             */

static gint ett_gsm_map_dialogue_MAP_DialoguePDU = -1;
static gint ett_gsm_map_dialogue_MAP_OpenInfo = -1;
static gint ett_gsm_map_dialogue_MAP_AcceptInfo = -1;
static gint ett_gsm_map_dialogue_MAP_CloseInfo = -1;
static gint ett_gsm_map_dialogue_MAP_RefuseInfo = -1;
static gint ett_gsm_map_dialogue_MAP_UserAbortInfo = -1;
static gint ett_gsm_map_dialogue_MAP_UserAbortChoice = -1;
static gint ett_gsm_map_dialogue_MAP_ProviderAbortInfo = -1;

/* --- Module MAP-LocationServiceOperations --- --- ---                       */


/* --- Module MAP-Group-Call-Operations --- --- ---                           */


/* --- Module MAP-ShortMessageServiceOperations --- --- ---                   */


/* --- Module MAP-SupplementaryServiceOperations --- --- ---                  */


/* --- Module MAP-CallHandlingOperations --- --- ---                          */


/* --- Module MAP-OperationAndMaintenanceOperations --- --- ---               */


/* --- Module MAP-MobileServiceOperations --- --- ---                         */


/* --- Module MAP-Errors --- --- ---                                          */


/* --- Module MAP-Protocol --- --- ---                                        */


/* --- Module DummyMAP --- --- ---                                            */

static gint ett_gsm_old_Component = -1;
static gint ett_gsm_old_Invoke = -1;
static gint ett_gsm_old_ReturnResult = -1;
static gint ett_gsm_old_T_resultretres = -1;
static gint ett_gsm_old_ReturnError = -1;
static gint ett_gsm_old_Reject = -1;
static gint ett_gsm_old_T_invokeIDRej = -1;
static gint ett_gsm_old_T_problem = -1;
static gint ett_gsm_old_MAP_OPERATION = -1;
static gint ett_gsm_old_MAP_ERROR = -1;
static gint ett_gsm_old_Bss_APDU = -1;
static gint ett_gsm_old_ProvideSIWFSNumberArg = -1;
static gint ett_gsm_old_ProvideSIWFSNumberRes = -1;
static gint ett_gsm_old_PurgeMSArgV2 = -1;
static gint ett_gsm_old_PrepareHO_ArgOld = -1;
static gint ett_gsm_old_PrepareHO_ResOld = -1;
static gint ett_gsm_old_SendAuthenticationInfoResOld = -1;
static gint ett_gsm_old_SendAuthenticationInfoResOld_item = -1;
static gint ett_gsm_old_SendIdentificationResV2 = -1;
static gint ett_gsm_old_TripletListold = -1;
static gint ett_gsm_old_AuthenticationTriplet_v2 = -1;
static gint ett_gsm_old_SIWFSSignallingModifyArg = -1;
static gint ett_gsm_old_SIWFSSignallingModifyRes = -1;
static gint ett_gsm_old_SecureTransportArg = -1;
static gint ett_gsm_old_SecureTransportErrorParam = -1;
static gint ett_gsm_old_SecureTransportRes = -1;
static gint ett_gsm_old_SecurityHeader = -1;
static gint ett_gsm_old_OriginalComponentIdentifier = -1;
static gint ett_gsm_old_OperationCode = -1;
static gint ett_gsm_old_ErrorCode = -1;
static gint ett_gsm_old_PlmnContainer_U = -1;
static gint ett_gsm_old_T_operatorSS_Code = -1;
static gint ett_gsm_old_ForwardSM_Arg = -1;
static gint ett_gsm_old_SM_RP_DAold = -1;
static gint ett_gsm_old_SM_RP_OAold = -1;
static gint ett_gsm_old_SendRoutingInfoArgV2 = -1;
static gint ett_gsm_old_SendRoutingInfoResV2 = -1;
static gint ett_gsm_old_BeginSubscriberActivityArg = -1;

/* --- Module SS-DataTypes --- --- ---                                        */

static gint ett_gsm_ss_NotifySS_Arg = -1;
static gint ett_gsm_ss_ForwardChargeAdviceArg = -1;
static gint ett_gsm_ss_ChargingInformation = -1;
static gint ett_gsm_ss_ForwardCUG_InfoArg = -1;
static gint ett_gsm_ss_ECT_Indicator = -1;
static gint ett_gsm_ss_NameIndicator = -1;
static gint ett_gsm_ss_Name = -1;
static gint ett_gsm_ss_NameSet = -1;
static gint ett_gsm_ss_RDN = -1;
static gint ett_gsm_ss_RemotePartyNumber = -1;
static gint ett_gsm_ss_AccessRegisterCCEntryArg = -1;
static gint ett_gsm_ss_CallDeflectionArg = -1;
static gint ett_gsm_ss_UserUserServiceArg = -1;
static gint ett_gsm_ss_LocationNotificationArg = -1;
static gint ett_gsm_ss_LocationNotificationRes = -1;
static gint ett_gsm_ss_LCS_MOLRArg = -1;
static gint ett_gsm_ss_MultiplePositioningProtocolPDUs = -1;
static gint ett_gsm_ss_LCS_MOLRRes = -1;
static gint ett_gsm_ss_LCS_AreaEventRequestArg = -1;
static gint ett_gsm_ss_LCS_AreaEventReportArg = -1;
static gint ett_gsm_ss_LCS_AreaEventCancellationArg = -1;
static gint ett_gsm_ss_LCS_PeriodicLocationRequestArg = -1;
static gint ett_gsm_ss_LCS_PeriodicLocationRequestRes = -1;
static gint ett_gsm_ss_LCS_LocationUpdateArg = -1;
static gint ett_gsm_ss_LCS_LocationUpdateRes = -1;
static gint ett_gsm_ss_LCS_PeriodicLocationCancellationArg = -1;

/* --- Module SS-Operations --- --- ---                                       */


/*--- End of included file: packet-gsm_map-ett.c ---*/
////#line 180 "../../asn1/gsm_map/packet-gsm_map-template.c"

static dissector_handle_t	data_handle;
static dissector_handle_t	ranap_handle;
static dissector_handle_t	map_handle;
static dissector_table_t	map_prop_arg_opcode_table; /* prorietary operation codes */
static dissector_table_t	map_prop_res_opcode_table; /* prorietary operation codes */
static dissector_table_t	map_prop_err_opcode_table; /* prorietary operation codes */
/* Preferenc settings default */
#define MAX_SSN 254
//static range_t *global_ssn_range;

/* Global variables */
static guint32 opcode=0;
static guint32 errorCode;
//static proto_tree *top_tree;
static int application_context_version;
static guint ProtocolId;
static guint AccessNetworkProtocolId;
static const char *obj_id = NULL;
static int gsm_map_tap = -1;

static gboolean tapping_is_active=FALSE;
static guint tap_packet_index;



#define TAP_PACKET_QUEUE_LEN 100
static tap_packet_t tap_packet_array[TAP_PACKET_QUEUE_LEN];

/************************************************************/
static gboolean show_internal_ber_fields = FALSE;
static gboolean decode_octetstring_as_ber = FALSE;
static gboolean decode_primitive_as_ber = FALSE;
static gboolean decode_unexpected = FALSE;
static gboolean decode_warning_leading_zero_bits = FALSE;

static gint8 last_class;
static gboolean last_pc;
static gint32 last_tag;
static guint32 last_length;
static gboolean last_ind;

#define G_GINT64_MODIFIER "l"

static gint proto_ber = -1;
static gint hf_ber_id_class = -1;
static gint hf_ber_id_pc = -1;
static gint hf_ber_id_uni_tag = -1;
static gint hf_ber_id_uni_tag_ext = -1;
static gint hf_ber_id_tag = -1;
static gint hf_ber_id_tag_ext = -1;
static gint hf_ber_length = -1;
static gint hf_ber_bitstring_padding = -1;
static gint hf_ber_bitstring_empty = -1;
static gint hf_ber_unknown_OID = -1;
static gint hf_ber_unknown_BOOLEAN = -1;
static gint hf_ber_unknown_OCTETSTRING = -1;
static gint hf_ber_unknown_BER_OCTETSTRING = -1;
static gint hf_ber_unknown_BER_primitive = -1;
static gint hf_ber_unknown_GraphicString = -1;
static gint hf_ber_unknown_NumericString = -1;
static gint hf_ber_unknown_PrintableString = -1;
static gint hf_ber_unknown_TeletexString = -1;
static gint hf_ber_unknown_VisibleString = -1;
static gint hf_ber_unknown_GeneralString = -1;
static gint hf_ber_unknown_UniversalString = -1;
static gint hf_ber_unknown_BMPString = -1;
static gint hf_ber_unknown_IA5String = -1;
static gint hf_ber_unknown_UTCTime = -1;
static gint hf_ber_unknown_UTF8String = -1;
static gint hf_ber_unknown_GeneralizedTime = -1;
static gint hf_ber_unknown_INTEGER = -1;
static gint hf_ber_unknown_BITSTRING = -1;
static gint hf_ber_unknown_ENUMERATED = -1;
static gint hf_ber_error = -1;
static gint hf_ber_no_oid = -1;
static gint hf_ber_no_syntax = -1;
static gint hf_ber_oid_not_implemented = -1;
static gint hf_ber_syntax_not_implemented = -1;
static gint hf_ber_direct_reference = -1;         /* OBJECT_IDENTIFIER */
static gint hf_ber_indirect_reference = -1;       /* INTEGER */
static gint hf_ber_data_value_descriptor = -1;    /* ObjectDescriptor */
static gint hf_ber_encoding = -1;                 /* T_encoding */
static gint hf_ber_single_ASN1_type = -1;         /* T_single_ASN1_type */
static gint hf_ber_octet_aligned = -1;            /* OCTET_STRING */
static gint hf_ber_arbitrary = -1;                /* BIT_STRING */

static int hf_ber_fragments = -1;
static int hf_ber_fragment = -1;
static int hf_ber_fragment_overlap = -1;
static int hf_ber_fragment_overlap_conflicts = -1;
static int hf_ber_fragment_multiple_tails = -1;
static int hf_ber_fragment_too_long_fragment = -1;
static int hf_ber_fragment_error = -1;
static int hf_ber_fragment_count = -1;
static int hf_ber_reassembled_in = -1;
static int hf_ber_reassembled_length = -1;

static gint ett_ber_octet_string = -1;
static gint ett_ber_reassembled_octet_string = -1;
static gint ett_ber_primitive = -1;
static gint ett_ber_unknown = -1;
static gint ett_ber_SEQUENCE = -1;
static gint ett_ber_EXTERNAL = -1;
static gint ett_ber_T_encoding = -1;
static gint ett_ber_fragment = -1;
static gint ett_ber_fragments = -1;
typedef struct _asn1_stack_frame_t {
  const gchar *name;
  struct _asn1_par_t *par;
  struct _asn1_stack_frame_t *next;
} asn1_stack_frame_t;
static dissector_table_t tp_dissector_table;
typedef struct _fragment_data {
	struct _fragment_data *next;
	guint32 frame;
	guint32	offset;
	guint32	len;
	guint32 datalen; /* Only valid in first item of list and when
                          * flags&FD_DATALEN_SET is set;
                          * number of bytes or (if flags&FD_BLOCKSEQUENCE set)
                          * segments in the datagram */
	guint32 reassembled_in;	/* frame where this PDU was reassembled,
				   only valid in the first item of the list
				   and when FD_DEFRAGMENTED is set*/
	guint32 flags;
	unsigned char *data;
} fragment_data;

static gboolean debug_use_memory_scrubber = FALSE;

static emem_header_t ep_packet_mem;
static emem_header_t se_packet_mem;

typedef guint32 gunichar;

#define GN_CHAR_ALPHABET_SIZE 128

#define GN_CHAR_ESCAPE 0x1b

static gunichar gsm_default_alphabet[GN_CHAR_ALPHABET_SIZE] = {

    /* ETSI GSM 03.38, version 6.0.1, section 6.2.1; Default alphabet */
    /* Fixed to use unicode */
    /* Characters in hex position 10, [12 to 1a] and 24 are not present on
       latin1 charset, so we cannot reproduce on the screen, however they are
       greek symbol not present even on my Nokia */

    '@',   0xa3,  '$',   0xa5,  0xe8,  0xe9,  0xf9,  0xec,
    0xf2,  0xc7,  '\n',  0xd8,  0xf8,  '\r',  0xc5,  0xe5,
    0x394, '_',   0x3a6, 0x393, 0x39b, 0x3a9, 0x3a0, 0x3a8,
    0x3a3, 0x398, 0x39e, 0xa0,  0xc6,  0xe6,  0xdf,  0xc9,
    ' ',   '!',   '\"',  '#',   0xa4,  '%',   '&',   '\'',
    '(',   ')',   '*',   '+',   ',',   '-',   '.',   '/',
    '0',   '1',   '2',   '3',   '4',   '5',   '6',   '7',
    '8',   '9',   ':',   ';',   '<',   '=',   '>',   '?',
    0xa1,  'A',   'B',   'C',   'D',   'E',   'F',   'G',
    'H',   'I',   'J',   'K',   'L',   'M',   'N',   'O',
    'P',   'Q',   'R',   'S',   'T',   'U',   'V',   'W',
    'X',   'Y',   'Z',   0xc4,  0xd6,  0xd1,  0xdc,  0xa7,
    0xbf,  'a',   'b',   'c',   'd',   'e',   'f',   'g',
    'h',   'i',   'j',   'k',   'l',   'm',   'n',   'o',
    'p',   'q',   'r',   's',   't',   'u',   'v',   'w',
    'x',   'y',   'z',   0xe4,  0xf6,  0xf1,  0xfc,  0xe0
};

/* Initialize the subtree pointers */
static gint ett_dtap_msg = -1;
static gint ett_dtap_oct_1 = -1;
static gint ett_cm_srvc_type = -1;
static gint ett_gsm_enc_info = -1;
static gint ett_bc_oct_3 = -1;
static gint ett_bc_oct_3a = -1;
static gint ett_bc_oct_4 = -1;
static gint ett_bc_oct_5 = -1;
static gint ett_bc_oct_5a = -1;
static gint ett_bc_oct_5b = -1;
static gint ett_bc_oct_6 = -1;
static gint ett_bc_oct_6a = -1;
static gint ett_bc_oct_6b = -1;
static gint ett_bc_oct_6c = -1;
static gint ett_bc_oct_6d = -1;
static gint ett_bc_oct_6e = -1;
static gint ett_bc_oct_6f = -1;
static gint ett_bc_oct_6g = -1;
static gint ett_bc_oct_7 = -1;
static gint ett_epc_ue_tl_a_lb_setup = -1;
static gint ett_mm_timer = -1;

static char a_bigbuf[1024];

static gint is_uplink;
static guint8 epc_test_loop_mode;

/*
 * this should be set on a per message basis, if possible
 */
#define IS_UPLINK_FALSE     0
#define IS_UPLINK_TRUE      1
#define IS_UPLINK_UNKNOWN   2


#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
       /* proto_tree_add_text( tvb,*/ \
            /*curr_offset, (edc_len) - (edc_max_len), "Extraneous Data"); */\
        curr_offset += ((edc_len) - (edc_max_len)); \
    }

static int hf_text_only = -1;

static field_info *field_info_tmp = NULL;
#define FIELD_INFO_NEW(fi)					\
	fi = sl_alloc(&field_info_slab)
#define FIELD_INFO_FREE(fi)					\
	sl_free(&field_info_slab, fi)

typedef struct _gpa_hfinfo_t {
	guint32             len;
	guint32             allocated_len;
	header_field_info **hfi;
} gpa_hfinfo_t;


//#define PROTO_REGISTRAR_GET_NTH(hfindex, hfinfo) \
//	/*DISSECTOR_ASSERT((guint)hfindex < gpa_hfinfo.len);*/ \
//	hfinfo = gpa_hfinfo.hfi[hfindex];

struct dtbl_entry {
	dissector_handle_t initial;
	dissector_handle_t current;
};
typedef struct dtbl_entry dtbl_entry_t;

typedef struct hf_register_info {
	int						*p_id;		 /**< written to by register() function */
	header_field_info		hfinfo;      /**< the field info to be registered */
} hf_register_info;

#define TFS(x)	(const struct true_false_string*)(x)
#define VALS(x)	(const struct _value_string*)(x)
#define RVALS(x) (const struct _range_string*)(x)

#define HFILL 0, 0, HF_REF_TYPE_NONE, 0, NULL, NULL

static dissector_table_t ber_oid_dissector_table=NULL;
static dissector_table_t ber_syntax_dissector_table=NULL;
static const true_false_string gsm_map_extension_value;

#define FI_HIDDEN		0x00000001
#define FI_GET_FLAG(fi, flag)   ((fi) ? ((fi)->flags & (flag)) : 0)
#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)
#define PITEM_FINFO(proto_item)  PNODE_FINFO(proto_item)
#define PROTO_ITEM_IS_HIDDEN(proto_item)        \
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN) : 0)
#define ITEM_LABEL_NEW(il)				\
	il = sl_alloc(&item_label_slab);

static gboolean reassemble_sms = TRUE;
static char bigbuf[1024];
#define GN_BYTE_MASK ((1 << bits) - 1)
#define ISUPPER(c)              ((c) >= 'A' && (c) <= 'Z')
#define ISLOWER(c)              ((c) >= 'a' && (c) <= 'z')
#define ISALPHA(c)              (ISUPPER (c) || ISLOWER (c))
#define TOUPPER(c)              (ISLOWER (c) ? (c) - 'a' + 'A' : (c))
#define TOLOWER(c)              (ISUPPER (c) ? (c) - 'A' + 'a' : (c))
#define SMS_MAX_MESSAGE_SIZE 160
static char    messagebuf[SMS_MAX_MESSAGE_SIZE+1];
#define MAX_SMS_FRAG_LEN      134

static guint16   g_sm_id;
static guint16   g_frags;
static guint16   g_frag;
static packet_info *g_pinfo;
static gint ett_gsm_sms_ud_fragment = -1;
static gint ett_gsm_sms_ud_fragments = -1;
static guint16   g_port_src;
static guint16   g_port_dst;
static gboolean  g_is_wsp;
static dissector_table_t gsm_sms_dissector_tbl;
typedef guint16 gunichar2;

#define pletohs(p)  ((guint16)                       \
                     ((guint16)*((const guint8 *)(p)+1)<<8|  \
                      (guint16)*((const guint8 *)(p)+0)<<0))

#define NUL_TERMINATOR_LENGTH 4
#define EINVAL          22      /* Invalid argument */
#define E2BIG            7      /* Arg list too long */
//#define EILSEQ          84      /* Illegal byte sequence */
#undef iconv_t
#define iconv_t libiconv_t
typedef void* iconv_t;
//#define iconv
#define FD_BLOCKSEQUENCE        0x0100

static guint8 message_type = 0;
#define BoundsError		1
#define ReportedBoundsError	2
#define TypeError		3
#define DissectorError		4
#define SCCP_MSG_TYPE_OFFSET 0
#define SCCP_MSG_TYPE_LENGTH 1
#define SCCP_MSG_TYPE_CR    0x01
#define SCCP_MSG_TYPE_CC    0x02
#define SCCP_MSG_TYPE_CREF  0x03
#define SCCP_MSG_TYPE_RLSD  0x04
#define SCCP_MSG_TYPE_RLC   0x05
#define SCCP_MSG_TYPE_DT1   0x06
#define SCCP_MSG_TYPE_DT2   0x07
#define SCCP_MSG_TYPE_AK    0x08
#define SCCP_MSG_TYPE_UDT   0x09
#define SCCP_MSG_TYPE_UDTS  0x0a
#define SCCP_MSG_TYPE_ED    0x0b
#define SCCP_MSG_TYPE_EA    0x0c
#define SCCP_MSG_TYPE_RSR   0x0d
#define SCCP_MSG_TYPE_RSC   0x0e
#define SCCP_MSG_TYPE_ERR   0x0f
#define SCCP_MSG_TYPE_IT    0x10
#define SCCP_MSG_TYPE_XUDT  0x11
#define SCCP_MSG_TYPE_XUDTS 0x12
#define SCCP_MSG_TYPE_LUDT  0x13
#define SCCP_MSG_TYPE_LUDTS 0x14
#define PARAMETER_CLASS                         0x05
#define PROTOCOL_CLASS_LENGTH                   1
#define POINTER_LENGTH       1
#define POINTER_LENGTH_LONG  2
#define PARAMETER_IMPORTANCE                    0x12
#define PARAMETER_LONG_DATA                     0x13
#define PARAMETER_CALLED_PARTY_ADDRESS          0x03
#define PARAMETER_CALLING_PARTY_ADDRESS         0x04
#define PARAMETER_CLASS                         0x05
#define PARAMETER_DATA                          0x0f
#define PARAMETER_LENGTH_LENGTH                 1
#define PARAMETER_LONG_DATA_LENGTH_LENGTH       2

#define PARAMETER_END_OF_OPTIONAL_PARAMETERS    0x00
#define PARAMETER_DESTINATION_LOCAL_REFERENCE   0x01
#define PARAMETER_SOURCE_LOCAL_REFERENCE        0x02
#define PARAMETER_CALLED_PARTY_ADDRESS          0x03
#define PARAMETER_CALLING_PARTY_ADDRESS         0x04
#define PARAMETER_CLASS                         0x05
#define PARAMETER_SEGMENTING_REASSEMBLING       0x06
#define PARAMETER_RECEIVE_SEQUENCE_NUMBER       0x07
#define PARAMETER_SEQUENCING_SEGMENTING         0x08
#define PARAMETER_CREDIT                        0x09
#define PARAMETER_RELEASE_CAUSE                 0x0a
#define PARAMETER_RETURN_CAUSE                  0x0b
#define PARAMETER_RESET_CAUSE                   0x0c
#define PARAMETER_ERROR_CAUSE                   0x0d
#define PARAMETER_REFUSAL_CAUSE                 0x0e
#define PARAMETER_DATA                          0x0f
#define PARAMETER_SEGMENTATION                  0x10
#define PARAMETER_HOP_COUNTER                   0x11
#define PARAMETER_ISNI                          0xfa
static guint32  sccp_source_pc_global = 0;
static gboolean sccp_show_length      = FALSE;
#define CLASS_CLASS_MASK                0xf
#define CLASS_SPARE_HANDLING_MASK       0xf0
#define CLASS_SPARE_HANDLING_SHIFT      4

#define ITU_RESERVED_MASK               0x80
#define ANSI_NATIONAL_MASK              0x80
#define ROUTING_INDICATOR_MASK          0x40
#define GTI_MASK                        0x3C
#define GTI_SHIFT                       2
#define ITU_SSN_INDICATOR_MASK          0x02
#define ITU_PC_INDICATOR_MASK           0x01
#define ANSI_PC_INDICATOR_MASK          0x02
#define ANSI_SSN_INDICATOR_MASK         0x01
typedef enum {
  ITU_STANDARD  = 1,
  ANSI_STANDARD = 2,
  CHINESE_ITU_STANDARD = 3,
  JAPAN_STANDARD = 4
} Standard_Type;
static Standard_Type decode_mtp3_standard;
#define ROUTE_ON_GT             0x0
#define ROUTE_ON_SSN            0x1
#define ROUTING_INDICATOR_SHIFT 6

#define ADDRESS_INDICATOR_LENGTH        1
#define ITU_RESERVED_MASK               0x80
#define ANSI_NATIONAL_MASK              0x80
#define ROUTING_INDICATOR_MASK          0x40
#define GTI_MASK                        0x3C
#define GTI_SHIFT                       2
#define ITU_SSN_INDICATOR_MASK          0x02
#define ITU_PC_INDICATOR_MASK           0x01
#define ANSI_PC_INDICATOR_MASK          0x02
#define ANSI_SSN_INDICATOR_MASK         0x01
#define ITU_PC_LENGTH     2
#define JAPAN_PC_LENGTH   2
#define JAPAN_PC_MASK     0xffff

#define ANSI_PC_LENGTH    3
#define ANSI_NCM_LENGTH   1
#define ANSI_NETWORK_OFFSET 2
#define ANSI_CLUSTER_OFFSET 1
#define ANSI_MEMBER_OFFSET 0
#define ANSI_PC_MASK      0xFFFFFF
#define ANSI_NETWORK_MASK 0xFF0000
#define ANSI_CLUSTER_MASK 0x00FF00
#define ANSI_MEMBER_MASK  0x0000FF
#define ANSI_PC_STRING_LENGTH 16

/* Called Party address */
static int hf_sccp_called_ansi_national_indicator = -1;
static int hf_sccp_called_itu_natl_use_bit = -1;
static int hf_sccp_called_routing_indicator = -1;
static int hf_sccp_called_itu_global_title_indicator = -1;
static int hf_sccp_called_ansi_global_title_indicator = -1;
static int hf_sccp_called_itu_ssn_indicator = -1;
static int hf_sccp_called_itu_point_code_indicator = -1;
static int hf_sccp_called_ansi_ssn_indicator = -1;
static int hf_sccp_called_ansi_point_code_indicator = -1;
static int hf_sccp_called_ssn = -1;
static int hf_sccp_called_pc_member = -1;
static int hf_sccp_called_pc_cluster = -1;
static int hf_sccp_called_pc_network = -1;
static int hf_sccp_called_ansi_pc = -1;
static int hf_sccp_called_chinese_pc = -1;
static int hf_sccp_called_itu_pc = -1;
static int hf_sccp_called_japan_pc = -1;
static int hf_sccp_called_gt_nai = -1;
static int hf_sccp_called_gt_oe = -1;
static int hf_sccp_called_gt_tt = -1;
static int hf_sccp_called_gt_np = -1;
static int hf_sccp_called_gt_es = -1;
static int hf_sccp_called_gt_digits = -1;
static int hf_sccp_called_gt_digits_length = -1;

/* Calling party address */
static int hf_sccp_calling_ansi_national_indicator = -1;
static int hf_sccp_calling_itu_natl_use_bit = -1;
static int hf_sccp_calling_routing_indicator = -1;
static int hf_sccp_calling_itu_global_title_indicator = -1;
static int hf_sccp_calling_ansi_global_title_indicator = -1;
static int hf_sccp_calling_itu_ssn_indicator = -1;
static int hf_sccp_calling_itu_point_code_indicator = -1;
static int hf_sccp_calling_ansi_ssn_indicator = -1;
static int hf_sccp_calling_ansi_point_code_indicator = -1;
static int hf_sccp_calling_ssn = -1;
static int hf_sccp_calling_pc_member = -1;
static int hf_sccp_calling_pc_cluster = -1;
static int hf_sccp_calling_pc_network = -1;
static int hf_sccp_calling_ansi_pc = -1;
static int hf_sccp_calling_chinese_pc = -1;
static int hf_sccp_calling_itu_pc = -1;
static int hf_sccp_calling_japan_pc = -1;
static int hf_sccp_calling_gt_nai = -1;
static int hf_sccp_calling_gt_oe = -1;
static int hf_sccp_calling_gt_tt = -1;
static int hf_sccp_calling_gt_np = -1;
static int hf_sccp_calling_gt_es = -1;
static int hf_sccp_calling_gt_digits = -1;
static int hf_sccp_calling_gt_digits_length = -1;

#define MAX_STRUCTURED_PC_LENGTH 20
gint mtp3_standard = ITU_STANDARD;
typedef enum {
  ITU_PC_STRUCTURE_NONE    = 1,
  ITU_PC_STRUCTURE_3_8_3   = 2,
  ITU_PC_STRUCTURE_4_3_4_3 = 3
} ITU_PC_Structure_Type;
typedef enum {
  JAPAN_PC_STRUCTURE_NONE    = 1,
  JAPAN_PC_STRUCTURE_7_4_5   = 2,
  JAPAN_PC_STRUCTURE_3_4_4_5 = 3
} JAPAN_PC_Structure_Type;
static gint itu_pc_structure = ITU_PC_STRUCTURE_NONE;
static gint japan_pc_structure = JAPAN_PC_STRUCTURE_NONE;

/* Initialize the subtree pointers */
static gint ett_sccp = -1;
static gint ett_sccp_called = -1;
static gint ett_sccp_called_ai = -1;
static gint ett_sccp_called_pc = -1;
static gint ett_sccp_called_gt = -1;
static gint ett_sccp_called_gt_digits = -1;
static gint ett_sccp_calling = -1;
static gint ett_sccp_calling_ai = -1;
static gint ett_sccp_calling_pc = -1;
static gint ett_sccp_calling_gt = -1;
static gint ett_sccp_calling_gt_digits = -1;
static gint ett_sccp_sequencing_segmenting = -1;
static gint ett_sccp_segmentation = -1;
static gint ett_sccp_ansi_isni_routing_control = -1;
static gint ett_sccp_xudt_msg_fragment = -1;
static gint ett_sccp_xudt_msg_fragments = -1;
static gint ett_sccp_assoc = -1;

#define is_connectionless(m) \
  ( m == SCCP_MSG_TYPE_UDT || m == SCCP_MSG_TYPE_UDTS      \
    || m == SCCP_MSG_TYPE_XUDT|| m == SCCP_MSG_TYPE_XUDTS  \
    || m == SCCP_MSG_TYPE_LUDT|| m == SCCP_MSG_TYPE_LUDTS)
#define ADDRESS_SSN_LENGTH      1
#define INVALID_SSN             0xff
static dissector_table_t sccp_ssn_dissector_table;
#define AI_GTI_NO_GT                    0x0
#define ITU_AI_GTI_NAI                  0x1
#define AI_GTI_TT                       0x2
#define ITU_AI_GTI_TT_NP_ES             0x3
#define ITU_AI_GTI_TT_NP_ES_NAI 0x4
#define ANSI_AI_GTI_TT_NP_ES    0x1
#define GT_TT_LENGTH 1

/* * * * * * * * * * * * * * * * * * * * * * * * * *
 * Global Title: ITU GTI == 0011, ANSI GTI == 0001 *
 * * * * * * * * * * * * * * * * * * * * * * * * * */
#define GT_NP_MASK              0xf0
#define GT_NP_SHIFT             4
#define GT_NP_ES_LENGTH         1
#define GT_NP_UNKNOWN           0x00
#define GT_NP_ISDN              0x01
#define GT_NP_GENERIC_RESERVED  0x02
#define GT_NP_DATA              0x03
#define GT_NP_TELEX             0x04
#define GT_NP_MARITIME_MOBILE   0x05
#define GT_NP_LAND_MOBILE       0x06
#define GT_NP_ISDN_MOBILE       0x07
#define GT_NP_PRIVATE_NETWORK   0x0e
#define GT_NP_RESERVED          0x0f

#define GT_ES_MASK     0x0f
#define GT_ES_UNKNOWN  0x0
#define GT_ES_BCD_ODD  0x1
#define GT_ES_BCD_EVEN 0x2
#define GT_ES_NATIONAL 0x3
#define GT_ES_RESERVED 0xf

#define GT_OE_MASK 0x80
#define GT_OE_EVEN 0
#define GT_OE_ODD  1

#define GT_NAI_MASK 0x7F
#define GT_NAI_LENGTH 1
#define GT_NAI_UNKNOWN                  0x00
#define GT_NAI_SUBSCRIBER_NUMBER        0x01
#define GT_NAI_RESERVED_NATIONAL        0x02
#define GT_NAI_NATIONAL_SIG_NUM         0x03
#define GT_NAI_INTERNATIONAL_NUM        0x04
sccp_msg_info_t* sccp_msg;
#define pletoh24(p) ((guint32)*((const guint8 *)(p)+2)<<16|  \
                     (guint32)*((const guint8 *)(p)+1)<<8|   \
                     (guint32)*((const guint8 *)(p)+0)<<0)

#define END_OF_OPTIONAL_PARAMETERS_LENGTH       1
#define DESTINATION_LOCAL_REFERENCE_LENGTH      3
#define SOURCE_LOCAL_REFERENCE_LENGTH           3
#define PROTOCOL_CLASS_LENGTH                   1
#define RECEIVE_SEQUENCE_NUMBER_LENGTH          1
#define CREDIT_LENGTH                           1
#define RELEASE_CAUSE_LENGTH                    1
#define RETURN_CAUSE_LENGTH                     1
#define RESET_CAUSE_LENGTH                      1
#define ERROR_CAUSE_LENGTH                      1
#define REFUSAL_CAUSE_LENGTH                    1
#define HOP_COUNTER_LENGTH                      1
#define IMPORTANCE_LENGTH                       1

#define             g_new0(struct_type, n_structs)
static int proto_sccp = -1;
static int hf_sccp_message_type = -1;

static int hf_sccp_optional_pointer = -1;
static int hf_sccp_param_length = -1;
static int hf_sccp_ssn = -1;
static int hf_sccp_gt_digits = -1;

#define GT_SIGNAL_LENGTH     1
#define GT_ODD_SIGNAL_MASK   0x0f
#define GT_EVEN_SIGNAL_MASK  0xf0
#define GT_EVEN_SIGNAL_SHIFT 4
#define GT_MAX_SIGNALS (32*7)	/* its a bit big, but it allows for adding a lot of "(spare)" and "Unknown" values (7 chars) if there are errors - e.g. ANSI vs ITU wrongly selected */

#define ANSI_ISNI_ROUTING_CONTROL_LENGTH 1
#define ANSI_ISNI_MI_MASK                0x01
#define ANSI_ISNI_IRI_MASK               0x06
#define ANSI_ISNI_RES_MASK               0x08
#define ANSI_ISNI_TI_MASK                0x10
#define ANSI_ISNI_TI_SHIFT               4
#define ANSI_ISNI_COUNTER_MASK           0xe0
#define ANSI_ISNI_NETSPEC_MASK           0x03

#define SEGMENTING_REASSEMBLING_LENGTH 1
#define SEGMENTING_REASSEMBLING_MASK   0x01
#define NO_MORE_DATA 0
#define MORE_DATA    1

static GHashTable *sccp_xudt_msg_fragment_table = NULL;
static GHashTable *sccp_xudt_msg_reassembled_table = NULL;

/* Declarations to desegment XUDT Messages */
static gboolean sccp_xudt_desegment = TRUE;
static gboolean show_key_params = FALSE;
static gboolean set_addresses = FALSE;

#define SEQUENCING_SEGMENTING_LENGTH            2
#define SEQUENCING_SEGMENTING_SSN_LENGTH        1
#define SEQUENCING_SEGMENTING_RSN_LENGTH        1
#define SEND_SEQUENCE_NUMBER_MASK               0xfe
#define RECEIVE_SEQUENCE_NUMBER_MASK            0xfe
#define SEQUENCING_SEGMENTING_MORE_MASK         0x01





#define RTP_MARKER(octet)	((octet) >> 7)
#define RTP_VERSION(octet)	((octet) >> 6)
static gint global_rtp_version0_type = 0;
#define RTP0_INVALID 0
#define RTP0_CLASSICSTUN    1
#define RTP0_T38     2

static dissector_handle_t rtp_handle;
static dissector_handle_t classicstun_handle;
static dissector_handle_t classicstun_heur_handle;
static dissector_handle_t t38_handle;
static dissector_handle_t zrtp_handle;

/* Padding is the third bit; No need to shift, because true is any value
   other than 0! */
#define RTP_PADDING(octet)	((octet) & 0x20)

/* Extension bit is the fourth bit */
#define RTP_EXTENSION(octet)	((octet) & 0x10)

/* CSRC count is the last four bits */
#define RTP_CSRC_COUNT(octet)	((octet) & 0xF)
/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet)	((octet) & 0x7F)

#define PT_PCMU           0  /* RFC 3551 */
#define PT_1016           1  /* RFC 1890 (reserved in RFC 3551) */
#define PT_G721           2  /* RFC 1890 (reserved in RFC 3551) */
#define PT_GSM            3  /* RFC 3551 */
#define PT_G723           4  /* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000      5  /* RFC 3551 */
#define PT_DVI4_16000     6  /* RFC 3551 */
#define PT_LPC            7  /* RFC 3551 */
#define PT_PCMA           8  /* RFC 3551 */
#define PT_G722           9  /* RFC 3551 */
#define PT_L16_STEREO    10  /* RFC 3551 */
#define PT_L16_MONO      11  /* RFC 3551 */
#define PT_QCELP         12  /* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN            13  /* RFC 3389 */
#define PT_MPA           14  /* RFC 3551, RFC 2250 */
#define PT_G728          15  /* RFC 3551 */
#define PT_DVI4_11025    16  /* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050    17  /* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729          18
#define PT_CN_OLD        19  /* Payload type reserved (old version Comfort Noise) */
#define PT_CELB          25  /* RFC 2029 */
#define PT_JPEG          26  /* RFC 2435 */
#define PT_NV            28  /* RFC 1890 */
#define PT_H261          31  /* RFC 2032 */
#define PT_MPV           32  /* RFC 2250 */
#define PT_MP2T          33  /* RFC 2250 */
#define PT_H263          34  /* from Chunrong Zhu of Intel; see the Web page */

/* Added to by Alex Lindberg to cover port ranges 96-127 - Dynamic RTP
   Some of these ports are used by Avaya for Modem and FAX support */

#define PT_UNDF_96       96  /* RFC 3551 */
#define PT_UNDF_97       97
#define PT_UNDF_98       98
#define PT_UNDF_99       99
#define PT_UNDF_100     100
#define PT_UNDF_101     101
#define PT_UNDF_102     102
#define PT_UNDF_103     103
#define PT_UNDF_104     104
#define PT_UNDF_105     105
#define PT_UNDF_106     106
#define PT_UNDF_107     107
#define PT_UNDF_108     108
#define PT_UNDF_109     109
#define PT_UNDF_110     110
#define PT_UNDF_111     111
#define PT_UNDF_112     112
#define PT_UNDF_113     113
#define PT_UNDF_114     114
#define PT_UNDF_115     115
#define PT_UNDF_116     116
#define PT_UNDF_117     117
#define PT_UNDF_118     118
#define PT_UNDF_119     119
#define PT_UNDF_120     120
#define PT_UNDF_121     121
#define PT_UNDF_122     122
#define PT_UNDF_123     123
#define PT_UNDF_124     124
#define PT_UNDF_125     125
#define PT_UNDF_126     126
#define PT_UNDF_127     127


#define pntohl(p)   ((guint32)*((const guint8 *)(p)+0)<<24|  \
                     (guint32)*((const guint8 *)(p)+1)<<16|  \
                     (guint32)*((const guint8 *)(p)+2)<<8|   \
                     (guint32)*((const guint8 *)(p)+3)<<0)

 GString *layer_names;
  guint16 can_desegment;



#undef	MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define BoundsError		1
#define ReportedBoundsError	2
#define TypeError		3
#define DissectorError		4
#define OutOfMemoryError	6
  typedef struct conversation_key {
	struct conversation_key *next;
	address	addr1;
	address	addr2;
    port_type ptype;
	guint32	port1;
	guint32	port2;
} conversation_key;

typedef struct conversation {
	struct conversation *next;	/** pointer to next conversation on hash chain */
	struct conversation *last;	/** pointer to the last conversation on hash chain */
	struct conversation *latest_found;
								/** pointer to the last conversation on hash chain */
	guint32	index;				/** unique ID for conversation */
	guint32 setup_frame;		/** frame number that setup this conversation */
	GSList *data_list;			/** list of data associated with conversation */
	dissector_handle_t dissector_handle;
								/** handle for protocol dissector client associated with conversation */
	guint	options;			/** wildcard flags */
	conversation_key *key_ptr;	/** pointer to the key for this conversation */
} conversation_t;

/* RTP header fields             */
static int proto_rtp           = -1;
static int hf_rtp_version      = -1;
static int hf_rtp_padding      = -1;
static int hf_rtp_extension    = -1;
static int hf_rtp_csrc_count   = -1;
static int hf_rtp_marker       = -1;
static int hf_rtp_payload_type = -1;
static int hf_rtp_seq_nr       = -1;
static int hf_rtp_ext_seq_nr   = -1;
static int hf_rtp_timestamp    = -1;
static int hf_rtp_ssrc         = -1;
static int hf_rtp_csrc_items   = -1;
static int hf_rtp_csrc_item    = -1;
static int hf_rtp_data         = -1;
static int hf_rtp_padding_data = -1;
static int hf_rtp_padding_count= -1;
static int hf_rtp_rfc2198_follow= -1;
static int hf_rtp_rfc2198_tm_off= -1;
static int hf_rtp_rfc2198_bl_len= -1;


#define NO_ADDR_B 0x01
#define NO_PORT_B 0x02
static gboolean desegment_rtp = TRUE;

typedef struct _uri_offset_info
{
	gint display_name_start;
	gint display_name_end;
	gint uri_start;
	gint uri_end;
	gint uri_parameters_start;
	gint uri_parameters_end;
	gint name_addr_start;
	gint name_addr_end;
	gint uri_user_start;
	gint uri_user_end;
	gint uri_host_start;
	gint uri_host_end;
	gint uri_host_port_start;
	gint uri_host_port_end;
} uri_offset_info;







/********* SIP Header**************************************************************************************/
#define ASN1_CTX_SIGNATURE 0x41435458  /* "ACTX" */
#define TAP_PACKET_QUEUE_LEN 100
#define BoundsError		1
#define ReportedBoundsError	2
#define TypeError		3
#define DissectorError		4

#define BER_CLASS_UNI	0
#define BER_CLASS_APP	1
#define BER_CLASS_CON	2
#define BER_CLASS_PRI	3
#define BER_CLASS_ANY   99			/* dont check class nor tag */

#define BER_UNI_TAG_EOC					0	/* 'end-of-content' */
#define BER_UNI_TAG_BOOLEAN				1
#define BER_UNI_TAG_INTEGER				2
#define BER_UNI_TAG_BITSTRING		    3
#define BER_UNI_TAG_OCTETSTRING		    4
#define BER_UNI_TAG_NULL				5
#define BER_UNI_TAG_OID					6	/* OBJECT IDENTIFIER */
#define BER_UNI_TAG_ObjectDescriptor	7
#define BER_UNI_TAG_EXTERNAL			8
#define BER_UNI_TAG_REAL				9
#define BER_UNI_TAG_ENUMERATED		    10
#define BER_UNI_TAG_EMBEDDED_PDV	    11
#define BER_UNI_TAG_UTF8String		    12
#define BER_UNI_TAG_RELATIVE_OID	    13
/* UNIVERSAL 14-15	
 * Reserved for future editions of this
 * Recommendation | International Standard
 */
#define BER_UNI_TAG_SEQUENCE		    16	/* SEQUENCE, SEQUENCE OF */
#define BER_UNI_TAG_SET					17	/* SET, SET OF */
/* UNIVERSAL 18-22 Character string types */
#define BER_UNI_TAG_NumericString	    18
#define BER_UNI_TAG_PrintableString	    19
#define BER_UNI_TAG_TeletexString	    20  /* TeletextString, T61String */
#define BER_UNI_TAG_VideotexString	    21
#define BER_UNI_TAG_IA5String		    22
/* UNIVERSAL 23-24 Time types */
#define BER_UNI_TAG_UTCTime				23
#define BER_UNI_TAG_GeneralizedTime	    24
/* UNIVERSAL 25-30 Character string types */
#define BER_UNI_TAG_GraphicString	    25
#define BER_UNI_TAG_VisibleString	    26  /* VisibleString, ISO64String */
#define BER_UNI_TAG_GeneralString	    27
#define BER_UNI_TAG_UniversalString	    28
#define BER_UNI_TAG_CHARACTERSTRING	    29
#define BER_UNI_TAG_BMPString		    30
/* UNIVERSAL 31- ...
 * Reserved for addenda to this Recommendation | International Standard
 */



#define BER_FLAGS_OPTIONAL	0x00000001
#define BER_FLAGS_IMPLTAG	0x00000002
#define BER_FLAGS_NOOWNTAG	0x00000004
#define BER_FLAGS_NOTCHKTAG	0x00000008

#define             g_assert(expr)
#define             g_assert_not_reached()




#define BER_MAX_NESTING 500

#define EMEM_CANARY_SIZE 8
#define EMEM_CANARY_DATA_SIZE (EMEM_CANARY_SIZE * 2 - 1)

#define va_dcl va_list va_alist;
#define va_start(ap) ap = (va_list)&va_alist
#define va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
#define va_end(ap) ap = (va_list)0

#define ENC_BIG_ENDIAN		0x00000000
#define ENC_LITTLE_ENDIAN	0x80000000

#define BUF_TOO_SMALL_ERR "[Buffer too small]"
#define	MAX_BYTE_STR_LEN	48

#define pntohs(p)   ((guint16)                       \
                     ((guint16)*((const guint8 *)(p)+0)<<8|  \
                      (guint16)*((const guint8 *)(p)+1)<<0))

#define NO_MORE_DATA_CHECK(nmdc_len) \
    if ((nmdc_len) == (curr_offset - offset)) return(nmdc_len);

/* To pass one of two strings, singular or plural */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

#define	Q931_UIL3_X25_PL	0x06
#define	Q931_UIL3_ISO_8208	0x07	/* X.25-based */
#define	Q931_UIL3_X223		0x08	/* X.25-based */
#define	Q931_UIL3_TR_9577	0x0B
#define	Q931_UIL3_USER_SPEC	0x10

#define	Q931_IE_SO_MASK	0x80	/* single-octet/variable-length mask */
/*
 * Single-octet IEs.
 */
#define	Q931_IE_SO_IDENTIFIER_MASK	0xf0	/* IE identifier mask */
#define	Q931_IE_SO_IDENTIFIER_SHIFT	4	/* IE identifier shift */
#define	Q931_IE_SO_IE_MASK		0x0F	/* IE mask */

#define	Q931_IE_SHIFT			0x90
#define	Q931_IE_SHIFT_NON_LOCKING	0x08	/* non-locking shift */
#define	Q931_IE_SHIFT_CODESET		0x07	/* codeset */

#define	Q931_IE_MORE_DATA_OR_SEND_COMP	0xA0	/* More Data or Sending Complete */
#define	Q931_IE_MORE_DATA		0xA0
#define	Q931_IE_SENDING_COMPLETE	0xA1

#define	Q931_IE_CONGESTION_LEVEL	0xB0
#define	Q931_IE_REPEAT_INDICATOR	0xD0

/*
 * Variable-length IEs.
 */
#define	Q931_IE_VL_EXTENSION		0x80	/* Extension flag */
#define	Q931_IT_RATE_MULTIRATE	0x18
#define	Q931_UIL2_USER_SPEC	0x10
#define	Q931_ITU_STANDARDIZED_CODING	0x00



#define P2P_DIR_UNKNOWN	-1
#define P2P_DIR_SENT	0
#define P2P_DIR_RECV	1

#define BER_TAG_ANY -1



#define MAX_NUMBER_OF_PPIDS     2

#ifndef NO_BOUND
#define NO_BOUND -1
#endif

#define ITEM_LABEL_LENGTH	240

typedef int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, int hf_index);
struct _protocol;
#define GUINT_TO_POINTER(u) ((gpointer) (gulong) (u))
typedef proto_node proto_item;

typedef int (*ber_type_fn)(gboolean, tvbuff_t*, int, asn1_ctx_t *actx, int);
typedef int (* dissect_function_t)( gboolean,
				    tvbuff_t *,
				    int ,
					asn1_ctx_t *,
				    //proto_tree *,
				    int);

typedef struct _protocol protocol_t;
typedef void (dissector_t)(tvbuff_t *, packet_info */*, proto_tree **/);
typedef int (*new_dissector_t)(tvbuff_t *, packet_info */**//*, proto_tree **/);

struct _value_string_ext;
typedef const value_string *(*_value_string_match2_t)(const guint32, const struct _value_string_ext *);

struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;

typedef enum ftenum ftenum_t;
typedef struct dissector_table *dissector_table_t;

typedef guint32 gunichar;

#define GN_CHAR_ALPHABET_SIZE 128

#define GN_CHAR_ESCAPE 0x1b

/*
 * this should be set on a per message basis, if possible
 */
#define IS_UPLINK_FALSE     0
#define IS_UPLINK_TRUE      1
#define IS_UPLINK_UNKNOWN   2


#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
       /* proto_tree_add_text( tvb,*/ \
            /*curr_offset, (edc_len) - (edc_max_len), "Extraneous Data"); */\
        curr_offset += ((edc_len) - (edc_max_len)); \
    }

#define FIELD_INFO_NEW(fi)					\
	fi = sl_alloc(&field_info_slab)
#define FIELD_INFO_FREE(fi)					\
	sl_free(&field_info_slab, fi)

typedef struct dtbl_entry dtbl_entry_t;


#define TFS(x)	(const struct true_false_string*)(x)
#define VALS(x)	(const struct _value_string*)(x)
#define RVALS(x) (const struct _range_string*)(x)

#define HFILL 0, 0, HF_REF_TYPE_NONE, 0, NULL, NULL


#define FI_HIDDEN		0x00000001
#define FI_GET_FLAG(fi, flag)   ((fi) ? ((fi)->flags & (flag)) : 0)
#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)
#define PITEM_FINFO(proto_item)  PNODE_FINFO(proto_item)
#define PROTO_ITEM_IS_HIDDEN(proto_item)        \
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN) : 0)
#define ITEM_LABEL_NEW(il)				\
	il = sl_alloc(&item_label_slab);

#define GN_BYTE_MASK ((1 << bits) - 1)
#define ISUPPER(c)              ((c) >= 'A' && (c) <= 'Z')
#define ISLOWER(c)              ((c) >= 'a' && (c) <= 'z')
#define ISALPHA(c)              (ISUPPER (c) || ISLOWER (c))
#define TOUPPER(c)              (ISLOWER (c) ? (c) - 'a' + 'A' : (c))
#define TOLOWER(c)              (ISUPPER (c) ? (c) - 'A' + 'a' : (c))
#define SMS_MAX_MESSAGE_SIZE 160
#define MAX_SMS_FRAG_LEN      134


#define pletohs(p)  ((guint16)                       \
                     ((guint16)*((const guint8 *)(p)+1)<<8|  \
                      (guint16)*((const guint8 *)(p)+0)<<0))

#define NUL_TERMINATOR_LENGTH 4
#define EINVAL          22      /* Invalid argument */
#define E2BIG            7      /* Arg list too long */
#define EILSEQ          84      /* Illegal byte sequence */
#undef iconv_t
#define iconv_t libiconv_t
typedef void* iconv_t;
//#define iconv
#define FD_BLOCKSEQUENCE        0x0100

//static guint8 message_type = 0;
#define BoundsError		1
#define ReportedBoundsError	2
#define TypeError		3
#define DissectorError		4
#define SCCP_MSG_TYPE_OFFSET 0
#define SCCP_MSG_TYPE_LENGTH 1
#define SCCP_MSG_TYPE_CR    0x01
#define SCCP_MSG_TYPE_CC    0x02
#define SCCP_MSG_TYPE_CREF  0x03
#define SCCP_MSG_TYPE_RLSD  0x04
#define SCCP_MSG_TYPE_RLC   0x05
#define SCCP_MSG_TYPE_DT1   0x06
#define SCCP_MSG_TYPE_DT2   0x07
#define SCCP_MSG_TYPE_AK    0x08
#define SCCP_MSG_TYPE_UDT   0x09
#define SCCP_MSG_TYPE_UDTS  0x0a
#define SCCP_MSG_TYPE_ED    0x0b
#define SCCP_MSG_TYPE_EA    0x0c
#define SCCP_MSG_TYPE_RSR   0x0d
#define SCCP_MSG_TYPE_RSC   0x0e
#define SCCP_MSG_TYPE_ERR   0x0f
#define SCCP_MSG_TYPE_IT    0x10
#define SCCP_MSG_TYPE_XUDT  0x11
#define SCCP_MSG_TYPE_XUDTS 0x12
#define SCCP_MSG_TYPE_LUDT  0x13
#define SCCP_MSG_TYPE_LUDTS 0x14
#define PARAMETER_CLASS                         0x05
#define PROTOCOL_CLASS_LENGTH                   1
#define POINTER_LENGTH       1
#define POINTER_LENGTH_LONG  2
#define PARAMETER_IMPORTANCE                    0x12
#define PARAMETER_LONG_DATA                     0x13
#define PARAMETER_CALLED_PARTY_ADDRESS          0x03
#define PARAMETER_CALLING_PARTY_ADDRESS         0x04
#define PARAMETER_CLASS                         0x05
#define PARAMETER_DATA                          0x0f
#define PARAMETER_LENGTH_LENGTH                 1
#define PARAMETER_LONG_DATA_LENGTH_LENGTH       2

#define PARAMETER_END_OF_OPTIONAL_PARAMETERS    0x00
#define PARAMETER_DESTINATION_LOCAL_REFERENCE   0x01
#define PARAMETER_SOURCE_LOCAL_REFERENCE        0x02
#define PARAMETER_CALLED_PARTY_ADDRESS          0x03
#define PARAMETER_CALLING_PARTY_ADDRESS         0x04
#define PARAMETER_CLASS                         0x05
#define PARAMETER_SEGMENTING_REASSEMBLING       0x06
#define PARAMETER_RECEIVE_SEQUENCE_NUMBER       0x07
#define PARAMETER_SEQUENCING_SEGMENTING         0x08
#define PARAMETER_CREDIT                        0x09
#define PARAMETER_RELEASE_CAUSE                 0x0a
#define PARAMETER_RETURN_CAUSE                  0x0b
#define PARAMETER_RESET_CAUSE                   0x0c
#define PARAMETER_ERROR_CAUSE                   0x0d
#define PARAMETER_REFUSAL_CAUSE                 0x0e
#define PARAMETER_DATA                          0x0f
#define PARAMETER_SEGMENTATION                  0x10
#define PARAMETER_HOP_COUNTER                   0x11
#define PARAMETER_ISNI                          0xfa
//static guint32  sccp_source_pc_global = 0;
//static gboolean sccp_show_length      = FALSE;
#define CLASS_CLASS_MASK                0xf
#define CLASS_SPARE_HANDLING_MASK       0xf0
#define CLASS_SPARE_HANDLING_SHIFT      4

#define ITU_RESERVED_MASK               0x80
#define ANSI_NATIONAL_MASK              0x80
#define ROUTING_INDICATOR_MASK          0x40
#define GTI_MASK                        0x3C
#define GTI_SHIFT                       2
#define ITU_SSN_INDICATOR_MASK          0x02
#define ITU_PC_INDICATOR_MASK           0x01
#define ANSI_PC_INDICATOR_MASK          0x02
#define ANSI_SSN_INDICATOR_MASK         0x01
#define ROUTE_ON_GT             0x0
#define ROUTE_ON_SSN            0x1
#define ROUTING_INDICATOR_SHIFT 6

#define ADDRESS_INDICATOR_LENGTH        1
#define ITU_RESERVED_MASK               0x80
#define ANSI_NATIONAL_MASK              0x80
#define ROUTING_INDICATOR_MASK          0x40
#define GTI_MASK                        0x3C
#define GTI_SHIFT                       2
#define ITU_SSN_INDICATOR_MASK          0x02
#define ITU_PC_INDICATOR_MASK           0x01
#define ANSI_PC_INDICATOR_MASK          0x02
#define ANSI_SSN_INDICATOR_MASK         0x01
#define ITU_PC_LENGTH     2
#define JAPAN_PC_LENGTH   2
#define JAPAN_PC_MASK     0xffff

#define ANSI_PC_LENGTH    3
#define ANSI_NCM_LENGTH   1
#define ANSI_NETWORK_OFFSET 2
#define ANSI_CLUSTER_OFFSET 1
#define ANSI_MEMBER_OFFSET 0
#define ANSI_PC_MASK      0xFFFFFF
#define ANSI_NETWORK_MASK 0xFF0000
#define ANSI_CLUSTER_MASK 0x00FF00
#define ANSI_MEMBER_MASK  0x0000FF
#define ANSI_PC_STRING_LENGTH 16


#define MAX_STRUCTURED_PC_LENGTH 20
#define is_connectionless(m) \
  ( m == SCCP_MSG_TYPE_UDT || m == SCCP_MSG_TYPE_UDTS      \
    || m == SCCP_MSG_TYPE_XUDT|| m == SCCP_MSG_TYPE_XUDTS  \
    || m == SCCP_MSG_TYPE_LUDT|| m == SCCP_MSG_TYPE_LUDTS)
#define ADDRESS_SSN_LENGTH      1
#define INVALID_SSN             0xff
//static dissector_table_t sccp_ssn_dissector_table;
#define AI_GTI_NO_GT                    0x0
#define ITU_AI_GTI_NAI                  0x1
#define AI_GTI_TT                       0x2
#define ITU_AI_GTI_TT_NP_ES             0x3
#define ITU_AI_GTI_TT_NP_ES_NAI 0x4
#define ANSI_AI_GTI_TT_NP_ES    0x1
#define GT_TT_LENGTH 1

/* * * * * * * * * * * * * * * * * * * * * * * * * *
 * Global Title: ITU GTI == 0011, ANSI GTI == 0001 *
 * * * * * * * * * * * * * * * * * * * * * * * * * */
#define GT_NP_MASK              0xf0
#define GT_NP_SHIFT             4
#define GT_NP_ES_LENGTH         1
#define GT_NP_UNKNOWN           0x00
#define GT_NP_ISDN              0x01
#define GT_NP_GENERIC_RESERVED  0x02
#define GT_NP_DATA              0x03
#define GT_NP_TELEX             0x04
#define GT_NP_MARITIME_MOBILE   0x05
#define GT_NP_LAND_MOBILE       0x06
#define GT_NP_ISDN_MOBILE       0x07
#define GT_NP_PRIVATE_NETWORK   0x0e
#define GT_NP_RESERVED          0x0f

#define GT_ES_MASK     0x0f
#define GT_ES_UNKNOWN  0x0
#define GT_ES_BCD_ODD  0x1
#define GT_ES_BCD_EVEN 0x2
#define GT_ES_NATIONAL 0x3
#define GT_ES_RESERVED 0xf

#define GT_OE_MASK 0x80
#define GT_OE_EVEN 0
#define GT_OE_ODD  1

#define GT_NAI_MASK 0x7F
#define GT_NAI_LENGTH 1
#define GT_NAI_UNKNOWN                  0x00
#define GT_NAI_SUBSCRIBER_NUMBER        0x01
#define GT_NAI_RESERVED_NATIONAL        0x02
#define GT_NAI_NATIONAL_SIG_NUM         0x03
#define GT_NAI_INTERNATIONAL_NUM        0x04
//sccp_msg_info_t* sccp_msg;
#define pletoh24(p) ((guint32)*((const guint8 *)(p)+2)<<16|  \
                     (guint32)*((const guint8 *)(p)+1)<<8|   \
                     (guint32)*((const guint8 *)(p)+0)<<0)

#define END_OF_OPTIONAL_PARAMETERS_LENGTH       1
#define DESTINATION_LOCAL_REFERENCE_LENGTH      3
#define SOURCE_LOCAL_REFERENCE_LENGTH           3
#define PROTOCOL_CLASS_LENGTH                   1
#define RECEIVE_SEQUENCE_NUMBER_LENGTH          1
#define CREDIT_LENGTH                           1
#define RELEASE_CAUSE_LENGTH                    1
#define RETURN_CAUSE_LENGTH                     1
#define RESET_CAUSE_LENGTH                      1
#define ERROR_CAUSE_LENGTH                      1
#define REFUSAL_CAUSE_LENGTH                    1
#define HOP_COUNTER_LENGTH                      1
#define IMPORTANCE_LENGTH                       1

#define             g_new0(struct_type, n_structs)

#define GT_SIGNAL_LENGTH     1
#define GT_ODD_SIGNAL_MASK   0x0f
#define GT_EVEN_SIGNAL_MASK  0xf0
#define GT_EVEN_SIGNAL_SHIFT 4
#define GT_MAX_SIGNALS (32*7)	/* its a bit big, but it allows for adding a lot of "(spare)" and "Unknown" values (7 chars) if there are errors - e.g. ANSI vs ITU wrongly selected */

#define ANSI_ISNI_ROUTING_CONTROL_LENGTH 1
#define ANSI_ISNI_MI_MASK                0x01
#define ANSI_ISNI_IRI_MASK               0x06
#define ANSI_ISNI_RES_MASK               0x08
#define ANSI_ISNI_TI_MASK                0x10
#define ANSI_ISNI_TI_SHIFT               4
#define ANSI_ISNI_COUNTER_MASK           0xe0
#define ANSI_ISNI_NETSPEC_MASK           0x03

#define SEGMENTING_REASSEMBLING_LENGTH 1
#define SEGMENTING_REASSEMBLING_MASK   0x01
#define NO_MORE_DATA 0
#define MORE_DATA    1


#define SEQUENCING_SEGMENTING_LENGTH            2
#define SEQUENCING_SEGMENTING_SSN_LENGTH        1
#define SEQUENCING_SEGMENTING_RSN_LENGTH        1
#define SEND_SEQUENCE_NUMBER_MASK               0xfe
#define RECEIVE_SEQUENCE_NUMBER_MASK            0xfe
#define SEQUENCING_SEGMENTING_MORE_MASK         0x01





#define RTP_MARKER(octet)	((octet) >> 7)
#define RTP_VERSION(octet)	((octet) >> 6)
//static gint global_rtp_version0_type = 0;
#define RTP0_INVALID 0
#define RTP0_CLASSICSTUN    1
#define RTP0_T38     2


/* Padding is the third bit; No need to shift, because true is any value
   other than 0! */
#define RTP_PADDING(octet)	((octet) & 0x20)

/* Extension bit is the fourth bit */
#define RTP_EXTENSION(octet)	((octet) & 0x10)

/* CSRC count is the last four bits */
#define RTP_CSRC_COUNT(octet)	((octet) & 0xF)
/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet)	((octet) & 0x7F)

#define PT_PCMU           0  /* RFC 3551 */
#define PT_1016           1  /* RFC 1890 (reserved in RFC 3551) */
#define PT_G721           2  /* RFC 1890 (reserved in RFC 3551) */
#define PT_GSM            3  /* RFC 3551 */
#define PT_G723           4  /* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000      5  /* RFC 3551 */
#define PT_DVI4_16000     6  /* RFC 3551 */
#define PT_LPC            7  /* RFC 3551 */
#define PT_PCMA           8  /* RFC 3551 */
#define PT_G722           9  /* RFC 3551 */
#define PT_L16_STEREO    10  /* RFC 3551 */
#define PT_L16_MONO      11  /* RFC 3551 */
#define PT_QCELP         12  /* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN            13  /* RFC 3389 */
#define PT_MPA           14  /* RFC 3551, RFC 2250 */
#define PT_G728          15  /* RFC 3551 */
#define PT_DVI4_11025    16  /* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050    17  /* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729          18
#define PT_CN_OLD        19  /* Payload type reserved (old version Comfort Noise) */
#define PT_CELB          25  /* RFC 2029 */
#define PT_JPEG          26  /* RFC 2435 */
#define PT_NV            28  /* RFC 1890 */
#define PT_H261          31  /* RFC 2032 */
#define PT_MPV           32  /* RFC 2250 */
#define PT_MP2T          33  /* RFC 2250 */
#define PT_H263          34  /* from Chunrong Zhu of Intel; see the Web page */

/* Added to by Alex Lindberg to cover port ranges 96-127 - Dynamic RTP
   Some of these ports are used by Avaya for Modem and FAX support */

#define PT_UNDF_96       96  /* RFC 3551 */
#define PT_UNDF_97       97
#define PT_UNDF_98       98
#define PT_UNDF_99       99
#define PT_UNDF_100     100
#define PT_UNDF_101     101
#define PT_UNDF_102     102
#define PT_UNDF_103     103
#define PT_UNDF_104     104
#define PT_UNDF_105     105
#define PT_UNDF_106     106
#define PT_UNDF_107     107
#define PT_UNDF_108     108
#define PT_UNDF_109     109
#define PT_UNDF_110     110
#define PT_UNDF_111     111
#define PT_UNDF_112     112
#define PT_UNDF_113     113
#define PT_UNDF_114     114
#define PT_UNDF_115     115
#define PT_UNDF_116     116
#define PT_UNDF_117     117
#define PT_UNDF_118     118
#define PT_UNDF_119     119
#define PT_UNDF_120     120
#define PT_UNDF_121     121
#define PT_UNDF_122     122
#define PT_UNDF_123     123
#define PT_UNDF_124     124
#define PT_UNDF_125     125
#define PT_UNDF_126     126
#define PT_UNDF_127     127


#define pntohl(p)   ((guint32)*((const guint8 *)(p)+0)<<24|  \
                     (guint32)*((const guint8 *)(p)+1)<<16|  \
                     (guint32)*((const guint8 *)(p)+2)<<8|   \
                     (guint32)*((const guint8 *)(p)+3)<<0)

 //GString *layer_names;
  //guint16 can_desegment;



#undef	MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define BoundsError		1
#define ReportedBoundsError	2
#define TypeError		3
#define DissectorError		4
#define OutOfMemoryError	6

#define MAX_CSEQ_METHOD_SIZE 16
#define MAX_CALL_ID_SIZE 128
#define MAGIC_SOURCE_PORT 0
typedef enum {
	REQUEST_LINE,
	STATUS_LINE,
	OTHER_LINE
} line_type_t;
#define SIP_METHOD_INVALID	0
           /* Pad so that the real methods start at index 1 */
#define SIP_METHOD_ACK		1
     
#define SIP_METHOD_BYE		2
     
#define SIP_METHOD_CANCEL	3
        
#define SIP_METHOD_DO		4
      
#define SIP_METHOD_INFO		5
      
#define SIP_METHOD_INVITE	6
        
#define SIP_METHOD_MESSAGE	7
       
#define SIP_METHOD_NOTIFY	8
        
#define SIP_METHOD_OPTIONS	9
       
#define SIP_METHOD_PRACK	10
        
#define SIP_METHOD_QAUTH	11
       
#define SIP_METHOD_REFER	12
        
#define SIP_METHOD_REGISTER	13
        
#define SIP_METHOD_SPRACK	14
        
#define SIP_METHOD_SUBSCRIBE	15
        
#define SIP_METHOD_UPDATE	16
       
#define SIP_METHOD_PUBLISH	17
static gboolean strict_sip_version = TRUE;
#define SIP2_HDR "SIP/2.0"
#define SIP2_HDR_LEN 7
typedef enum {
  G_ASCII_ALNUM  = 1 << 0,
  G_ASCII_ALPHA  = 1 << 1,
  G_ASCII_CNTRL  = 1 << 2,
  G_ASCII_DIGIT  = 1 << 3,
  G_ASCII_GRAPH  = 1 << 4,
  G_ASCII_LOWER  = 1 << 5,
  G_ASCII_PRINT  = 1 << 6,
  G_ASCII_PUNCT  = 1 << 7,
  G_ASCII_SPACE  = 1 << 8,
  G_ASCII_UPPER  = 1 << 9,
  G_ASCII_XDIGIT = 1 << 10
} GAsciiType;
static gboolean sip_desegment_headers = TRUE;

/*
 * desegmentation of SIP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static gboolean sip_desegment_body = TRUE;
typedef struct _sip_info_value_t
{
    gchar	*request_method;
    guint	 response_code;
	guchar	resend;
	guint32 setup_time;
    /* added for VoIP calls analysis, see gtk/voip_calls.c*/
    gchar   *tap_call_id;
    gchar   *tap_from_addr;
    gchar   *tap_to_addr;
    guint32 tap_cseq_number;
    gchar   *reason_phrase;
} sip_info_value_t;
static sip_info_value_t *stat_info;

static dissector_handle_t sip_diag_handle;
#define     GPOINTER_TO_UINT(p)
#define G_UNLIKELY(expr) (expr)
#define HASH_IS_REAL(h_) ((h_) >= 2)
#define UNUSED_HASH_VALUE 0
#define TOMBSTONE_HASH_VALUE 1
#define HASH_IS_TOMBSTONE(h_) ((h_) == TOMBSTONE_HASH_VALUE)
#define HASH_IS_UNUSED(h_) ((h_) == UNUSED_HASH_VALUE)
static GHashTable *sip_hash = NULL;           /* Hash table */
static GHashTable *sip_headers_hash = NULL;		/* Hash table */
static dissector_table_t ext_hdr_subdissector_table;
/* Initialize the protocol and registered fields */
static gint proto_sip                     = -1;
static gint proto_raw_sip                 = -1;
static gint hf_sip_raw_line               = -1;
static gint hf_sip_msg_hdr                = -1;
static gint hf_sip_Method                 = -1;
static gint hf_Request_Line               = -1;
static gint hf_sip_ruri                   = -1;
static gint hf_sip_ruri_user              = -1;
static gint hf_sip_ruri_host              = -1;
static gint hf_sip_ruri_port              = -1;
static gint hf_sip_ruri_param             = -1;
static gint hf_sip_Status_Code            = -1;
static gint hf_sip_Status_Line            = -1;
static gint hf_sip_display                = -1;
static gint hf_sip_to_addr                = -1;
static gint hf_sip_to_user                = -1;
static gint hf_sip_to_host                = -1;
static gint hf_sip_to_port                = -1;
static gint hf_sip_to_param               = -1;
static gint hf_sip_to_tag                 = -1;
static gint hf_sip_from_addr              = -1;
static gint hf_sip_from_user              = -1;
static gint hf_sip_from_host              = -1;
static gint hf_sip_from_port              = -1;
static gint hf_sip_from_param             = -1;
static gint hf_sip_from_tag               = -1;
static gint hf_sip_tag                    = -1;
static gint hf_sip_pai_addr               = -1;
static gint hf_sip_pai_user               = -1;
static gint hf_sip_pai_host               = -1;
static gint hf_sip_pai_port               = -1;
static gint hf_sip_pai_param              = -1;
static gint hf_sip_pmiss_addr             = -1;
static gint hf_sip_pmiss_user             = -1;
static gint hf_sip_pmiss_host             = -1;
static gint hf_sip_pmiss_port             = -1;
static gint hf_sip_pmiss_param            = -1;
static gint hf_sip_ppi_addr               = -1;
static gint hf_sip_ppi_user               = -1;
static gint hf_sip_ppi_host               = -1;
static gint hf_sip_ppi_port               = -1;
static gint hf_sip_ppi_param              = -1;
static gint hf_sip_tc_addr                = -1;
static gint hf_sip_tc_user                = -1;
static gint hf_sip_tc_host                = -1;
static gint hf_sip_tc_port                = -1;
static gint hf_sip_tc_param               = -1;
static gint hf_sip_tc_turi                = -1;
static gint hf_sip_contact_param          = -1;
static gint hf_sip_resend                 = -1;
static gint hf_sip_original_frame         = -1;
static gint hf_sip_matching_request_frame = -1;
static gint hf_sip_response_time          = -1;
static gint hf_sip_release_time           = -1;
static gint hf_sip_curi                   = -1;
static gint hf_sip_curi_user              = -1;
static gint hf_sip_curi_host              = -1;
static gint hf_sip_curi_port              = -1;
static gint hf_sip_curi_param             = -1;
static gint hf_sip_route                  = -1;
static gint hf_sip_route_user             = -1;
static gint hf_sip_route_host             = -1;
static gint hf_sip_route_port             = -1;
static gint hf_sip_route_param            = -1;
static gint hf_sip_record_route           = -1;
static gint hf_sip_record_route_user      = -1;
static gint hf_sip_record_route_host      = -1;
static gint hf_sip_record_route_port      = -1;
static gint hf_sip_record_route_param     = -1;

static gint hf_sip_auth                   = -1;
static gint hf_sip_auth_scheme            = -1;
static gint hf_sip_auth_digest_response   = -1;
static gint hf_sip_auth_nc                = -1;
static gint hf_sip_auth_username          = -1;
static gint hf_sip_auth_realm             = -1;
static gint hf_sip_auth_nonce             = -1;
static gint hf_sip_auth_algorithm         = -1;
static gint hf_sip_auth_opaque            = -1;
static gint hf_sip_auth_qop               = -1;
static gint hf_sip_auth_cnonce            = -1;
static gint hf_sip_auth_uri               = -1;
static gint hf_sip_auth_domain            = -1;
static gint hf_sip_auth_stale             = -1;
static gint hf_sip_auth_auts              = -1;
static gint hf_sip_auth_rspauth           = -1;
static gint hf_sip_auth_nextnonce         = -1;
static gint hf_sip_auth_ik                = -1;
static gint hf_sip_auth_ck                = -1;

static gint hf_sip_cseq_seq_no            = -1;
static gint hf_sip_cseq_method            = -1;

static gint hf_sip_via_transport          = -1;
static gint hf_sip_via_sent_by_address    = -1;
static gint hf_sip_via_sent_by_port       = -1;
static gint hf_sip_via_branch             = -1;
static gint hf_sip_via_maddr              = -1;
static gint hf_sip_via_rport              = -1;
static gint hf_sip_via_received           = -1;
static gint hf_sip_via_ttl                = -1;
static gint hf_sip_via_comp               = -1;
static gint hf_sip_via_sigcomp_id         = -1;

static gint hf_sip_rack_rseq_no           = -1;
static gint hf_sip_rack_cseq_no           = -1;
static gint hf_sip_rack_cseq_method       = -1;

static gint hf_sip_msg_body               = -1;

/* Initialize the subtree pointers */
static gint ett_sip                       = -1;
static gint ett_sip_reqresp               = -1;
static gint ett_sip_hdr                   = -1;
static gint ett_sip_ext_hdr               = -1;
static gint ett_raw_text                  = -1;
static gint ett_sip_element               = -1;
static gint ett_sip_hist                  = -1;
static gint ett_sip_uri                   = -1;
static gint ett_sip_contact_item          = -1;
static gint ett_sip_message_body          = -1;
static gint ett_sip_cseq                  = -1;
static gint ett_sip_via                   = -1;
static gint ett_sip_reason                = -1;
static gint ett_sip_rack                  = -1;
static gint ett_sip_route                 = -1;
static gint ett_sip_record_route          = -1;
static gint ett_sip_ruri                  = -1;
static gint ett_sip_to_uri                = -1;
static gint ett_sip_curi                  = -1;
static gint ett_sip_from_uri              = -1;
static gint ett_sip_pai_uri               = -1;
static gint ett_sip_pmiss_uri             = -1;
static gint ett_sip_ppi_uri               = -1;
static gint ett_sip_tc_uri                = -1;
#define ISUPPER(c)              ((c) >= 'A' && (c) <= 'Z')
#define ISLOWER(c)              ((c) >= 'a' && (c) <= 'z')
#define ISALPHA(c)              (ISUPPER (c) || ISLOWER (c))
#define TOUPPER(c)              (ISLOWER (c) ? (c) - 'a' + 'A' : (c))
#define TOLOWER(c)              (ISUPPER (c) ? (c) - 'A' + 'a' : (c))

static dissector_table_t media_type_dissector_table = NULL;
static dissector_handle_t media_handle = NULL;
//static dissector_handle_t data_handle = NULL;
static dissector_handle_t stream_jxta_handle = NULL;
typedef GSList *heur_dissector_list_t;
#define  g_slist_next(slist)	         ((slist) ? (((GSList *)(slist))->next) : NULL)
static heur_dissector_list_t heur_subdissector_list;
#define	SET_ADDRESS(addr, addr_type, addr_len, addr_data) { \
	(addr)->data = (addr_data); \
	(addr)->type = (addr_type); \
	(addr)->len  = (addr_len);  \
	}
static gboolean global_sip_raw_text = FALSE;
static gboolean global_sip_raw_text_without_crlf = FALSE;

#define	INITIAL_FMTBUF_SIZE	128
#define isprint(c) (c >= 0x20 && c < 0x7f)
#define _SPACE          0x8  
#define _DIGIT          0x4  

//#include <ctype.h>
/* set bit masks for the possible character types */

#define _UPPER          0x1     /* upper case letter */
#define _LOWER          0x2     /* lower case letter */
#define _DIGIT          0x4     /* digit[0-9] */
#define _SPACE          0x8     /* tab, carriage return, newline, */
                                /* vertical tab or form feed */
#define _PUNCT          0x10    /* punctuation character */
#define _CONTROL        0x20    /* control character */
#define _BLANK          0x40    /* space char */
#define _HEX            0x80    /* hexadecimal digit */

#define _LEADBYTE       0x8000                  /* multibyte leadbyte */
#define _ALPHA          (0x0100|_UPPER|_LOWER)  /* alphabetic character */


unsigned short _ctype[257] = {
  0,                      // -1 EOF
  _CONTROL,               // 00 (NUL)
  _CONTROL,               // 01 (SOH)
  _CONTROL,               // 02 (STX)
  _CONTROL,               // 03 (ETX)
  _CONTROL,               // 04 (EOT)
  _CONTROL,               // 05 (ENQ)
  _CONTROL,               // 06 (ACK)
  _CONTROL,               // 07 (BEL)
  _CONTROL,               // 08 (BS)
  _SPACE+_CONTROL,        // 09 (HT)
  _SPACE+_CONTROL,        // 0A (LF)
  _SPACE+_CONTROL,        // 0B (VT)
  _SPACE+_CONTROL,        // 0C (FF)
  _SPACE+_CONTROL,        // 0D (CR)
  _CONTROL,               // 0E (SI)
  _CONTROL,               // 0F (SO)
  _CONTROL,               // 10 (DLE)
  _CONTROL,               // 11 (DC1)
  _CONTROL,               // 12 (DC2)
  _CONTROL,               // 13 (DC3)
  _CONTROL,               // 14 (DC4)
  _CONTROL,               // 15 (NAK)
  _CONTROL,               // 16 (SYN)
  _CONTROL,               // 17 (ETB)
  _CONTROL,               // 18 (CAN)
  _CONTROL,               // 19 (EM)
  _CONTROL,               // 1A (SUB)
  _CONTROL,               // 1B (ESC)
  _CONTROL,               // 1C (FS)
  _CONTROL,               // 1D (GS)
  _CONTROL,               // 1E (RS)
  _CONTROL,               // 1F (US)
  _SPACE+_BLANK,          // 20 SPACE
  _PUNCT,                 // 21 !
  _PUNCT,                 // 22 "
  _PUNCT,                 // 23 #
  _PUNCT,                 // 24 $
  _PUNCT,                 // 25 %
  _PUNCT,                 // 26 &
  _PUNCT,                 // 27 '
  _PUNCT,                 // 28 (
  _PUNCT,                 // 29 )
  _PUNCT,                 // 2A *
  _PUNCT,                 // 2B +
  _PUNCT,                 // 2C ,
  _PUNCT,                 // 2D -
  _PUNCT,                 // 2E .
  _PUNCT,                 // 2F /
  _DIGIT+_HEX,            // 30 0
  _DIGIT+_HEX,            // 31 1
  _DIGIT+_HEX,            // 32 2
  _DIGIT+_HEX,            // 33 3
  _DIGIT+_HEX,            // 34 4
  _DIGIT+_HEX,            // 35 5
  _DIGIT+_HEX,            // 36 6
  _DIGIT+_HEX,            // 37 7
  _DIGIT+_HEX,            // 38 8
  _DIGIT+_HEX,            // 39 9
  _PUNCT,                 // 3A :
  _PUNCT,                 // 3B ;
  _PUNCT,                 // 3C <
  _PUNCT,                 // 3D =
  _PUNCT,                 // 3E >
  _PUNCT,                 // 3F ?
  _PUNCT,                 // 40 @
  _UPPER+_HEX,            // 41 A
  _UPPER+_HEX,            // 42 B
  _UPPER+_HEX,            // 43 C
  _UPPER+_HEX,            // 44 D
  _UPPER+_HEX,            // 45 E
  _UPPER+_HEX,            // 46 F
  _UPPER,                 // 47 G
  _UPPER,                 // 48 H
  _UPPER,                 // 49 I
  _UPPER,                 // 4A J
  _UPPER,                 // 4B K
  _UPPER,                 // 4C L
  _UPPER,                 // 4D M
  _UPPER,                 // 4E N
  _UPPER,                 // 4F O
  _UPPER,                 // 50 P
  _UPPER,                 // 51 Q
  _UPPER,                 // 52 R
  _UPPER,                 // 53 S
  _UPPER,                 // 54 T
  _UPPER,                 // 55 U
  _UPPER,                 // 56 V
  _UPPER,                 // 57 W
  _UPPER,                 // 58 X
  _UPPER,                 // 59 Y
  _UPPER,                 // 5A Z
  _PUNCT,                 // 5B [
  _PUNCT,                 // 5C \ 
  _PUNCT,                 // 5D ]
  _PUNCT,                 // 5E ^
  _PUNCT,                 // 5F _
  _PUNCT,                 // 60 `
  _LOWER+_HEX,            // 61 a
  _LOWER+_HEX,            // 62 b
  _LOWER+_HEX,            // 63 c
  _LOWER+_HEX,            // 64 d
  _LOWER+_HEX,            // 65 e
  _LOWER+_HEX,            // 66 f
  _LOWER,                 // 67 g
  _LOWER,                 // 68 h
  _LOWER,                 // 69 i
  _LOWER,                 // 6A j
  _LOWER,                 // 6B k
  _LOWER,                 // 6C l
  _LOWER,                 // 6D m
  _LOWER,                 // 6E n
  _LOWER,                 // 6F o
  _LOWER,                 // 70 p
  _LOWER,                 // 71 q
  _LOWER,                 // 72 r
  _LOWER,                 // 73 s
  _LOWER,                 // 74 t
  _LOWER,                 // 75 u
  _LOWER,                 // 76 v
  _LOWER,                 // 77 w
  _LOWER,                 // 78 x
  _LOWER,                 // 79 y
  _LOWER,                 // 7A z
  _PUNCT,                 // 7B {
  _PUNCT,                 // 7C |
  _PUNCT,                 // 7D }
  _PUNCT,                 // 7E ~
  _CONTROL,               // 7F (DEL)
  // and the rest are 0...
};
unsigned short *_pctype = _ctype + 1; // pointer to table for char's
#define isspace(c)     (_pctype[(unsigned char)(c)] & _SPACE)
#define isdigit(c)     (_pctype[(unsigned char)(c)] & _DIGIT)
#define isalpha(c)     (_pctype[(unsigned char)(c)] & _ALPHA)


#define ETHERNET_TYPE_II 2048
#define ETHERNET_TYPE_ARP 2054 //0x0806
#define ETHERNET_TYPE_RVARP  32821  //0x8035 
#define ETHERNET_TYPE_IEEE802  38//IFFF
#define ETHERNET_TYPE_IPV4  8 //0x0800
#define ETHERNET_TYPE_IPV6 34525 //0x86DD
#define ETHERNET_TYPE_Internetflowcontrol 34824 //0x8808
#define ETHERNET_TYPE_PPP 33 //ppp
#define  ETHERNET_TYPE_PPP_LCP 49185//LINK CONtrol protocol 0xc021


//transoprtProtocol identifier
#define TRANSPORT_UDP 17 //USER DATAGRAM PROTOCOL
#define TRANSPORT_TCP 6  //transmission control protocol
#define TRANSPORT_ICMP 1  //internet control message protocol
#define TRANSPORT_HOP_HOP   0 //IPv6 Hop-by-Hop Option
#define TRANSPORT_MUX   18    //multiplexing
#define TRANSPORT_DCCP  33    //Datagram Congestion Control Protocol
#define TRANSPORT_SCTP  132   //Stream Control Transmission Protocol
#define TRANSPORT_IGMP   2 //Internet Group Management

struct flag_id
{
     int pcap_flage[3];
} flag_id_v;

typedef struct WaveHeader {
    char chunkId[4];
    int  chunkSize;
    char format[4];

    char subChunk1Id[4];
    int  subChunk1Size;
    short int audioFormat;
    short int numChannels;
    int sampleRate;
    int byteRate;
    short int blockAlign;
    short int bitsPerSample;
    char subChunk2Id[4];
    int  subChunk2Size;

} WaveHeader;

# define char_length 16
# define arr_length 16
////////////////////////////////////////////////////////////////////H_245/////////////////////////////////////////////////


#ifndef PACKET_H245_H
#define PACKET_H245_H
typedef enum _h245_msg_type {
	H245_TermCapSet,
	H245_TermCapSetAck,
	H245_TermCapSetRjc,
	H245_TermCapSetRls,
	H245_OpenLogChn,
	H245_OpenLogChnCnf,
	H245_OpenLogChnAck,
	H245_OpenLogChnRjc,	
	H245_CloseLogChn,
	H245_CloseLogChnAck,
	H245_MastSlvDet,
	H245_MastSlvDetAck,
	H245_MastSlvDetRjc,
	H245_MastSlvDetRls,
        H245_OTHER
} h245_msg_type;

typedef struct _h245_packet_info {
        h245_msg_type msg_type;         /* type of message */
        gchar frame_label[50];          /* the Frame label used by graph_analysis, what is a abreviation of cinfo */
        gchar comment[50];                      /* the Frame Comment used by graph_analysis, what is a message desc */
} h245_packet_info;

/*
 * h223 LC info
 */

typedef enum {
	al_nonStandard,
	al1Framed,
	al1NotFramed,
	al2WithoutSequenceNumbers,
	al2WithSequenceNumbers,
	al3,
	/*...*/
	/* al?M: unimplemented annex C adaptation layers */
	al1M,
	al2M,
	al3M
} h223_al_type;

typedef struct {
	guint8 control_field_octets;
	guint32 send_buffer_size;
} h223_al3_params;

typedef struct {
	h223_al_type al_type;
	gpointer al_params;
	gboolean segmentable;
	dissector_handle_t subdissector;
} h223_lc_params;

typedef enum {
	H245_nonStandardDataType,
	H245_nullData,
	H245_videoData,
	H245_audioData,
	H245_data,
	H245_encryptionData,
	/*...,*/
	H245_h235Control,
	H245_h235Media,
	H245_multiplexedStream,
	H245_redundancyEncoding,
	H245_multiplePayloadStream,
	H245_fec
} h245_lc_data_type_enum;

typedef struct {
	h245_lc_data_type_enum data_type;
	gpointer               params;
} h245_lc_data_type;

/*
 * h223 MUX info
 */

typedef struct _h223_mux_element h223_mux_element;
struct _h223_mux_element {
    h223_mux_element* sublist; /* if NULL, use vc instead */
    guint16 vc;
    guint16 repeat_count; /* 0 == untilClosingFlag */
    h223_mux_element* next;
};


typedef void (*h223_set_mc_handle_t) ( packet_info* pinfo, guint8 mc, h223_mux_element* me );
extern void h245_set_h223_set_mc_handle( h223_set_mc_handle_t handle );

typedef void (*h223_add_lc_handle_t) ( packet_info* pinfo, guint16 lc, h223_lc_params* params );
extern void h245_set_h223_add_lc_handle( h223_add_lc_handle_t handle );


/*--- Included file: packet-h245-exp.h ---*/
extern const value_string h245_Capability_vals[];
extern const value_string DataProtocolCapability_vals[];
extern const value_string h245_TransportAddress_vals[];
extern const value_string h245_UnicastAddress_vals[];
extern const value_string h245_MulticastAddress_vals[];
int dissect_h245_Capability(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_H223Capability(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_QOSCapability(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_DataProtocolCapability(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_T38FaxProfile(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_OpenLogicalChannel(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_H223LogicalChannelParameters(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_TransportAddress(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_UnicastAddress(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );
int dissect_h245_MulticastAddress(tvbuff_t *tvb , int offset , asn1_ctx_t *actx , int hf_index );

/*--- End of included file: packet-h245-exp.h ---*/
void dissect_h245_FastStart_OLC(tvbuff_t *tvb, packet_info *pinfo , char *codec_str);


#endif  /* PACKET_H245_H */

static int proto_per = -1;
static int hf_per_GeneralString_length = -1;
static int hf_per_extension_bit = -1;
static int hf_per_extension_present_bit = -1;
static int hf_per_choice_index = -1;
static int hf_per_choice_extension_index = -1;
static int hf_per_enum_index = -1;
static int hf_per_enum_extension_index = -1;
static int hf_per_num_sequence_extensions = -1;
static int hf_per_small_number_bit = -1;
static int hf_per_optional_field_bit = -1;
static int hf_per_sequence_of_length = -1;
static int hf_per_object_identifier_length = -1;
static int hf_per_open_type_length = -1;
static int hf_per_real_length = -1;
static int hf_per_octet_string_length = -1;
static int hf_per_bit_string_length = -1;
static int hf_per_normally_small_nonnegative_whole_number_length = -1;
static int hf_per_const_int_len = -1;
static int hf_per_direct_reference = -1;          /* T_direct_reference */
static int hf_per_indirect_reference = -1;        /* T_indirect_reference */
static int hf_per_data_value_descriptor = -1;     /* T_data_value_descriptor */
static int hf_per_encoding = -1;                  /* External_encoding */
static int hf_per_single_ASN1_type = -1;          /* T_single_ASN1_type */
static int hf_per_octet_aligned = -1;             /* T_octet_aligned */
static int hf_per_arbitrary = -1;                 /* T_arbitrary */
static int hf_per_integer_length = -1;			  /* Show integer length if "show internal per fields" */
static int hf_per_debug_pos = -1;

static gint ett_per_open_type = -1;
static gint ett_per_containing = -1;
static gint ett_per_sequence_of_item = -1;
static gint ett_per_External = -1;
static gint ett_per_External_encoding = -1;

/*
#define DEBUG_ENTRY(x) \
printf("#%u  %s   tvb:0x%08x\n",actx->pinfo->fd->num,x,(int)tvb);
*/
#define DEBUG_ENTRY(x) \
	;

#define BLEN(old_offset, offset) (((offset)>>3)!=((old_offset)>>3)?((offset)>>3)-((old_offset)>>3):1)
 typedef struct h323_t
 {
	 char* msg_type;
	  guint8* src_ip;
	 guint8* dest_ip;
	 guint8* h245_ip;
	 int h245_port;
 }H323_attr;
/* whether the PER helpers should put the internal PER fields into the tree
   or not.
*/
static gboolean display_internal_per_fields = FALSE;
typedef int (*per_type_fn)(tvbuff_t*, int, asn1_ctx_t*, int);
typedef struct _per_choice_t {
	gint value;
	const int *p_id;
	int extension;
	per_type_fn func;
} per_choice_t;

typedef struct _per_sequence_t {
	const int *p_id;
	int extension;
	int optional;
	per_type_fn func;
	
} per_sequence_t;
/* flags */
#define ASN1_EXT_ROOT 0x01
#define ASN1_EXT_EXT  0x02
#define ASN1_OPT      0x04
#define ASN1_DFLT     0x08

#define ASN1_NO_EXTENSIONS	0
#define ASN1_EXTENSION_ROOT	    ASN1_EXT_ROOT
#define ASN1_NOT_EXTENSION_ROOT	ASN1_EXT_EXT

/* value for optional */
#define ASN1_NOT_OPTIONAL	0
#define ASN1_OPTIONAL		ASN1_OPT
#define pntohs(p)   ((guint16)                       \
                     ((guint16)*((const guint8 *)(p)+0)<<8|  \
                      (guint16)*((const guint8 *)(p)+1)<<0))

#define pntoh24(p)  ((guint32)*((const guint8 *)(p)+0)<<16|  \
                     (guint32)*((const guint8 *)(p)+1)<<8|   \
                     (guint32)*((const guint8 *)(p)+2)<<0)

#define pntohl(p)   ((guint32)*((const guint8 *)(p)+0)<<24|  \
                     (guint32)*((const guint8 *)(p)+1)<<16|  \
                     (guint32)*((const guint8 *)(p)+2)<<8|   \
                     (guint32)*((const guint8 *)(p)+3)<<0)

#define pntoh64(p)  ((guint64)*((const guint8 *)(p)+0)<<56|  \
                     (guint64)*((const guint8 *)(p)+1)<<48|  \
                     (guint64)*((const guint8 *)(p)+2)<<40|  \
                     (guint64)*((const guint8 *)(p)+3)<<32|  \
                     (guint64)*((const guint8 *)(p)+4)<<24|  \
                     (guint64)*((const guint8 *)(p)+5)<<16|  \
                     (guint64)*((const guint8 *)(p)+6)<<8|   \
                     (guint64)*((const guint8 *)(p)+7)<<0)


struct student 
{
            int msg_value;
			int  vendor_value;
            const guint8 *data_output;
			gboolean true_false;
			gint32 *octet_ip;
			gint32* octet_port;
			guint8 id[16];
};
struct student h_245_message_value;
 #define BYTE_ALIGN_OFFSET(offset) if(offset&0x07){offset=(offset&0xfffffff8)+8;}
 typedef struct {
  tvbuff_t *tvb;
  gboolean name_initialized;
  const char *name;
} data_source;
 #define va_start _crt_va_start
#define va_arg _crt_va_arg
#define va_end _crt_va_end
 typedef struct {
	time_t	secs;
	int	nsecs;
} nstime_t;



 //Q931
 typedef struct _q931_packet_info {
       gchar *calling_number;
       gchar *called_number;
       guint8 cause_value;
       gint32 crv;
       guint8 message_type;
} q931_packet_info;

 static gboolean have_valid_q931_pi=FALSE;
static q931_packet_info *q931_pi=NULL;
static int q931_tap = -1;
static const guint8* ensure_contiguous_no_exception(tvbuff_t *tvb, const gint offset, const gint length, int *exception);
static int proto_q931 					= -1;
static int hf_q931_discriminator			= -1;
static int hf_q931_coding_standard			= -1;
static int hf_q931_interpretation			= -1;
static int hf_q931_pres_meth_prot_prof			= -1;
static int hf_q931_high_layer_characteristics		= -1;
static int hf_q931_extended_high_layer_characteristics	= -1;
static int hf_q931_extended_audiovisual_characteristics	= -1;
static int hf_q931_information_transfer_capability	= -1;
static int hf_q931_transfer_mode			= -1;
static int hf_q931_information_transfer_rate		= -1;
static int hf_q931_layer_ident				= -1;
static int hf_q931_uil1					= -1;
static int hf_q931_call_ref_len 			= -1;
static int hf_q931_call_ref_flag 			= -1;
static int hf_q931_call_ref 				= -1;
static int hf_q931_message_type 			= -1;
static int hf_q931_maintenance_message_type	= -1;
static int hf_q931_segment_type 			= -1;
static int hf_q931_cause_location			= -1;
static int hf_q931_cause_value 				= -1;
static int hf_q931_number_type				= -1;
static int hf_q931_numbering_plan			= -1;
static int hf_q931_extension_ind			= -1;
static int hf_q931_calling_party_number 		= -1;
static int hf_q931_called_party_number 			= -1;
static int hf_q931_connected_number 			= -1;
static int hf_q931_redirecting_number 			= -1;
static int hf_q931_screening_ind				= -1;
static int hf_q931_presentation_ind				= -1;

/* fields for Channel Indentification IE */
static int hf_q931_channel_interface_explicit		= -1;
static int hf_q931_channel_interface_type		= -1;
static int hf_q931_channel_exclusive			= -1;
static int hf_q931_channel_dchan			= -1;
static int hf_q931_channel_selection_bri		= -1;
static int hf_q931_channel_selection_pri		= -1;
static int hf_q931_channel_map				= -1;
static int hf_q931_channel_element_type			= -1;
static int hf_q931_channel_number			= -1;


static int hf_q931_segments = -1;
static int hf_q931_segment = -1;
static int hf_q931_segment_overlap = -1;
static int hf_q931_segment_overlap_conflict = -1;
static int hf_q931_segment_multiple_tails = -1;
static int hf_q931_segment_too_long_segment = -1;
static int hf_q931_segment_error = -1;
static int hf_q931_segment_count = -1;
static int hf_q931_reassembled_in = -1;
static int hf_q931_reassembled_length = -1;

static gint ett_q931 					= -1;
static gint ett_q931_ie 				= -1;

static gint ett_q931_segments = -1;
static gint ett_q931_segment = -1;
typedef struct _fragment_items {
	gint	*ett_fragment;
	gint	*ett_fragments;

	int	*hf_fragments;
	int	*hf_fragment;
	int	*hf_fragment_overlap;
	int	*hf_fragment_overlap_conflict;
	int	*hf_fragment_multiple_tails;
	int	*hf_fragment_too_long_fragment;
	int	*hf_fragment_error;
	int     *hf_fragment_count;
	int	*hf_reassembled_in;
	int	*hf_reassembled_length;

	const char	*tag;
} fragment_items;
static const fragment_items q931_frag_items = {
	&ett_q931_segment,
	&ett_q931_segments,

	&hf_q931_segments,
	&hf_q931_segment,
	&hf_q931_segment_overlap,
	&hf_q931_segment_overlap_conflict,
	&hf_q931_segment_multiple_tails,
	&hf_q931_segment_too_long_segment,
	&hf_q931_segment_error,
	&hf_q931_segment_count,
	&hf_q931_reassembled_in,
	&hf_q931_reassembled_length,
	"segments"
};

/* Tables for reassembly of fragments. */
static GHashTable *q931_fragment_table = NULL;
static GHashTable *q931_reassembled_table = NULL;

/* Preferences */
static gboolean q931_reassembly = TRUE;

#define NLPID_NULL		0x00
#define NLPID_IPI_T_70		0x01	/* T.70, when an IPI */
#define NLPID_SPI_X_29		0x01	/* X.29, when an SPI */
#define NLPID_X_633		0x03	/* X.633 */
#define NLPID_DMS		0x03	/* Maintenace messages: AT&T TR41459, Nortel NIS A211-1, Telcordia SR-4994, ... */
#define NLPID_Q_931		0x08	/* Q.931, Q.932, X.36, ISO 11572, ISO 11582 */
#define NLPID_Q_933		0x08	/* Q.933, on Frame Relay */
#define NLPID_Q_2931		0x09	/* Q.2931 */
#define NLPID_Q_2119		0x0c	/* Q.2119 */
#define NLPID_SNAP		0x80
#define NLPID_ISO8473_CLNP	0x81	/* X.233 */
#define NLPID_ISO9542_ESIS	0x82
#define NLPID_ISO10589_ISIS	0x83
#define NLPID_ISO10747_IDRP     0x85
#define NLPID_ISO9542X25_ESIS	0x8a
#define NLPID_ISO10030		0x8c
#define NLPID_ISO11577		0x8d	/* X.273 */
#define NLPID_IP6		0x8e
#define NLPID_COMPRESSED	0xb0	/* "Data compression protocol" */
#define NLPID_SNDCF		0xc1	/* "SubNetwork Dependent Convergence Function */
#define NLPID_IEEE_8021AQ	0xc1	/* IEEE 802.1aq (draft-ietf-isis-ieee-aq-05.txt); defined in context of ISIS "supported protocols" TLV */
#define NLPID_IP		0xcc
#define NLPID_PPP		0xcf


#define First_bit(x) x>>7;
#define last_five_octet(x) x&0x1f
#define	Q931_IE_VL_EXTENSION		0x80	/* Extension flag */
#define DMS_SERVICE_ACKNOWLEDGE     0x07
#define DMS_SERVICE     0x0F


/*
 * Q.931 message types.
 */
#define Q931_ESCAPE               0x00
#define Q931_ALERTING             0x01
#define Q931_CALL_PROCEEDING      0x02
#define Q931_PROGRESS             0x03
#define Q931_SETUP                0x05
#define Q931_GROUIP_SERVICE       0x06
#define Q931_CONNECT              0x07
#define Q931_RESYNC_REQ           0x08
#define Q931_RESYNC_RESP          0x09
#define Q931_VERSION              0x0A
#define Q931_GROUIP_SERVICE_ACK   0x0B
#define Q931_SETUP_ACK            0x0D
#define Q931_CONNECT_ACK          0x0F
#define Q931_USER_INFORMATION     0x20
#define Q931_SUSPEND_REJECT       0x21
#define Q931_RESUME_REJECT        0x22
#define Q931_HOLD                 0x24
#define Q931_SUSPEND              0x25
#define Q931_RESUME               0x26
#define Q931_HOLD_ACK             0x28
#define Q931_SUSPEND_ACK          0x2D
#define Q931_RESUME_ACK           0x2E
#define Q931_HOLD_REJECT          0x30
#define Q931_RETRIEVE             0x31
#define Q931_RETRIEVE_ACK         0x33
#define Q931_RETRIEVE_REJECT      0x37
#define Q931_DETACH               0x40
#define Q931_DISCONNECT           0x45
#define Q931_RESTART              0x46
#define Q931_DETACH_ACKNOWLEDGE   0x48
#define Q931_RELEASE              0x4D
#define Q931_RESTART_ACK          0x4E
#define Q931_RELEASE_COMPLETE     0x5A
#define Q931_SEGMENT              0x60
#define Q931_FACILITY             0x62
#define Q931_REGISTER             0x64
#define Q931_FACILITY_ACKNOWLEDGE 0x6A
#define Q931_NOTIFY               0x6E
#define Q931_FACILITY_REJECT      0x72
#define Q931_STATUS_ENQUIRY       0x75
#define Q931_CONGESTION_CONTROL   0x79
#define Q931_INFORMATION          0x7B
#define Q931_STATUS               0x7D


struct _value_string_ext;
typedef const value_string *(*_value_string_match2_t)(const guint32, const struct _value_string_ext *);

const value_string q931_message_type_vals[] = {
/*  0 */	{ Q931_ESCAPE,				"ESCAPE" },
/*  1 */	{ Q931_ALERTING,			"ALERTING" },
/*  2 */	{ Q931_CALL_PROCEEDING,		"CALL PROCEEDING" },
/*  3 */	{ Q931_PROGRESS,			"PROGRESS" },
/*  5 */	{ Q931_SETUP,				"SETUP" },
/*  6 */	{ Q931_GROUIP_SERVICE,		"GROUP SERVICE" },
/*  7 */	{ Q931_CONNECT,				"CONNECT" },
/*  8 */	{ Q931_RESYNC_REQ,			"RESYNC REQ" },
/*  9 */	{ Q931_RESYNC_RESP,			"RESYNC RESP" },
/* 10 */	{ Q931_VERSION,				"VERSION" },
/* 11 */	{ Q931_GROUIP_SERVICE_ACK,	"GROUP SERVICE ACK" },
/* 13 */	{ Q931_SETUP_ACK,			"SETUP ACKNOWLEDGE" },
/* 15 */	{ Q931_CONNECT_ACK,			"CONNECT ACKNOWLEDGE" },
/* 32 */	{ Q931_USER_INFORMATION,	"USER INFORMATION" },
/* 33 */	{ Q931_SUSPEND_REJECT,		"SUSPEND REJECT" },
/* 34 */	{ Q931_RESUME_REJECT,		"RESUME REJECT" },
/* 36 */	{ Q931_HOLD,				"HOLD" },
/* 37 */	{ Q931_SUSPEND,				"SUSPEND" },
/* 38 */	{ Q931_RESUME,				"RESUME" },
/* 40 */	{ Q931_HOLD_ACK,			"HOLD_ACKNOWLEDGE" },
/* 45 */	{ Q931_SUSPEND_ACK,			"SUSPEND ACKNOWLEDGE" },
/* 46 */	{ Q931_RESUME_ACK,			"RESUME ACKNOWLEDGE" },
/* 48 */	{ Q931_HOLD_REJECT,			"HOLD_REJECT" },
/* 49 */	{ Q931_RETRIEVE,			"RETRIEVE" },
/* 51 */	{ Q931_RETRIEVE_ACK,		"RETRIEVE ACKNOWLEDGE" },
/* 55 */	{ Q931_RETRIEVE_REJECT,		"RETRIEVE REJECT" },
/* 64 */	{ Q931_DETACH, 				"DETACH" },
/* 69 */	{ Q931_DISCONNECT,			"DISCONNECT" },
/* 70 */	{ Q931_RESTART,				"RESTART" },
/* 72 */	{ Q931_DETACH_ACKNOWLEDGE,	"DETACH ACKNOWLEDGE" },
/* 77 */	{ Q931_RELEASE,				"RELEASE" },
/* 78 */	{ Q931_RESTART_ACK,			"RESTART ACKNOWLEDGE" },
/* 90 */	{ Q931_RELEASE_COMPLETE,	"RELEASE COMPLETE" },
/* 96 */	{ Q931_SEGMENT,				"SEGMENT" },
/* 98 */	{ Q931_FACILITY,			"FACILITY" },
/*100 */	{ Q931_REGISTER,			"REGISTER" },
/*106 */	{ Q931_FACILITY_ACKNOWLEDGE,	"FACILITY ACKNOWLEDGE" },
/*110 */	{ Q931_NOTIFY,				"NOTIFY" },
/*114 */	{ Q931_FACILITY_REJECT,		"FACILITY REJECT" },
/*117 */	{ Q931_STATUS_ENQUIRY,		"STATUS ENQUIRY" },
/*121 */	{ Q931_CONGESTION_CONTROL,	"CONGESTION CONTROL" },
/*123 */	{ Q931_INFORMATION,			"INFORMATION" },
/*125 */	{ Q931_STATUS,				"STATUS" },

	{ 0,				NULL }
};



#define	Q931_IE_SEGMENTED_MESSAGE	0x00
#define	Q931_IE_CHANGE_STATUS	0x01
#define	Q931_IE_BEARER_CAPABILITY	0x04
#define	Q931_IE_CAUSE			0x08
#define	Q931_IE_CALL_IDENTITY		0x10
#define	Q931_IE_CALL_STATE		0x14
#define	Q931_IE_CHANNEL_IDENTIFICATION	0x18
#define	Q931_IE_FACILITY		0x1C
#define	Q931_IE_PROGRESS_INDICATOR	0x1E
#define	Q931_IE_NETWORK_SPECIFIC_FACIL	0x20	/* Network Specific Facilities */
#define	Q931_IE_NOTIFICATION_INDICATOR	0x27
#define	Q931_IE_DISPLAY			0x28
#define	Q931_IE_DATE_TIME		0x29
#define	Q931_IE_KEYPAD_FACILITY		0x2C
#define	Q931_IE_INFORMATION_REQUEST	0x32
#define	Q931_IE_SIGNAL			0x34
#define	Q931_IE_SWITCHHOOK		0x36
#define	Q931_IE_FEATURE_ACTIVATION	0x38
#define	Q931_IE_FEATURE_INDICATION	0x39
#define	Q931_IE_ENDPOINT_IDENTIFIER	0x3B
#define	Q931_IE_SERVICE_PROFILE_ID	0x3A
#define	Q931_IE_INFORMATION_RATE	0x40
#define	Q931_IE_E2E_TRANSIT_DELAY	0x42	/* End-to-end Transit Delay */
#define	Q931_IE_TD_SELECTION_AND_INT	0x43	/* Transit Delay Selection and Indication */
#define	Q931_IE_PL_BINARY_PARAMETERS	0x44	/* Packet layer binary parameters */
#define	Q931_IE_PL_WINDOW_SIZE		0x45	/* Packet layer window size */
#define	Q931_IE_PACKET_SIZE		0x46	/* Packet size */
#define	Q931_IE_CUG			0x47	/* Closed user group */
#define	Q931_IE_REVERSE_CHARGE_IND	0x4A	/* Reverse charging indication */
#define	Q931_IE_CONNECTED_NUMBER_DEFAULT        0x4C	/* Connected Number */
#define	Q931_IE_INTERFACE_SERVICE	0x66	/* q931+ Interface Service */
#define	Q931_IE_CHANNEL_STATUS		0x67	/* q931+ Channel Status */
#define	Q931_IE_VERSION_INFO		0x68	/* q931+ Version Info */
#define	Q931_IE_CALLING_PARTY_NUMBER	0x6C	/* Calling Party Number */
#define	Q931_IE_CALLING_PARTY_SUBADDR	0x6D	/* Calling Party Subaddress */
#define	Q931_IE_CALLED_PARTY_NUMBER	0x70	/* Called Party Number */
#define	Q931_IE_CALLED_PARTY_SUBADDR	0x71	/* Called Party Subaddress */
#define	Q931_IE_REDIRECTING_NUMBER	0x74
#define	Q931_IE_REDIRECTION_NUMBER	0x76
#define	Q931_IE_TRANSIT_NETWORK_SEL	0x78	/* Transit Network Selection */
#define	Q931_IE_RESTART_INDICATOR	0x79
#define	Q931_IE_LOW_LAYER_COMPAT	0x7C	/* Low-Layer Compatibility */
#define	Q931_IE_HIGH_LAYER_COMPAT	0x7D	/* High-Layer Compatibility */
#define	Q931_IE_USER_USER		0x7E	/* User-User */
#define	Q931_IE_ESCAPE			0x7F	/* Escape for extension */

/*
 * Codeset 0 ETSI.
 */
#define	Q931_IE_CONNECTED_NUMBER	0x8C
#define	Q931_IE_CONNECTED_SUBADDR	0x8D

/*
 * Codeset 5 (National-specific) Belgium.
 */
#define	Q931_IE_CHARGING_ADVICE		0x1A

/*
 * Codeset 5 (National-specific) Bellcore National ISDN.
 */
#define	Q931_IE_OPERATOR_SYSTEM_ACCESS	0x1D

/*
 * Codeset 5 ETSI ETS 300 192
 */
#define	Q931_IE_PARTY_CATEGORY		0x32

/*
 * Codeset 6 (Network-specific) Belgium.
 */
/* 0x1A is Charging Advice, as with Codeset 5 */
#define	Q931_IE_REDIRECTING_NUMBER	0x74

/*
 * Codeset 6 (Network-specific) FT-Numeris.
 */
/* 0x1D is User Capability */

/*
 * Codeset 6 (Network-specific) Bellcore National ISDN.
 */
#define	Q931_IE_REDIRECTING_SUBADDR	0x75	/* Redirecting Subaddress */
/* 0x76 is Redirection Number, but that's also Codeset 0 */
#define	Q931_IE_CALL_APPEARANCE		0x7B

#define NUM_INFO_ELEMENT_VALS	(Q931_IE_SHIFT_CODESET+1)
typedef enum {
	NONE,
	CALLING_PARTY_NUMBER,
	CALLED_PARTY_NUMBER
	} e164_number_type_t;
typedef struct {
	e164_number_type_t e164_number_type;
	guint nature_of_address;
	char *E164_number_str;		/* E164 number string */
	guint E164_number_length;	/* Length of the E164_number string */
} e164_info_t;


/* Shifted codeset values */
#define CS0 0x000
#define CS1 0x100
#define CS2 0x200
#define CS3 0x300
#define CS4 0x400
#define CS5 0x500
#define CS6 0x600
#define CS7 0x700

#define	Q931_IE_REDIRECTING_SUBADDR	0x75	/* Redirecting Subaddress */
/* 0x76 is Redirection Number, but that's also Codeset 0 */
#define	Q931_IE_CALL_APPEARANCE		0x7B


#define NUM_INFO_ELEMENT_VALS	(Q931_IE_SHIFT_CODESET+1)
#define	Q931_PROTOCOL_DISCRIMINATOR_USER	0x00
#define	Q931_PROTOCOL_DISCRIMINATOR_IA5		0x04
#define Q931_PROTOCOL_DISCRIMINATOR_ASN1	0x05
static dissector_handle_t h225_handle;
#define	Q931_CAUSE_UNALLOC_NUMBER	0x01
#define	Q931_CAUSE_NO_ROUTE_TO_DEST	0x03
#define	Q931_CAUSE_CALL_REJECTED	0x15
#define	Q931_CAUSE_NUMBER_CHANGED	0x16
#define	Q931_CAUSE_ACCESS_INFO_DISC	0x2B
#define	Q931_CAUSE_QOS_UNAVAILABLE	0x31
#define	Q931_CAUSE_CHAN_NONEXISTENT	0x52
#define	Q931_CAUSE_INCOMPATIBLE_DEST	0x58
#define	Q931_CAUSE_MAND_IE_MISSING	0x60
#define	Q931_CAUSE_MT_NONEX_OR_UNIMPL	0x61
#define	Q931_CAUSE_IE_NONEX_OR_UNIMPL	0x63
#define	Q931_CAUSE_INVALID_IE_CONTENTS	0x64
#define	Q931_CAUSE_MSG_INCOMPAT_W_CS	0x65
#define	Q931_CAUSE_REC_TIMER_EXP	0x66

#define	Q931_INTERFACE_IDENTIFIED	0x40
#define	Q931_NOT_BASIC_CHANNEL		0x20
#define	Q931_IS_SLOT_MAP		0x10

#define ENC_TIME_TIMESPEC	0x00000000
#define ENC_TIME_NTP		0x00000002
#define ENC_CHARENCODING_MASK	0x7FFFFFFE	/* mask out byte-order bits */
#define ENC_ASCII		0x00000000
#define ENC_UTF_8		0x00000002
#define ENC_UTF_16		0x00000004
#define ENC_UCS_2		0x00000006
#define ENC_EBCDIC		0x00000008
#define ENC_NA			0x00000000
void EBCDIC_to_ASCII(guint8 *buf, guint bytes);
guint8 EBCDIC_to_ASCII1(guint8 c);
#define Q931_HIGH_LAYER_PROTOCOL_PROFILE 0x01
#define	Q931_PROTOCOL_DISCRIMINATOR_USER	0x00
#define	Q931_PROTOCOL_DISCRIMINATOR_IA5		0x04
#define Q931_PROTOCOL_DISCRIMINATOR_ASN1	0x05

#define First_bit(x) x>>7;
#define last_five_octet(x) x&0x1f
#define	Q931_IE_VL_EXTENSION		0x80	/* Extension flag */
#define	Q931_REJ_USER_SPECIFIC		0x00
#define	Q931_REJ_IE_MISSING		0x04
#define	Q931_REJ_IE_INSUFFICIENT	0x08
#define BER_MAX_NESTING 500





//++++++++++++++ h.225 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
typedef enum _h225_msg_type {
	H225_RAS,
	H225_CS,
	H225_OTHERS
} h225_msg_type;
typedef enum _h225_cs_type {
    H225_SETUP,
    H225_CALL_PROCEDING,
    H225_CONNECT,
    H225_ALERTING,
    H225_INFORMATION,
    H225_RELEASE_COMPLET,
    H225_FACILITY,
    H225_PROGRESS,
    H225_EMPTY,
    H225_STATUS,
    H225_STATUS_INQUIRY,
    H225_SETUP_ACK,
    H225_NOTIFY,
    H225_OTHER
} h225_cs_type;

 typedef struct _e_guid_t {
   guint32 data1;
    guint16 data2;
    guint16 data3;
     guint8  data4[8];
   } e_guid_t;
typedef struct _h225_packet_info {
	h225_msg_type msg_type;		/* ras or cs message */
	h225_cs_type cs_type;		/* cs message type */
	gint msg_tag;			/* message tag*/
	gint reason;			/* reason tag, if available */
	guint requestSeqNum;		/* request sequence number of ras-message, if available */
	e_guid_t guid;			/* globally unique call id */
	gboolean is_duplicate;		/* true, if this is a repeated message */
	gboolean request_available;	/* true, if response matches to a request */
	nstime_t delta_time; 		/* this is the RAS response time delay */
	/* added for h225 conversations analysis */
	gboolean is_faststart;		/* true, if faststart field is included */
	gboolean is_h245;
	gboolean is_h245Tunneling;
	guint32 h245_address;
	guint16 h245_port;
	gchar dialedDigits[129]; /* Dialed Digits in the LRQ and LCF used for voip analysis */
	gboolean is_destinationInfo;
	gchar frame_label[50]; /* the Fram label used by graph_analysis, what is a abreviation of cinfo */
} h225_packet_info;
#define NTVB_PORT	NTVB_UINT
  typedef enum {
  NTVB_HANDLE,
  NTVB_UINT,
  NTVB_STRING
} next_tvb_call_e;

typedef struct next_tvb_item {
  struct next_tvb_item *next;
  struct next_tvb_item *previous;
  next_tvb_call_e type;
  dissector_handle_t handle;
  dissector_table_t table;
  guint32 uint_val;
  const gchar *string;
  tvbuff_t *tvb;
 // proto_tree *tree;
} next_tvb_item_t;
  typedef struct {
  next_tvb_item_t *first;
  next_tvb_item_t *last;
  int count;
} next_tvb_list_t;
static next_tvb_list_t h245_list;
/*--- End of included file: packet-h235-ett.c ---*/
#define GEF_CTX_SIGNATURE 0x47454658  /* "GEFX" */
 
  typedef struct _gef_ctx_t {
     guint32 signature;
    struct _gef_ctx_t *parent;
    /*
   35     H323-MESSAGES
   36       FeatureDescriptor/<id>
   37         <id>
   38       GenericData/<id>
   39         <id>
   40     MULTIMEDIA-SYSTEM-CONTROL
   41       GenericInformation/<id>[-<subid>]
   42         <id>
   43       GenericMessage/<id>[-<subid>]
   44         <id>
   45       GenericCapability/<id>
   46         collapsing/<id>
   47         nonCollapsing/<id>
   48         nonCollapsingRaw
   49       EncryptionSync
   50         <id>
   51   */
     const gchar *type;
     const gchar *id;
     const gchar *subid;
     const gchar *key;
    } gef_ctx_t;
  #define             G_GNUC_MALLOC
  void* ep_alloc0(size_t size) G_GNUC_MALLOC;
#define MAX_STRBUF_LEN 65536
#define DEFAULT_STRBUF_LEN (ITEM_LABEL_LENGTH / 10)
  typedef struct _emem_strbuf_t {
    gchar *str;             /**< Points to the character data. It may move as text is       */
                            /*  added. The str field is null-terminated and so can        */
                            /*  be used as an ordinary C string.                          */
    gsize len;              /**< strlen: ie: length of str not including trailing '\0'      */
    gsize alloc_len;        /**< num bytes curently allocated for str: 1 .. MAX_STRBUF_LEN  */
    gsize max_alloc_len;    /**< max num bytes to allocate for str: 1 .. MAX_STRBUF_LEN     */
} emem_strbuf_t;
  /*--- End of included file: packet-h245-ett.c ---*/
typedef enum {
  ASN1_PAR_IRR, /* irrelevant parameter */
  /* value */
  ASN1_PAR_BOOLEAN,
  ASN1_PAR_INTEGER,
  /* type */
  ASN1_PAR_TYPE
} asn1_par_type;
typedef struct _asn1_par_t {
  const gchar *name;
  asn1_par_type ptype;
  union {
    gboolean v_boolean;
    gint32 v_integer;
    void *v_type;
  } value;
  struct _asn1_par_t *next;
} asn1_par_t;
struct student_225 
{
            int msg_value;
			int  vendor_value;
            const guint8 *data_output;
			gboolean true_false;
			gint32 *octet_ip;
			gint32* octet_port;
			guint8 id[16];
};
struct student_225 h_225_message_value;
void fnc(struct student_225 h_225_message_value);
/*--- Included file: packet-h235-hf.c ---*/
//#line 1 "../../asn1/h235/packet-h235-hf.c"
static int hf_h235_SrtpCryptoCapability_PDU = -1;  /* SrtpCryptoCapability */
static int hf_h235_nonStandardIdentifier = -1;    /* OBJECT_IDENTIFIER */
static int hf_h235_data = -1;                     /* OCTET_STRING */
static int hf_h235_halfkey = -1;                  /* BIT_STRING_SIZE_0_2048 */
static int hf_h235_modSize = -1;                  /* BIT_STRING_SIZE_0_2048 */
static int hf_h235_generator = -1;                /* BIT_STRING_SIZE_0_2048 */
static int hf_h235_x = -1;                        /* BIT_STRING_SIZE_0_511 */
static int hf_h235_y = -1;                        /* BIT_STRING_SIZE_0_511 */
static int hf_h235_eckasdhp = -1;                 /* T_eckasdhp */
static int hf_h235_public_key = -1;               /* ECpoint */
static int hf_h235_modulus = -1;                  /* BIT_STRING_SIZE_0_511 */
static int hf_h235_base = -1;                     /* ECpoint */
static int hf_h235_weierstrassA = -1;             /* BIT_STRING_SIZE_0_511 */
static int hf_h235_weierstrassB = -1;             /* BIT_STRING_SIZE_0_511 */
static int hf_h235_eckasdh2 = -1;                 /* T_eckasdh2 */
static int hf_h235_fieldSize = -1;                /* BIT_STRING_SIZE_0_511 */
static int hf_h235_type = -1;                     /* OBJECT_IDENTIFIER */
static int hf_h235_certificatedata = -1;          /* OCTET_STRING */
static int hf_h235_default = -1;                  /* NULL */
static int hf_h235_radius = -1;                   /* NULL */
static int hf_h235_dhExch = -1;                   /* NULL */
static int hf_h235_pwdSymEnc = -1;                /* NULL */
static int hf_h235_pwdHash = -1;                  /* NULL */
static int hf_h235_certSign = -1;                 /* NULL */
static int hf_h235_ipsec = -1;                    /* NULL */
static int hf_h235_tls = -1;                      /* NULL */
static int hf_h235_nonStandard = -1;              /* NonStandardParameter */
static int hf_h235_authenticationBES = -1;        /* AuthenticationBES */
static int hf_h235_keyExch = -1;                  /* OBJECT_IDENTIFIER */
static int hf_h235_tokenOID = -1;                 /* OBJECT_IDENTIFIER */
static int hf_h235_timeStamp = -1;                /* TimeStamp */
static int hf_h235_password = -1;                 /* Password */
static int hf_h235_dhkey = -1;                    /* DHset */
static int hf_h235_challenge = -1;                /* ChallengeString */
static int hf_h235_random = -1;                   /* RandomVal */
static int hf_h235_certificate = -1;              /* TypedCertificate */
static int hf_h235_generalID = -1;                /* Identifier */
static int hf_h235_eckasdhkey = -1;               /* ECKASDH */
static int hf_h235_sendersID = -1;                /* Identifier */
static int hf_h235_h235Key = -1;                  /* H235Key */
static int hf_h235_profileInfo = -1;              /* SEQUENCE_OF_ProfileElement */
static int hf_h235_profileInfo_item = -1;         /* ProfileElement */
static int hf_h235_elementID = -1;                /* INTEGER_0_255 */
static int hf_h235_paramS = -1;                   /* Params */
static int hf_h235_element = -1;                  /* Element */
static int hf_h235_octets = -1;                   /* OCTET_STRING */
static int hf_h235_integer = -1;                  /* INTEGER */
static int hf_h235_bits = -1;                     /* BIT_STRING */
static int hf_h235_name = -1;                     /* BMPString */
static int hf_h235_flag = -1;                     /* BOOLEAN */
static int hf_h235_toBeSigned = -1;               /* ToBeSigned */
static int hf_h235_algorithmOID = -1;             /* OBJECT_IDENTIFIER */
static int hf_h235_signaturedata = -1;            /* BIT_STRING */
static int hf_h235_encryptedData = -1;            /* OCTET_STRING */
static int hf_h235_hash = -1;                     /* BIT_STRING */
static int hf_h235_ranInt = -1;                   /* INTEGER */
static int hf_h235_iv8 = -1;                      /* IV8 */
static int hf_h235_iv16 = -1;                     /* IV16 */
static int hf_h235_iv = -1;                       /* OCTET_STRING */
static int hf_h235_clearSalt = -1;                /* OCTET_STRING */
static int hf_h235_cryptoEncryptedToken = -1;     /* T_cryptoEncryptedToken */
static int hf_h235_encryptedToken = -1;           /* ENCRYPTED */
static int hf_h235_cryptoSignedToken = -1;        /* T_cryptoSignedToken */
static int hf_h235_signedToken = -1;              /* SIGNED */
static int hf_h235_cryptoHashedToken = -1;        /* T_cryptoHashedToken */
static int hf_h235_hashedVals = -1;               /* ClearToken */
static int hf_h235_hashedToken = -1;              /* HASHED */
static int hf_h235_cryptoPwdEncr = -1;            /* ENCRYPTED */
static int hf_h235_secureChannel = -1;            /* KeyMaterial */
static int hf_h235_sharedSecret = -1;             /* ENCRYPTED */
static int hf_h235_certProtectedKey = -1;         /* SIGNED */
static int hf_h235_secureSharedSecret = -1;       /* V3KeySyncMaterial */
static int hf_h235_encryptedSessionKey = -1;      /* OCTET_STRING */
static int hf_h235_encryptedSaltingKey = -1;      /* OCTET_STRING */
static int hf_h235_clearSaltingKey = -1;          /* OCTET_STRING */
static int hf_h235_paramSsalt = -1;               /* Params */
static int hf_h235_keyDerivationOID = -1;         /* OBJECT_IDENTIFIER */
static int hf_h235_genericKeyMaterial = -1;       /* OCTET_STRING */
static int hf_h235_SrtpCryptoCapability_item = -1;  /* SrtpCryptoInfo */
static int hf_h235_cryptoSuite = -1;              /* OBJECT_IDENTIFIER */
static int hf_h235_sessionParams = -1;            /* SrtpSessionParameters */
static int hf_h235_allowMKI = -1;                 /* BOOLEAN */
static int hf_h235_SrtpKeys_item = -1;            /* SrtpKeyParameters */
static int hf_h235_masterKey = -1;                /* OCTET_STRING */
static int hf_h235_masterSalt = -1;               /* OCTET_STRING */
static int hf_h235_lifetime = -1;                 /* T_lifetime */
static int hf_h235_powerOfTwo = -1;               /* INTEGER */
static int hf_h235_specific = -1;                 /* INTEGER */
static int hf_h235_mki = -1;                      /* T_mki */
static int hf_h235_length = -1;                   /* INTEGER_1_128 */
static int hf_h235_value = -1;                    /* OCTET_STRING */
static int hf_h235_kdr = -1;                      /* INTEGER_0_24 */
static int hf_h235_unencryptedSrtp = -1;          /* BOOLEAN */
static int hf_h235_unencryptedSrtcp = -1;         /* BOOLEAN */
static int hf_h235_unauthenticatedSrtp = -1;      /* BOOLEAN */
static int hf_h235_fecOrder = -1;                 /* FecOrder */
static int hf_h235_windowSizeHint = -1;           /* INTEGER_64_65535 */
static int hf_h235_newParameter = -1;             /* SEQUENCE_OF_GenericData */
static int hf_h235_newParameter_item = -1;        /* GenericData */
static int hf_h235_fecBeforeSrtp = -1;            /* NULL */
static int hf_h235_fecAfterSrtp = -1;             /* NULL */
/*--- End of included file: packet-h235-hf.c ---*/
/*--- Included file: packet-h235-ett.c ---*/
//#line 1 "../../asn1/h235/packet-h235-ett.c"
static gint ett_h235_NonStandardParameter = -1;
static gint ett_h235_DHset = -1;
static gint ett_h235_ECpoint = -1;
static gint ett_h235_ECKASDH = -1;
static gint ett_h235_T_eckasdhp = -1;
static gint ett_h235_T_eckasdh2 = -1;
static gint ett_h235_TypedCertificate = -1;
static gint ett_h235_AuthenticationBES = -1;
static gint ett_h235_AuthenticationMechanism = -1;
static gint ett_h235_ClearToken = -1;
static gint ett_h235_SEQUENCE_OF_ProfileElement = -1;
static gint ett_h235_ProfileElement = -1;
static gint ett_h235_Element = -1;
static gint ett_h235_SIGNED = -1;
static gint ett_h235_ENCRYPTED = -1;
static gint ett_h235_HASHED = -1;
static gint ett_h235_Params = -1;
static gint ett_h235_CryptoToken = -1;
static gint ett_h235_T_cryptoEncryptedToken = -1;
static gint ett_h235_T_cryptoSignedToken = -1;
static gint ett_h235_T_cryptoHashedToken = -1;
static gint ett_h235_H235Key = -1;
static gint ett_h235_V3KeySyncMaterial = -1;
static gint ett_h235_SrtpCryptoCapability = -1;
static gint ett_h235_SrtpCryptoInfo = -1;
static gint ett_h235_SrtpKeys = -1;
static gint ett_h235_SrtpKeyParameters = -1;
static gint ett_h235_T_lifetime = -1;
static gint ett_h235_T_mki = -1;
static gint ett_h235_SrtpSessionParameters = -1;
static gint ett_h235_SEQUENCE_OF_GenericData = -1;
static gint ett_h235_FecOrder = -1;
 H323_attr* ip_val=(H323_attr* )malloc(sizeof(H323_attr));