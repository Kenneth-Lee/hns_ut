#ifndef _COMM_H
#define _COMM_H

#include "ut.c"

typedef long long __le64;
typedef short __le16;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long long dma_addr_t;
typedef int bool;
typedef unsigned long size_t;
typedef int irqreturn_t;


#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define __iomem

#define MODULE_DESCRIPTION(str)
#define MODULE_AUTHOR(str)
#define MODULE_LICENSE(str)
#define MODULE_ALIAS(str)
#define EXPORT_SYMBOL(str)

enum netdev_tx {
	//__NETDEV_TX_MIN	 = INT_MIN,	/* make sure enum is signed */
	NETDEV_TX_OK	 = 0x00,	/* driver took care of packet */
	NETDEV_TX_BUSY	 = 0x10,	/* driver tx path was busy*/
	NETDEV_TX_LOCKED = 0x20,	/* driver tx lock was already taken */
};
typedef enum netdev_tx netdev_tx_t;

#define DMA_TO_DEVICE 1
#define DMA_FROM_DEVICE 2
#define DMA_BIDIRECTIONAL 3

#define IRQ_HANDLED 1

#define HZ 1

#define IFF_UNICAST_FLT 1
#define NETIF_F_IP_CSUM 0x1 
#define NETIF_F_IPV6_CSUM 0x2
#define NETIF_F_RXCSUM 0x4
#define NETIF_F_SG 0x8
#define NETIF_F_GSO 0xf
#define NETIF_F_GRO 0x10

#define DMA_BIT_MASK(val) (val)

unsigned long jiffies;

//-------real list stub----------------------
struct list_head {
	        struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
		struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
		list->next = list;
			list->prev = list;
}


#define list_entry(ptr, type, member) \
	        container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry_rcu(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
static inline void list_del_rcu(struct list_head * entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
}
static inline void list_add_tail_rcu(struct list_head *new, struct list_head *head) {
	new->next = head;
	new->prev = head->prev;
	head->prev->next = new;
	head->prev = new;
}


struct hlist_node {};
struct ifreq {};
struct ethtool_cmd {};
struct module {};
struct device_node{};
struct of_device_id
{
	char	name[32];
	char	type[32];
	char	compatible[128];
	const void *data;
};

struct device {
	struct device_node	*of_node; /* associated device tree node */
#if 0
	struct device		*parent;

	struct device_private	*p;

	struct kobject kobj;
	const char		*init_name;
	const struct device_type *type;

	struct mutex		mutex;

	struct bus_type	*bus;
	struct device_driver *driver;
	void		*platform_data;
	void		*driver_data;
	struct dev_pm_info	power;
	struct dev_pm_domain	*pm_domain;

#ifdef CONFIG_PINCTRL
	struct dev_pin_info	*pins;
#endif

#ifdef CONFIG_NUMA
	int		numa_node;	/* NUMA node this device is close to */
#endif
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	u64		coherent_dma_mask;/* Like dma_mask, but for
					     alloc_coherent mappings as
					     not all hardware supports
					     64 bit addresses for consistent
					     allocations such descriptors. */
	unsigned long	dma_pfn_offset;

	struct device_dma_parameters *dma_parms;

	struct list_head	dma_pools;	/* dma pools (if dma'ble) */

	struct dma_coherent_mem	*dma_mem; /* internal for coherent mem
					     override */
#ifdef CONFIG_DMA_CMA
	struct cma *cma_area;		/* contiguous memory area for dma
					   allocations */
#endif
	/* arch specific additions */
	struct dev_archdata	archdata;

	struct acpi_dev_node	acpi_node; /* associated ACPI device node */

	dev_t			devt;	/* dev_t, creates the sysfs "dev" */
	u32			id;	/* device instance */

	spinlock_t		devres_lock;
	struct list_head	devres_head;

	struct klist_node	knode_class;
	struct class		*class;
	const struct attribute_group **groups;	/* optional groups */

	void	(*release)(struct device *dev);
	struct iommu_group	*iommu_group;

	struct mbi_data		*mbi;

	bool			offline_disabled:1;
	bool			offline:1;
#endif
};

#define SET_NETDEV_DEV(ndev, dev)

struct skb_frag_struct {
	/*
	struct {
		struct page *p;
	} page;
	*/
	u16 page_offset;
	u16 size;
};
typedef struct skb_frag_struct skb_frag_t;
struct net_device_stats {
	unsigned long	rx_packets;
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_bytes;
	unsigned long	rx_errors;
	unsigned long	tx_errors;
	unsigned long	rx_dropped;
	unsigned long	tx_dropped;
	unsigned long	multicast;
	unsigned long	collisions;
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;
	unsigned long	rx_crc_errors;
	unsigned long	rx_frame_errors;
	unsigned long	rx_fifo_errors;
	unsigned long	rx_missed_errors;
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};
struct net_device {
	char			name[256];
	//struct hlist_node	name_hlist;
	char 			*ifalias;
	unsigned long		mem_end;
	unsigned long		mem_start;
	unsigned long		base_addr;
	int			irq;
	unsigned long		state;

	struct list_head	dev_list;
	struct list_head	napi_list;
	struct list_head	unreg_list;
	struct list_head	close_list;

	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;

	struct {
		struct list_head upper;
		struct list_head lower;
	} all_adj_list;

	u32	features;
/*
	netdev_features_t	hw_features;
	netdev_features_t	wanted_features;
	netdev_features_t	vlan_features;
	netdev_features_t	hw_enc_features;
	netdev_features_t	mpls_features;
	*/

	int			ifindex;
	int			iflink;

	struct net_device_stats	stats;

	const struct net_device_ops *netdev_ops;
	const struct ethtool_ops *ethtool_ops;

/*
	atomic_long_t		rx_dropped;
	atomic_long_t		tx_dropped;

	atomic_t		carrier_changes;

	const struct forwarding_accel_ops *fwd_ops;

	const struct header_ops *header_ops;
	*/

	unsigned int		flags;
	unsigned int		priv_flags;

	unsigned short		gflags;
	unsigned short		padded;

	unsigned char		operstate;
	unsigned char		link_mode;

	unsigned char		if_port;
	unsigned char		dma;

	unsigned int		mtu;
	unsigned short		type;
	unsigned short		hard_header_len;

	unsigned short		needed_headroom;
	unsigned short		needed_tailroom;

	/* Interface address info. */
//	unsigned char		perm_addr[MAX_ADDR_LEN];
	unsigned char		addr_assign_type;
	unsigned char		addr_len;
	unsigned short		neigh_priv_len;
	unsigned short          dev_id;
	unsigned short          dev_port;
	/*
	spinlock_t		addr_list_lock;
	struct netdev_hw_addr_list	uc;
	struct netdev_hw_addr_list	mc;
	struct netdev_hw_addr_list	dev_addrs;

#ifdef CONFIG_SYSFS
	struct kset		*queues_kset;
#endif
	*/

	unsigned char		name_assign_type;

	bool			uc_promisc;
	unsigned int		promiscuity;
	unsigned int		allmulti;


	void 			*atalk_ptr;
	unsigned long		last_rx;
	unsigned char		*dev_addr;
	/*
	struct in_device __rcu	*ip_ptr;
	struct dn_dev __rcu     *dn_ptr;
	struct inet6_dev __rcu	*ip6_ptr;
	void			*ax25_ptr;
	struct wireless_dev	*ieee80211_ptr;



	rx_handler_func_t __rcu	*rx_handler;
	void __rcu		*rx_handler_data;

	struct netdev_queue __rcu *ingress_queue;
	unsigned char		broadcast[MAX_ADDR_LEN];

	struct netdev_queue	*_tx ____cacheline_aligned_in_smp;
	unsigned int		num_tx_queues;
	unsigned int		real_num_tx_queues;
	struct Qdisc		*qdisc;
	unsigned long		tx_queue_len;
	spinlock_t		tx_global_lock;
	*/

	unsigned long		trans_start;

	int			watchdog_timeo;
	/*
	struct timer_list	watchdog_timer;

	int __percpu		*pcpu_refcnt;
	struct list_head	todo_list;

	struct hlist_node	index_hlist;
	struct list_head	link_watch_list;
	*/

	enum { NETREG_UNINITIALIZED=0,
	       NETREG_REGISTERED,	/* completed register_netdevice */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
	       NETREG_UNREGISTERED,	/* completed unregister todo */
	       NETREG_RELEASED,		/* called free_netdev */
	       NETREG_DUMMY,		/* dummy device for NAPI poll */
	} reg_state:8;

	bool dismantle;

	enum {
		RTNL_LINK_INITIALIZED,
		RTNL_LINK_INITIALIZING,
	} rtnl_link_state:16;

	void (*destructor)(struct net_device *dev);

/*
	union {
		void					*ml_priv;
		struct pcpu_lstats __percpu		*lstats;
		struct pcpu_sw_netstats __percpu	*tstats;
		struct pcpu_dstats __percpu		*dstats;
		struct pcpu_vstats __percpu		*vstats;
	};

	struct garp_port __rcu	*garp_port;
	struct mrp_port __rcu	*mrp_port;
	*/

	struct device	dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;

	const struct rtnl_link_ops *rtnl_link_ops;

	/* for setting kernel sock attribute on TCP connection setup */
#define GSO_MAX_SIZE		65536
	unsigned int		gso_max_size;
#define GSO_MAX_SEGS		65535
	u16			gso_max_segs;
	u16			gso_min_segs;
#ifdef CONFIG_DCB
	const struct dcbnl_rtnl_ops *dcbnl_ops;
#endif
	u8 num_tc;
	//struct netdev_tc_txq tc_to_txq[TC_MAX_QUEUE];
//	u8 prio_tc_map[TC_BITMASK + 1];

/*
	struct phy_device *phydev;
	struct lock_class_key *qdisc_tx_busylock;
	int group;
	struct pm_qos_request	pm_qos_req;
	*/
};
struct sk_buff {
	struct sk_buff		*next;
	struct sk_buff		*prev;
/*
	union {
		ktime_t		tstamp;
		struct skb_mstamp skb_mstamp;
	};

	struct sock		*sk;
	*/
	struct net_device	*dev;

	char			cb[48];

	unsigned long		_skb_refdst;
	void			(*destructor)(struct sk_buff *skb);
	unsigned int		len,
				data_len;
	u16			mac_len,
				hdr_len;

	u16			queue_mapping;
	u8			cloned:1,
				nohdr:1,
				fclone:2,
				peeked:1,
				head_frag:1,
				xmit_more:1;
	u32			headers_start[0];
	u8			__pkt_type_offset[0];
	u8			pkt_type:3;
	u8			pfmemalloc:1;
	u8			ignore_df:1;
	u8			nfctinfo:3;

	u8			nf_trace:1;
	u8			ip_summed:2;
	u8			ooo_okay:1;
	u8			l4_hash:1;
	u8			sw_hash:1;
	u8			wifi_acked_valid:1;
	u8			wifi_acked:1;

	u8			no_fcs:1;
	u8			encapsulation:1;
	u8			encap_hdr_csum:1;
	u8			csum_valid:1;
	u8			csum_complete_sw:1;
	u8			csum_level:2;
	u8			csum_bad:1;

	u8			ipvs_property:1;
	u8			inner_protocol_type:1;


	union {
		//__wsum		csum;
		struct {
			u16	csum_start;
			u16	csum_offset;
		};
	};
	u32			priority;
	int			skb_iif;
	u32			hash;
	u16			vlan_proto;
	u16			vlan_tci;
	union {
		u32		mark;
		u32		dropcount;
		u32		reserved_tailroom;
	};

	union {
		u16		inner_protocol;
		u8		inner_ipproto;
	};

	u16			inner_transport_header;
	u16			inner_network_header;
	u16			inner_mac_header;

	u16			protocol;
	u16			transport_header;
	u16			network_header;
	u16			mac_header;

	/* private: */
	u32			headers_end[0];
	/* public: */

/*
	sk_buff_data_t		tail;
	sk_buff_data_t		end;
	*/
	unsigned char		*head,
				*data;
	unsigned int		truesize;
	//atomic_t		users;
};
struct napi_struct {
	struct list_head	poll_list;

	unsigned long		state;
	int			weight;
	unsigned int		gro_count;
	int			(*poll)(struct napi_struct *, int);
	/*
	spinlock_t		poll_lock;
	int			poll_owner;
	*/
	struct net_device	*dev;
	struct sk_buff		*gro_list;
	struct sk_buff		*skb;
	struct list_head	dev_list;
	struct hlist_node	napi_hash_node;
	unsigned int		napi_id;
	};

#define ETH_P_IP 1
#define ETH_P_IPV6 2

#define IPPROTO_UDP 2
#define IPPROTO_TCP 3

#define ETH_HLEN 1

#define NULL ((void *)0)

#define ENOMEM 1
#define EIO 2
#define EINVAL 3
#define EADDRNOTAVAIL 4
#define ENODEV 5

#define GFP_KERNEL 1

#define THIS_MODULE NULL
struct device_driver {
        const char              *name;
        struct bus_type         *bus;

        struct module           *owner;
        const struct of_device_id       *of_match_table;
#if 0
        const char              *mod_name;      /* used for built-in modules */

        bool suppress_bind_attrs;       /* disables bind/unbind via sysfs */

        const struct acpi_device_id     *acpi_match_table;

        int (*probe) (struct device *dev);
        int (*remove) (struct device *dev);
        void (*shutdown) (struct device *dev);
        int (*suspend) (struct device *dev, pm_message_t state);
        int (*resume) (struct device *dev);
        const struct attribute_group **groups;

        const struct dev_pm_ops *pm;

        struct driver_private *p;
#endif
};

struct platform_device {
        struct device   dev;
#if 0
        const char      *name;
        int             id;
        bool            id_auto;
        u32             num_resources;
        struct resource *resource;

        const struct platform_device_id *id_entry;
        char *driver_override; /* Driver name to force a match */

        /* MFD cell pointer */
        struct mfd_cell *mfd_cell;

        /* arch specific additions */
        struct pdev_archdata    archdata;
#endif
};

struct platform_driver {
        int (*probe)(struct platform_device *);
        int (*remove)(struct platform_device *);
        void (*shutdown)(struct platform_device *);
	/* I don't use this
        int (*suspend)(struct platform_device *, pm_message_t state);
        int (*resume)(struct platform_device *);
	*/
        struct device_driver driver;
        const struct platform_device_id *id_table;
        bool prevent_deferred_probe;
};

struct ethtool_ops {
	u32	(*get_link)(struct net_device *);
	int	(*get_settings)(struct net_device *, struct ethtool_cmd *);
	int	(*set_settings)(struct net_device *, struct ethtool_cmd *);
	/*
	void	(*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int	(*get_regs_len)(struct net_device *);
	void	(*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void	(*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int	(*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32	(*get_msglevel)(struct net_device *);
	void	(*set_msglevel)(struct net_device *, u32);
	int	(*nway_reset)(struct net_device *);
	int	(*get_eeprom_len)(struct net_device *);
	int	(*get_eeprom)(struct net_device *,
			      struct ethtool_eeprom *, u8 *);
	int	(*set_eeprom)(struct net_device *,
			      struct ethtool_eeprom *, u8 *);
	int	(*get_coalesce)(struct net_device *, struct ethtool_coalesce *);
	int	(*set_coalesce)(struct net_device *, struct ethtool_coalesce *);
	void	(*get_ringparam)(struct net_device *,
				 struct ethtool_ringparam *);
	int	(*set_ringparam)(struct net_device *,
				 struct ethtool_ringparam *);
	void	(*get_pauseparam)(struct net_device *,
				  struct ethtool_pauseparam*);
	int	(*set_pauseparam)(struct net_device *,
				  struct ethtool_pauseparam*);
	void	(*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void	(*get_strings)(struct net_device *, u32 stringset, u8 *);
	int	(*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	void	(*get_ethtool_stats)(struct net_device *,
				     struct ethtool_stats *, u64 *);
	int	(*begin)(struct net_device *);
	void	(*complete)(struct net_device *);
	u32	(*get_priv_flags)(struct net_device *);
	int	(*set_priv_flags)(struct net_device *, u32);
	int	(*get_sset_count)(struct net_device *, int);
	int	(*get_rxnfc)(struct net_device *,
			     struct ethtool_rxnfc *, u32 *rule_locs);
	int	(*set_rxnfc)(struct net_device *, struct ethtool_rxnfc *);
	int	(*flash_device)(struct net_device *, struct ethtool_flash *);
	int	(*reset)(struct net_device *, u32 *);
	u32	(*get_rxfh_key_size)(struct net_device *);
	u32	(*get_rxfh_indir_size)(struct net_device *);
	int	(*get_rxfh)(struct net_device *, u32 *indir, u8 *key);
	int	(*set_rxfh)(struct net_device *, const u32 *indir,
			    const u8 *key);
	void	(*get_channels)(struct net_device *, struct ethtool_channels *);
	int	(*set_channels)(struct net_device *, struct ethtool_channels *);
	int	(*get_dump_flag)(struct net_device *, struct ethtool_dump *);
	int	(*get_dump_data)(struct net_device *,
				 struct ethtool_dump *, void *);
	int	(*set_dump)(struct net_device *, struct ethtool_dump *);
	int	(*get_ts_info)(struct net_device *, struct ethtool_ts_info *);
	int     (*get_module_info)(struct net_device *,
				   struct ethtool_modinfo *);
	int     (*get_module_eeprom)(struct net_device *,
				     struct ethtool_eeprom *, u8 *);
	int	(*get_eee)(struct net_device *, struct ethtool_eee *);
	int	(*set_eee)(struct net_device *, struct ethtool_eee *);
	int	(*get_tunable)(struct net_device *,
			       const struct ethtool_tunable *, void *);
	int	(*set_tunable)(struct net_device *,
			       const struct ethtool_tunable *, const void *);
*/
};

struct netdev_queue{};

struct net_device_ops {
	int			(*ndo_init)(struct net_device *dev);
	void			(*ndo_uninit)(struct net_device *dev);
	int			(*ndo_open)(struct net_device *dev);
	int			(*ndo_stop)(struct net_device *dev);
	netdev_tx_t		(*ndo_start_xmit) (struct sk_buff *skb,
						   struct net_device *dev);
	/*
	u16			(*ndo_select_queue)(struct net_device *dev,
						    struct sk_buff *skb,
						    void *accel_priv,
						    select_queue_fallback_t fallback);
	*/
	void			(*ndo_change_rx_flags)(struct net_device *dev,
						       int flags);
	void			(*ndo_set_rx_mode)(struct net_device *dev);
	int			(*ndo_set_mac_address)(struct net_device *dev,
						       void *addr);
	int			(*ndo_validate_addr)(struct net_device *dev);
	int			(*ndo_do_ioctl)(struct net_device *dev,
					        struct ifreq *ifr, int cmd);
	/*
	int			(*ndo_set_config)(struct net_device *dev,
					          struct ifmap *map);
	int			(*ndo_change_mtu)(struct net_device *dev,
						  int new_mtu);
	int			(*ndo_neigh_setup)(struct net_device *dev,
						   struct neigh_parms *);
	*/
	void			(*ndo_tx_timeout) (struct net_device *dev);

/*
	struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
						     struct rtnl_link_stats64 *storage);
	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	int			(*ndo_vlan_rx_add_vid)(struct net_device *dev,
						       __be16 proto, u16 vid);
	int			(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
						        __be16 proto, u16 vid);
	*/
	void                    (*ndo_poll_controller)(struct net_device *dev);
	/*
	int			(*ndo_netpoll_setup)(struct net_device *dev,
						     struct netpoll_info *info);
	*/
	void			(*ndo_netpoll_cleanup)(struct net_device *dev);
#ifdef CONFIG_NET_RX_BUSY_POLL
	int			(*ndo_busy_poll)(struct napi_struct *dev);
#endif
	/*
	int			(*ndo_set_vf_mac)(struct net_device *dev,
						  int queue, u8 *mac);
	int			(*ndo_set_vf_vlan)(struct net_device *dev,
						   int queue, u16 vlan, u8 qos);
	int			(*ndo_set_vf_rate)(struct net_device *dev,
						   int vf, int min_tx_rate,
						   int max_tx_rate);
	int			(*ndo_set_vf_spoofchk)(struct net_device *dev,
						       int vf, bool setting);
	int			(*ndo_get_vf_config)(struct net_device *dev,
						     int vf,
						     struct ifla_vf_info *ivf);
	int			(*ndo_set_vf_link_state)(struct net_device *dev,
							 int vf, int link_state);
	int			(*ndo_set_vf_port)(struct net_device *dev,
						   int vf,
						   struct nlattr *port[]);
	int			(*ndo_get_vf_port)(struct net_device *dev,
						   int vf, struct sk_buff *skb);
	int			(*ndo_setup_tc)(struct net_device *dev, u8 tc);
#if IS_ENABLED(CONFIG_FCOE)
	int			(*ndo_fcoe_enable)(struct net_device *dev);
	int			(*ndo_fcoe_disable)(struct net_device *dev);
	int			(*ndo_fcoe_ddp_setup)(struct net_device *dev,
						      u16 xid,
						      struct scatterlist *sgl,
						      unsigned int sgc);
	int			(*ndo_fcoe_ddp_done)(struct net_device *dev,
						     u16 xid);
	int			(*ndo_fcoe_ddp_target)(struct net_device *dev,
						       u16 xid,
						       struct scatterlist *sgl,
						       unsigned int sgc);
	int			(*ndo_fcoe_get_hbainfo)(struct net_device *dev,
							struct netdev_fcoe_hbainfo *hbainfo);
#endif

#if IS_ENABLED(CONFIG_LIBFCOE)
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
	int			(*ndo_fcoe_get_wwn)(struct net_device *dev,
						    u64 *wwn, int type);
#endif

#ifdef CONFIG_RFS_ACCEL
	int			(*ndo_rx_flow_steer)(struct net_device *dev,
						     const struct sk_buff *skb,
						     u16 rxq_index,
						     u32 flow_id);
#endif
	int			(*ndo_add_slave)(struct net_device *dev,
						 struct net_device *slave_dev);
	int			(*ndo_del_slave)(struct net_device *dev,
						 struct net_device *slave_dev);
	netdev_features_t	(*ndo_fix_features)(struct net_device *dev,
						    netdev_features_t features);
	int			(*ndo_set_features)(struct net_device *dev,
						    netdev_features_t features);
	int			(*ndo_neigh_construct)(struct neighbour *n);
	void			(*ndo_neigh_destroy)(struct neighbour *n);

	int			(*ndo_fdb_add)(struct ndmsg *ndm,
					       struct nlattr *tb[],
					       struct net_device *dev,
					       const unsigned char *addr,
					       u16 flags);
	int			(*ndo_fdb_del)(struct ndmsg *ndm,
					       struct nlattr *tb[],
					       struct net_device *dev,
					       const unsigned char *addr);
	int			(*ndo_fdb_dump)(struct sk_buff *skb,
						struct netlink_callback *cb,
						struct net_device *dev,
						struct net_device *filter_dev,
						int idx);

	int			(*ndo_bridge_setlink)(struct net_device *dev,
						      struct nlmsghdr *nlh);
	int			(*ndo_bridge_getlink)(struct sk_buff *skb,
						      u32 pid, u32 seq,
						      struct net_device *dev,
						      u32 filter_mask);
	int			(*ndo_bridge_dellink)(struct net_device *dev,
						      struct nlmsghdr *nlh);
	int			(*ndo_change_carrier)(struct net_device *dev,
						      bool new_carrier);
	int			(*ndo_get_phys_port_id)(struct net_device *dev,
							struct netdev_phys_port_id *ppid);
	void			(*ndo_add_vxlan_port)(struct  net_device *dev,
						      sa_family_t sa_family,
						      __be16 port);
	void			(*ndo_del_vxlan_port)(struct  net_device *dev,
						      sa_family_t sa_family,
						      __be16 port);

	void*			(*ndo_dfwd_add_station)(struct net_device *pdev,
							struct net_device *dev);
	void			(*ndo_dfwd_del_station)(struct net_device *pdev,
							void *priv);

	netdev_tx_t		(*ndo_dfwd_start_xmit) (struct sk_buff *skb,
							struct net_device *dev,
							void *priv);
	int			(*ndo_get_lock_subclass)(struct net_device *dev);
	bool			(*ndo_gso_check) (struct sk_buff *skb,
						  struct net_device *dev);
	*/
};

#define MODULE_DEVICE_TABLE(a, b)
#define module_platform_driver(str) 

#define likely(str) (str)
#define unlikely(str) (str)

void wmb(void){}
void rmb(void){}

struct sockaddr {
	//sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};

struct phy_device {};

//functions
int dev_emerg(const struct device *dev, const char *fmt, ...)
{ return 0; }
int dev_crit(const struct device *dev, const char *fmt, ...)
{ return 0; }
int dev_alert(const struct device *dev, const char *fmt, ...)
{ return 0; }
int dev_err(const struct device *dev, const char *fmt, ...)
{ return 0; }
int dev_warn(const struct device *dev, const char *fmt, ...)
{ return 0; }
int dev_dbg(const struct device *dev, const char *fmt, ...)
{ return 0; }

int netdev_emerg(const struct net_device *dev, const char *fmt, ...)
{ return 0; }
int netdev_crit(const struct net_device *dev, const char *fmt, ...)
{ return 0; }
int netdev_alert(const struct net_device *dev, const char *fmt, ...)
{ return 0; }
int netdev_err(const struct net_device *dev, const char *fmt, ...)
{ return 0; }
int netdev_warn(const struct net_device *dev, const char *fmt, ...)
{ return 0; }
int netdev_notice(const struct net_device *dev, const char *fmt, ...)
{ return 0; }
int netdev_dbg(const struct net_device *dev, const char *fmt, ...)
{ return 0; }

#define setup_timer(timer, fn, data)
#define INIT_WORK(_work, _func)
#define DEFINE_SPINLOCK(lock) int lock

struct dev_pm_ops {
	int (*prepare)(struct device *dev);
	void (*complete)(struct device *dev);
	int (*suspend)(struct device *dev);
	int (*resume)(struct device *dev);
	int (*freeze)(struct device *dev);
	int (*thaw)(struct device *dev);
	int (*poweroff)(struct device *dev);
	int (*restore)(struct device *dev);
	int (*suspend_late)(struct device *dev);
	int (*resume_early)(struct device *dev);
	int (*freeze_late)(struct device *dev);
	int (*thaw_early)(struct device *dev);
	int (*poweroff_late)(struct device *dev);
	int (*restore_early)(struct device *dev);
	int (*suspend_noirq)(struct device *dev);
	int (*resume_noirq)(struct device *dev);
	int (*freeze_noirq)(struct device *dev);
	int (*thaw_noirq)(struct device *dev);
	int (*poweroff_noirq)(struct device *dev);
	int (*restore_noirq)(struct device *dev);
	int (*runtime_suspend)(struct device *dev);
	int (*runtime_resume)(struct device *dev);
	int (*runtime_idle)(struct device *dev);
};

struct attribute {              
	const char *name;
	int	mode;
};

struct device_attribute {
	struct attribute	attr;
	ssize_t (*show)(struct device *dev, struct device_attribute *attr,
			char *buf);
	ssize_t (*store)(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count);
};

#define __ATTR(_name, _mode, _show, _store) {                           \
	.attr = {.name = #_name,                            \
	.mode = (_mode) },             \
	.show   = _show,                                                \
	.store  = _store,                                               \
}
#define DEVICE_ATTR(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)

struct attribute_group {
	const char              *name;
	struct attribute        **attrs;
};

typedef struct pm_message {
	        int event;
} pm_message_t;

struct class {
	const char		*name;
//	struct module		*owner;

	struct class_attribute		*class_attrs;
	const struct attribute_group	**dev_groups;
//	struct kobject			*dev_kobj;

//	int (*dev_uevent)(struct device *dev, struct kobj_uevent_env *env);
//	char *(*devnode)(struct device *dev, umode_t *mode);

	void (*class_release)(struct class *class);
	void (*dev_release)(struct device *dev);

//	int (*suspend)(struct device *dev, pm_message_t state);
	int (*resume)(struct device *dev);

	const struct kobj_ns_type_operations *ns_type;
	const void *(*namespace)(struct device *dev);

	const struct dev_pm_ops *pm;

	struct subsys_private *p;
};

#define __init
#define __exit
#define subsys_initcall(str)
#define module_exit(str)

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#endif
