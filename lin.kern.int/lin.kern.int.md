# Linux Network Internals

# Part 1: general background

## Chapter 1: introduction

### Basic terminology

* _Byte_ over _octet_
* _ingress_ or input, __Rx__
* _egress_ or output, __Tx__

### Common coding patterns

Some requirements are common to several kernel components:
* allocate several instances of the same data structure type
* need to keep track of references to an instance of a data
  structure to avoid unsafe memory deallocations

#### Memory caches

* `kmalloc()` or `kfree()`
* use alloc/dealloc routine with dedicated cache

1. _Socket buffer descriptors_: cache allocated by `skb_init()` in `net/core/sk_buff.c` and used for the allocation of `sk_buff` buffer descriptors.
2. _neighbouring protocol mappings_
3. _routing tables_: two memory caches

some kernel functions:
* `kmem_cache_create`
* `kmem_cache_destroy`
* `kmem_cache_alloc`
* `kmem_cache_free`

#### Caching and hash tables

common caches for l3-to-l2 mapping. often implemented with hash tables.

#### Reference counts

pseudo-gc and calling functions (`xxx_hold` or `xxx_release/put`)

#### Garbage collection

* __asynchronous:__ timer trigger routine to inspect a set of data structures (eligible for deletion)
* __synchronous:__ do not wait for timer

#### Functions pointers and virtual function tables (VFTs)

interfaces between kernel components or generic mechanisms to invoke the right function handler.

* _virtual function table_ (VTF): set of function pointers grouped into a DS. Can be used as an interface between two major subsystems (L3 and L4)

#### goto statements

#### Vector definitions

```c
struct abc {
  int age;
  char *name[20]
  ...
  char placeholder[0];
}
```

Here, `placeholder` either points to the end of the structure or reuse the same definition in different structures by extending it and modifying it slightly.

#### Conditional directive (#ifdef and family)

Mostly used to check if a given feature is supported by the kernel.

#### Compile-time optimization for condtion checks

`likely` and `unlikely` macros.

#### Mutual Exclusion

* Spin locks
* Read-write locks
* Read-copy-update (RCU)

#### Conversions between host and network order

Endianness... 

* `htons`: host-to-network order (short)
* `htonl`: host-to-network order (long)
* `ntohs`: network-to-host (short)
* `ntohl`: network-to-host (long)

#### Catching bugs (?)

* `BUG_ON`
* `BUG_TRAP`

#### Measuring time

__tick:__ time between two consecutives expirations of the timer interrupt, which expires in HZ times per second. For example, if `HZ` = 1,000, then the timer interrupt expires 1,000 times per second (or 1 ms between two consecutive expirations).

Every time the timer expires, `jiffies++`. This variable represents the number of ticks since the system booted and thus can be used to measure the passing of time.

## Chapter 2: critical data structure

* `struct sk_buff`: where a packet is stored. Used by all layers to store their headers, payload and other stuff.
* `struct net_device`: represents the network device (HW and SW configuration).
* `struct sock`: not covered here...

### The socket buffer

"*it consists of a tremendous heap of variables that try to be all things to all people*"

Fields classification:
- layout
- general
- feature-specific
- management functions

Each layer appends its header on the struct via the `skb_reserve` function to reserve space for its header. When the buffer is passed up the layers, the useless headers are not removed but the pointer to payload moved (less CPU cycle)

#### Networking options and kernel structures

`sk_buff` is peppered with C preprocessor directives to accomodate many options.

#### Layout fields

Exist to facilitate searching and to organize the DS itself. Pseudo doubly-linked list of all `sk_buff` struct.

```c
struct sk_buff_head {
  struct sk_buff *next;
  struct sk_buff *prev;
  __32 qlen;
  spinlock_t lock;
}
```

where `qlen` represents the number of elements in the list; `lock` is to prevent simultaneous accesses. Every `sk_buff` structure contains a poitner to the single `sk_buff_head`: `list`

![sk_buff_head](lin.kern.int/img/sk_buff_head.png)

* `struct sock *sk`: pointer to the buffer that owns this buffer.
* `unsigned int len`: size of block of data in buffer (includes data in the main buffer and in the fragments). Its value will change as the buffer moves between the layers.
* `unsigned int data_len`: size of data in fragments
* `unsigned int mac_len`: size of MAC header
* `atomic_t users`: reference count.
* `unsigned int truesize`: total size of the buffer, include the `sk_buff` itself. Set by `allock_skb` to *len + sizeof(sk_buff)*
  
Represent boundaries of buffer and data within it:
* `unsigned char *head`: start buffer
* `unsigned char *end`: end buffer
* `unsigned char *data`: start data
* `unsigned char *tail`: end data
Manipulated when a layer prepares its activities. Layers can fill the gap between `head` and `data` with a protocol header, or the gap between `tail` and `end` with new data.

![sk_buff_b](lin.kern.int/img/sk_buff_boundaries.png)

* `void (*destructor)(...)`: function pointer can be initialized to a routine that performs some activity when the buffer is removed. When the buffer belongs to a socket, it is usually set to `sock_rfree` or `sock_wfree` (by `skb_set_owner_r` and `skb_set_owner_w`).

#### General fieds

* `struct timeval stamp`: timestamp for when a packet was received. Set by the function `netif_rx` with `net_timestamp`, which is called by the device driver after the reception.
* `struct net_device *dev`: the network device.
* `struct net_device *input_dev`: device the sent the packet
* `struct net_device *real_dev`: virtual devices only
* ![sk_buff_layer](lin.kern.int/img/sk_buff_layer.png)
* `struct dst_entry dst`: used by routing subsystem...
* `char cb[40]`: control buffer used to store layer-specific control information. 
* `unsigned int csum` and `unsigned char ip_summed`: checksum and associated status flag.
* `unsigned char cloned`: boolean flag to indicate whether this structure is a clone
* `unsigned char pkt_type`: classify the type of frame...
* `__u32 priority`: QoS class of a packet.
* `unsgined short protocol`: protocol used at the next-higher layer (typically IP, IPv6 or ARP). Used to select which handler to use.
* `unsigned short security`: security level of the packet - no longer used...

#### Feature-specific fields

Fields compiled only if some features are enabled

#### Management functions

Functions to manipulate `sk_buff` elements or list of elements.
These can exists in two version `do_something` and `__do_something`, the first one being a wrapper to the second that adds either sanity checks or locking mechanisms.

__Allocating memory: `alloc_skb` and `dev_alloc_skb`__

Creating a single buffer = 2 allocations (buffer and head structure)

```c
struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask,
			    int flags, int node)
{
	struct kmem_cache *cache;
	struct sk_buff *skb;
	u8 *data;
	bool pfmemalloc;

	cache = (flags & SKB_ALLOC_FCLONE)
		? skbuff_fclone_cache : skbuff_head_cache;

	if (sk_memalloc_socks() && (flags & SKB_ALLOC_RX))
		gfp_mask |= __GFP_MEMALLOC;

	/* Get the HEAD */
	if ((flags & (SKB_ALLOC_FCLONE | SKB_ALLOC_NAPI)) == SKB_ALLOC_NAPI &&
	    likely(node == NUMA_NO_NODE || node == numa_mem_id()))
		skb = napi_skb_cache_get();
	else
		skb = kmem_cache_alloc_node(cache, gfp_mask & ~GFP_DMA, node);
	if (unlikely(!skb))
		return NULL;
	prefetchw(skb);

	/* We do our best to align skb_shared_info on a separate cache
	 * line. It usually works because kmalloc(X > SMP_CACHE_BYTES) gives
	 * aligned memory blocks, unless SLUB/SLAB debug is enabled.
	 * Both skb->head and skb_shared_info are cache line aligned.
	 */
	size = SKB_DATA_ALIGN(size);
	size += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	data = kmalloc_reserve(size, gfp_mask, node, &pfmemalloc);
	if (unlikely(!data))
		goto nodata;
	/* kmalloc(size) might give us more room than requested.
	 * Put skb_shared_info exactly at the end of allocated zone,
	 * to allow max possible filling before reallocation.
	 */
	size = SKB_WITH_OVERHEAD(ksize(data));
	prefetchw(data + size);

	/*
	 * Only clear those fields we need to clear, not those that we will
	 * actually initialise below. Hence, don't put any more fields after
	 * the tail pointer in struct sk_buff!
	 */
	memset(skb, 0, offsetof(struct sk_buff, tail));
	__build_skb_around(skb, data, 0);
	skb->pfmemalloc = pfmemalloc;

	if (flags & SKB_ALLOC_FCLONE) {
		struct sk_buff_fclones *fclones;

		fclones = container_of(skb, struct sk_buff_fclones, skb1);

		skb->fclone = SKB_FCLONE_ORIG;
		refcount_set(&fclones->fclone_ref, 1);

		fclones->skb2.fclone = SKB_FCLONE_CLONE;
	}

	return skb;

nodata:
	kmem_cache_free(cache, skb);
	return NULL;
}
EXPORT_SYMBOL(__alloc_skb);
```
![sk_buff_alloc](lin.kern.int/img/sk_buff_alloc.png)

`(net)dev_alloc_skb` is the buffer allocation function meant for use by device drivers and expected to be executed in interrupt mode. It is simply a wrapper around `alloc_skb` that adds 16 bytes to the requested size for optimization reasons and asks for an atomic operation (`GFP_ATOMIC`) since it will be called from within an interrupt handler routine.

__Freeing memory: `kfree_skb` and `dev_kfree_skb`__

Returns a buffer to the pool. 

![sk_buff_free](lin.kern.int/img/sk_buff_free.png)

__Data reservation and aligment: `skb_reserve`, `skb_put`, `skb_push`, and `skb_pull`__

![sk_buff_manag](lin.kern.int/img/sk_buff_manag.png)

* (a) `skb_put`, (b) `skb_push`, (c) `skb_pull`, (d) `skb_reserve`

![skb_buff_reserve1](lin.kern.int/img/skb_buff_reserve1.png)

![skb_buff_reserve2](lin.kern.int/img/skb_buff_reserve2.png)

1. When TCP is asked to transmit some data, it allocates a buffer following certain criteria (TCP Maximum Segment Size (mss), support for scatter gather I/O, etc.).
2. TCP reserves (with `skb_reserve`) enough space at the head of the buffer to hold all the headers of all layers (TCP, IP, link layer). The parameter MAX_TCP_HEADER is the sum of all headers of all levels and is calculated taking into account the worst-case scenarios: because the TCP layer does not know what type of interface will be used for the transmission, it reserves the biggest possible header foreach layer. It even accounts for the possibility of multiple IP headers (because you can have multiple IP headers when the kernel is compiled with support for IP over IP
3. The TCP payload is copied into the buffer. The TCP payload could be organized differently; for example, it could be stored as fragments. 
4. The TCP layer adds its header
5. The TCP layer hands the buffer to the IP layer, which adds its header as well.
6. The IP layer hands the IP packet to the neighboring layer, which adds the link layer header.

__The `skb_shared_info` structure and the `skb_shinfo` function__

To keep additional information about the data block:

```c
struct skb_shared_info {
  atomic_t dataref; // #users
  unsigned int nr_frags; //#for IP
  unsigned short tso_size; // NIC card compute checksum
  unsigned short tso_seqs;
  struct sk_buff *frag_list; //#for IP
  skb_frag_t frags[MAX_SKB_FRAGS]; //#for IP
};
```

```c
#define skb_shinfo(SKB)((struct skb_shared_info *)((SKB)->end))
```

__Cloning and copying buffers__

When the same buffer needs to be processed independently by different consumers, and they may need to change the content of the `sk_buff` descriptor (the `h` and `nh` pointers to the protocol headers), the kernel does not need to make a complete copyof both the `sk_buff` structure and the associated data buffers. Instead, to be more efficient, the kernel can clone the original, which consists of making a copy of the `sk_buff` structure only and playing with the reference counts to avoid releasing the shared data block prematurely. Buffer cloning is done with the `skb_clone` function.

The `sk_buff` clone is not linked to any list and has no reference to the socket owner.The field `skb->cloned` is set to 1 in both the clone and the original buffer. `skb->users` is set to 1 in the clone so that the first attempt to remove it succeeds, and the number of references (`dataref`) to the buffer containing the data is incremented (since now there is one more `sk_buff` data structure pointing to it).

![sk_buff_clone](lin.kern.int/img/sk_buff_clone.png)

When a buffer is cloned, the contents of the data block cannot be modified. This means that code can access the data without any need for locking. When, however, a function needs to modify not only the contents of the `sk_buff` structure but the data too, it needs to clone the data block as well. In this case, the programmer has two options. When he knows he needs to modify only the contents of the data in the area between `skb->start` and `skb->end`, he can use `pskb_copy` to clone just that area. When
he thinks he may need to modify the content of the fragment data blocks too, he must use `skb_copy`.

![sk_buff_clone2](lin.kern.int/img/sk_buff_clone2.png)

#### List management functions

List of `sk_buff` elements = queue

* `skb_queue_head_init`: init an `sk_buff_head` with an empty queue of elements 
* `skb_queue_head`, `sbk_queue_tail`: adds one buffer to the head or tail of a queue
* `skb_dequeue`, `skb_dequeue_tail`:  dequeues head or tail
* `skb_queue_purge`: empties queue
* `skb_queue_walk`: runs a loop

these functions must be executed atomically - thus are wrappers to a `__xxx` function with spinlock acquisition

### `net_device` structure


