/*
 * Lightweight Autonomic Network Architecture
 *
 * crr_tx test module.
 *
 * Copyright 2011 Florian Deragisch <floriade@ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

/* TODO:
 *
 * Don't use seq nr, which is still not ACK'ed ( 1 - 2 ACK 3 ACK 4 ACK 1 X )!
 * We need 2*WIN_SZ timers (1 - 2 ACK 3 ACK <- X) would stop timer 1!
 * Check if receiving is an open packet
 * Fix Timeout retransmission! NOT WORKING!
 * Reset von Seq Nr für neue Transfers?
 */

/* Important!
 *
 * Packets coming from userspace, that are using the PF_LANA socket, are raw
 * packets. The data pointer points to the ETH_HDR, unlike packtes that have
 * passed the kernel already. For those packets data points after ETH_TYPE
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/percpu.h>
#include <linux/prefetch.h>
#include <linux/if_ether.h>
#include <linux/timer.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

#define ETH_HDR_LEN	14
#define WIN_SZ		2
#define MAX_OPEN_PKTS	2
#define MAX_QUEUE_LEN	500
#define MAX_RTT		2*HZ

struct fb_crr_tx_priv {
	idp_t port[2];
	seqlock_t lock;
	rwlock_t tx_lock;
	unsigned char *tx_open_pkts;
	unsigned char *tx_seq_nr;
	struct sk_buff_head *tx_stack_list;
	struct sk_buff_head *tx_queue_list;
	struct timer_list *timer1;
	struct timer_list *timer2;
};

struct mytimer {
	unsigned char *open_pkts;
	struct timer_list mytimer;
	struct sk_buff_head *stack_list;
	rwlock_t *tx_lock;
};

struct mytimer my_timer[WIN_SZ];

static struct sk_buff *skb_get_nr(unsigned char n, struct sk_buff_head *list)
{

	struct sk_buff *curr = list->next;

	while (1) {
		if ((*(curr->data + ETH_HDR_LEN) >> 4) == n)
			return curr;
		else {
			if ((curr = curr->next) == (struct sk_buff *)list)
				return 0;
		}
	}
}

/* returns a pointer to the skb_buff with the according seq number */
/*static struct sk_buff *skb_get_pos(unsigned char seq, struct sk_buff_head *list)
{
	struct sk_buff *curr = list->next;

	if (seq < 0 || seq > (2 * WIN_SZ))
		return 0;

	if (list->next == (struct sk_buff *)list) {				// list is empty 
		printk(KERN_ERR "List is empty\n");		
		return list->next;
	}
	
	else if (seq == 2) {							// Second element 
		printk(KERN_ERR "Seqnr 2 -> First element\n");
		return list->next;
	}	
		
	while(1) {								// Others 
		if ((*(curr->data + ETH_HDR_LEN) >> 4) > seq)
			break;
		else if ((*(curr->data + ETH_HDR_LEN) >> 4) == seq) {		// identical copy 
			printk(KERN_ERR "Identical copy exists\n");
			return 0;
		}
	
		if (curr->next == (struct sk_buff *)list) {
			printk(KERN_ERR "Reached end of the list\n");
			return (struct sk_buff *)list;
		}
		curr = curr->next;
	}
	return curr;
}*/


/* Timeout:
 * 1.) Get oldest packet from stack.
 *	-> Fails: decrement pkt counter
 * 2.) Clone it
 *	-> Fails: decrement pkt counter
 * 3.) Schedule the packet
 * 4.) Restart the timer
 */

static void fb_crr_tx_timeout(unsigned long args)
{
	struct sk_buff *curr, *cloned_skb;
	struct mytimer *timer = (struct mytimer *)args;

	printk(KERN_ERR "[TO]\tTimeout!\n");

	write_lock_bh(timer->tx_lock);						// LOCK
	//printk(KERN_ERR "Timer LOCKED!\n");			
	if (*timer->open_pkts == 0) {
		printk(KERN_ERR "[TO]\tNo open packets\n");
		//mod_timer(&timer->mytimer, jiffies + 10*HZ);			// restart timer 
		write_unlock_bh(timer->tx_lock);				// UNLOCK
		//printk(KERN_ERR "Timer UNLOCKED!\n");
		return;
	}	

	curr = skb_dequeue(timer->stack_list);

	if (curr == NULL) {							// W send pkt again. first in list is oldest
		printk(KERN_ERR "[TO]\tError: Stack is empty!\n"); 			// BUG should never happen!
		timer->open_pkts -=1;						// W 
		write_unlock_bh(timer->tx_lock);				// UNLOCKa
		//printk(KERN_ERR "Timer UNLOCKED!\n");
		return;
	}

	printk(KERN_ERR "[TO]\tOpen packet!\n"); 	

	if ((cloned_skb = skb_copy(curr, GFP_ATOMIC))) {
		skb_queue_tail(timer->stack_list, curr);
		engine_backlog_tail(cloned_skb, TYPE_EGRESS);			// idp should be correct. schedule for egress path 
		printk(KERN_ERR "[TO]\t\tResent packet!\n");	
	}
	else {
		skb_queue_tail(timer->stack_list, curr);	
		printk(KERN_ERR "[TO]\t\tError: Couldn't copy!\n");
		timer->open_pkts -=1;
	}

	mod_timer(&timer->mytimer, jiffies + 10*HZ);				// restart timer 
	write_unlock_bh(timer->tx_lock);					// UNLOCKb
	//printk(KERN_ERR "Timer UNLOCKED!\n");
}

static int fb_crr_tx_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int drop = 0;
	unsigned int queue_len;
	unsigned char custom, seq, ack, currseq;
	struct sk_buff *cloned_skb, *curr;
	struct fb_crr_tx_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->lock);
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->port[*dir]);
		if (fb_priv_cpu->port[*dir] == IDP_UNKNOWN)
			drop = 1;
	} while (read_seqretry(&fb_priv_cpu->lock, seq));

	if (*dir == TYPE_EGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {	// Send 

		custom = *(skb->data + ETH_HDR_LEN);
		seq = custom >> 4;
		ack = custom & 0xF;

		printk(KERN_ERR "[TX]\tSend packet\n");
		write_lock_bh(&fb_priv_cpu->tx_lock);				// LOCK
		//printk(KERN_ERR "Send UNLOCKED!\n");
		currseq = *fb_priv_cpu->tx_seq_nr; 				// R tag packet with seq nr 
		*fb_priv_cpu->tx_seq_nr = (*fb_priv_cpu->tx_seq_nr % (2*WIN_SZ)) + 1; // W Increment seq nr for next packet 
		*(skb->data + ETH_HDR_LEN) = currseq << 4;		
		queue_len = skb_queue_len(fb_priv_cpu->tx_queue_list);		// R 
		printk(KERN_ERR "[TX]\tCurrseq: %d\tOpen_pkts: %d\tQlen: %d\n",
			 currseq, *fb_priv_cpu->tx_open_pkts, queue_len);

		//write_unlock_bh(&fb_priv_cpu->tx_lock);			JUST FOR TESTING !!!! LOCK

		if (*fb_priv_cpu->tx_open_pkts == MAX_OPEN_PKTS) {		// R Queue packet
			//printk(KERN_ERR "Open packets: %d\n", *fb_priv_cpu->tx_open_pkts);
			if (queue_len < MAX_QUEUE_LEN) {
				printk(KERN_ERR "[TX]\tAdd to queue\n");
				skb_queue_tail(fb_priv_cpu->tx_queue_list, skb);// W 
				write_unlock_bh(&fb_priv_cpu->tx_lock);		// UNLOCKa
				//printk(KERN_ERR "Send UNLOCKED!\n");
				drop = 2;
			}
			else {
				write_unlock_bh(&fb_priv_cpu->tx_lock);		// UNLOCKb
				//printk(KERN_ERR "Send UNLOCKED!\n");
				printk(KERN_ERR "[TX]\tQueue is full!\n");
				drop = 1;	
			}
		}
		else {
			//printk(KERN_ERR "Packet slots available\n");		// Send packet and write to stack 
			if (queue_len) {					// Check if packets in queue need to be send first 
				printk(KERN_ERR "[TX]\tSend other packet from queue\n");
				skb_queue_tail(fb_priv_cpu->tx_queue_list, skb);// W Queue at end of queue_list 
				curr = skb_dequeue(fb_priv_cpu->tx_queue_list);	// W Dequeue first element of queue_list 

				if ((cloned_skb = skb_copy(curr, GFP_ATOMIC))) { 
					skb_queue_tail(fb_priv_cpu->tx_stack_list, curr);// W Queue at end of stack_list 	
					engine_backlog_tail(cloned_skb, TYPE_EGRESS);	// idp and seq_nr should be correct. schedule for egress path 
					(*fb_priv_cpu->tx_open_pkts)++;	
					printk(KERN_ERR "[TX]\t\tSent\n");			
				}
				else {
					skb_queue_tail(fb_priv_cpu->tx_stack_list, curr);// W Queue at end of stack_list 
					printk(KERN_ERR "[TX]\tError: Couldn't copy!\n");	
				}		
				drop = 2;					// don't send and don't free, because in list
			}
			else {							// send packet and push on stack 
				printk(KERN_ERR "[TX]\tPush packet on stack and send\n");

				if ((cloned_skb = skb_copy(skb, GFP_ATOMIC))) { 	
					skb_queue_tail(fb_priv_cpu->tx_stack_list, cloned_skb);// W 
					(*fb_priv_cpu->tx_open_pkts)++;				// W 
					printk(KERN_ERR "[TX]\t\tSent\n");			
				}
				else {
					drop = 1;
					write_unlock_bh(&fb_priv_cpu->tx_lock);	// UNLOCKc
					printk(KERN_ERR "[TX]\t\tError: Couldn't copy!\n");
					goto out;
				}
			}

			/*if (!(currseq % 2))
				mod_timer(&my_timer[1].mytimer, jiffies + 10*HZ);// W REMOVE
			else
				mod_timer(&my_timer[0].mytimer, jiffies + 10*HZ);// W*/

			mod_timer(&my_timer[(currseq+1)%WIN_SZ].mytimer, jiffies + 10*HZ); 
			//printk(KERN_ERR "Reset timer\n");

			write_unlock_bh(&fb_priv_cpu->tx_lock);			// UNLOCKc
			//printk(KERN_ERR "Send UNLOCKED!\n");
		}
	}
	/* Receive */
	else if (*dir == TYPE_INGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) { // possible ACK 

		custom = *skb->data;
		seq = custom >> 4;
		ack = custom & 0xF;
		
		
		if (ack != 0xF || seq == 0 || seq > 2*WIN_SZ)			// invalid packets
			goto out;

		printk(KERN_ERR "[RX]\tACK received\n");
		write_lock_bh(&fb_priv_cpu->tx_lock);				// LOCK
		//printk(KERN_ERR "Receive LOCKED!\n");
	
		/* for (i = 0; i < 14; i++)
			printk(KERN_ERR "Data %d 0x%2x\n", i, *(skb->data + i)); */

		/*if ((seq % 2) == 0)				
			del_timer(fb_priv_cpu->timer2);				// W Stop Timer 2 
		else							
			del_timer(fb_priv_cpu->timer1);*/			// W Stop Timer 1 
		
		del_timer(&my_timer[(seq+1)%WIN_SZ].mytimer);

		(*fb_priv_cpu->tx_open_pkts)--;					// W 

		printk(KERN_ERR "[RX]\tStop Timer %d\tOpenpkts: %d\n", seq,
					*fb_priv_cpu->tx_open_pkts);

		if ((curr = skb_get_nr(seq, fb_priv_cpu->tx_stack_list))) {	// R get according element 
			skb_unlink(curr, fb_priv_cpu->tx_stack_list);		// W dequeue from list 
			kfree(curr);
		}
		//printk(KERN_ERR "Deleted from stack\n");			// delete pkt from stack 
		drop = 1;							// drop pkt before user space 

		queue_len = skb_queue_len(fb_priv_cpu->tx_queue_list);		// R 
		printk(KERN_ERR "[RX]\tQlen: %d\n", queue_len);

		if (queue_len) {						// && *fb_priv_cpu->tx_open_pkts <= MAX_OPEN_PKTS) {  R 
			curr = skb_dequeue(fb_priv_cpu->tx_queue_list);		// W Dequeue first element of queue_list 

			if ((cloned_skb = skb_copy(curr, GFP_ATOMIC)))  {
				skb_queue_tail(fb_priv_cpu->tx_stack_list, curr);// W Queue at end of stack_list 			
				printk(KERN_ERR "[RX]\t\tSent\n");
				engine_backlog_tail(cloned_skb, TYPE_EGRESS);	// idp and seq_nr should be correct. schedule for egress path
				(*fb_priv_cpu->tx_open_pkts)++;			// W  
			}
			else {
				skb_queue_tail(fb_priv_cpu->tx_stack_list, curr);// W Queue at end of stack_list 
				printk(KERN_ERR "[RX]\t\tError: Couldn't copy!\n");
			}

				

			/*if (!(seq % 2))						// Start timers 
				mod_timer(&my_timer[1].mytimer, jiffies +10*HZ); // W 
			else
				mod_timer(&my_timer[0].mytimer, jiffies + 10*HZ);*/ // W 
			mod_timer(&my_timer[(seq+1)%WIN_SZ].mytimer, jiffies + 10*HZ); 
			//printk(KERN_ERR "Started timer\n");
		}
		write_unlock_bh(&fb_priv_cpu->tx_lock);				// UNLOCK
		//printk(KERN_ERR "Receive UNLOCKED!\n");
	}
out:
	if (drop == 1) {
		kfree_skb(skb);
		//printk(KERN_ERR "Freed and dropped!\n");
		return PPE_DROPPED;
	}
	else if (drop == 2) {
		printk(KERN_ERR "Dropped!\n");
		return PPE_DROPPED;
	}
	printk(KERN_ERR "Passed on!\n");
	return PPE_SUCCESS;
}

static int fb_crr_tx_event(struct notifier_block *self, unsigned long cmd,
			  void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_crr_tx_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_crr_tx_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

#ifdef __DEBUG
	printk("Got event %lu on %p!\n", cmd, fb);
#endif

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_crr_tx_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == IDP_UNKNOWN) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = msg->idp;
				write_sequnlock(&fb_priv_cpu->lock);
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (bound)
			printk(KERN_INFO "[%s::%s] port %s bound to IDP%u\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir], msg->idp);
		} break;
	case FBLOCK_UNBIND_IDP: {
		int unbound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_crr_tx_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			if (fb_priv_cpu->port[msg->dir] == msg->idp) {
				write_seqlock(&fb_priv_cpu->lock);
				fb_priv_cpu->port[msg->dir] = IDP_UNKNOWN;
				write_sequnlock(&fb_priv_cpu->lock);
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
		}
		put_online_cpus();
		if (unbound)
			printk(KERN_INFO "[%s::%s] port %s unbound\n",
			       fb->name, fb->factory->type,
			       path_names[msg->dir]);
		} break;
	case FBLOCK_SET_OPT: {
		struct fblock_opt_msg *msg = args;
		printk("Set option %s to %s!\n", msg->key, msg->val);
		} break;
	default:
		break;
	}

	return ret;
}

static struct fblock *fb_crr_tx_ctor(char *name)
{
	int ret = 0;
	unsigned char *tmp_open_pkts, *tmp_seq_nr;
	unsigned int i, cpu;
	struct sk_buff_head *tmp_stack_list, *tmp_queue_list;
	struct fblock *fb;
	struct fb_crr_tx_priv __percpu *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_crr_tx_priv);
	if (!fb_priv)
		goto err;

	if (unlikely((tmp_open_pkts = kzalloc(sizeof(unsigned char), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto erra;
	}

	if (unlikely((tmp_seq_nr = kzalloc(sizeof(unsigned char), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto errb;
	}

	if (unlikely((tmp_stack_list = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1;
	}

	if (unlikely((tmp_queue_list = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1a;
	}

	*tmp_open_pkts = 0;
	*tmp_seq_nr = 1;

	skb_queue_head_init(tmp_stack_list);
	skb_queue_head_init(tmp_queue_list);

	for (i = 0; i < WIN_SZ; i++) {
		init_timer(&my_timer[i].mytimer);
		my_timer[i].open_pkts = tmp_open_pkts;
		my_timer[i].stack_list = tmp_stack_list;
	}

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_crr_tx_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		rwlock_init(&fb_priv_cpu->tx_lock);
		my_timer[0].tx_lock = &fb_priv_cpu->tx_lock;
		my_timer[1].tx_lock = &fb_priv_cpu->tx_lock;
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->tx_open_pkts = tmp_open_pkts;
		fb_priv_cpu->tx_seq_nr = tmp_seq_nr;
		fb_priv_cpu->tx_stack_list = tmp_stack_list;
		fb_priv_cpu->tx_queue_list = tmp_queue_list;
	}
	put_online_cpus();

	for (i = 0; i < WIN_SZ; i++) {
		my_timer[i].mytimer.expires = jiffies + 10*HZ;
		my_timer[i].mytimer.function = fb_crr_tx_timeout;
		my_timer[i].mytimer.data = (unsigned long)&my_timer[i];
		add_timer(&my_timer[i].mytimer);
	}

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;
	fb->netfb_rx = fb_crr_tx_netrx;
	fb->event_rx = fb_crr_tx_event;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	__module_get(THIS_MODULE);
	printk(KERN_ERR "[CRR TX] Initialization passed!\n");
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	del_timer_sync(&my_timer[0].mytimer);
	del_timer_sync(&my_timer[1].mytimer);
	kfree(tmp_queue_list);
err1a:
	kfree(tmp_stack_list);
err1:
	kfree(tmp_seq_nr);
errb:
	kfree(tmp_open_pkts);	
erra:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_crr_tx_dtor(struct fblock *fb)
{
	int i, queue_len;
	struct fb_crr_tx_priv *fb_priv_cpu;
	struct fb_crr_tx_priv __percpu *fb_priv;
	struct sk_buff *tmp_skb;

	printk(KERN_ERR "[CRR TX] Deinit Start!\n");
	for (i = 0; i < WIN_SZ; i++)
		del_timer(&my_timer[i].mytimer);

	rcu_read_lock();
	fb_priv = (struct fb_crr_tx_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);					/* CPUs share same priv. d */
	rcu_read_unlock();

	write_lock_bh(&fb_priv_cpu->tx_lock);					/* LOCK */
	printk(KERN_ERR "[CRR TX] Deinit LOCKED!\n");
	del_timer_sync(&my_timer[0].mytimer);
	del_timer_sync(&my_timer[1].mytimer);
	printk(KERN_ERR "[CRR TX] Deinit Timers stopped\n");

	queue_len = skb_queue_len(fb_priv_cpu->tx_stack_list);
	printk(KERN_ERR "[CRR TX] Deinit Qlen stack: %d\n", queue_len);

	for (i = 0; i < queue_len; i++) {					/* delete remaining elements in stack list */
		tmp_skb = skb_dequeue(fb_priv_cpu->tx_stack_list);
		kfree(tmp_skb);
	}
	printk(KERN_ERR "[CRR TX] Deinit Qlen queue: %d\n", queue_len);
	queue_len = skb_queue_len(fb_priv_cpu->tx_queue_list);

	for (i = 0; i < queue_len; i++) {					/* delete remaining elements in queue list */
		tmp_skb = skb_dequeue(fb_priv_cpu->tx_queue_list);		
		kfree(tmp_skb);
	}
	printk(KERN_ERR "[CRR TX] Deinit Queues cleaned\n");

	kfree(fb_priv_cpu->tx_stack_list);
	kfree(fb_priv_cpu->tx_queue_list);
	printk(KERN_ERR "[CRR TX] Deinit lists freed\n");

	kfree(fb_priv_cpu->tx_open_pkts);
	kfree(fb_priv_cpu->tx_seq_nr);
	printk(KERN_ERR "[CRR TX] Deinit pkts and seq freed\n");

	write_unlock_bh(&fb_priv_cpu->tx_lock);					// UNLOCK
	printk(KERN_ERR "[CRR TX] Deinit UNLOCKED!\n");

	free_percpu(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
	printk(KERN_ERR "[CRR TX] Deinitialization passed!\n");
}

static struct fblock_factory fb_crr_tx_factory = {
	.type = "crr_tx",
	.mode = MODE_DUAL,
	.ctor = fb_crr_tx_ctor,
	.dtor = fb_crr_tx_dtor,
	.owner = THIS_MODULE,
};

static int __init init_fb_crr_tx_module(void)
{
	return register_fblock_type(&fb_crr_tx_factory);
}

static void __exit cleanup_fb_crr_tx_module(void)
{
	synchronize_rcu();
	unregister_fblock_type(&fb_crr_tx_factory);
}

module_init(init_fb_crr_tx_module);
module_exit(cleanup_fb_crr_tx_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Florian Deragisch <floriade@ee.ethz.ch>");
MODULE_DESCRIPTION("LANA CRR tx module");
