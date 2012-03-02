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
 * Don't use seq nr, which is still not ACK'ed ( 1 - 2 ACK 3 ACK 4 ACK 1 X )! DONE
 * We need 2*WIN_SZ timers (1 - 2 ACK 3 ACK <- X) would stop timer 1! DONE
 * Fix Timeout retransmission! NOT WORKING! DONE
 * Change seq and ack structure for bigger window size
 * Check if receiving is an open packet -> Affects spoofing.
 * Reset von Seq Nr für neue Transfers? -> Not important Seq Nr is being 
 * tracked from kernel space not user space!
 */

/* Important!
 *
 * Packets coming from userspace, that are using the PF_LANA socket, are raw
 * packets. The data pointer points to the ETH_HDR, unlike packtes that have
 * passed the kernel already. For those packets data points after ETH_TYPE
 *
 * WIN_SZ between 1 and 16 so far 
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
#include <linux/hrtimer.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>

#include "xt_fblock.h"
#include "xt_builder.h"
#include "xt_idp.h"
#include "xt_skb.h"
#include "xt_engine.h"
#include "xt_builder.h"

#define ETH_HDR_LEN	14
#define WIN_SZ		4
#define ACK_LEN		1
#define MAX_QUEUE_LEN	500							// just test functionality without queue first
#define MAX_RTT		2*HZ

#define SET_BIT(x, y)	x | (1 << (y - 1))
#define UNSET_BIT(x,y) 	x & ~(1 << (y - 1))

struct fb_crr_tx_priv {
	idp_t port[2];
	seqlock_t lock;
	rwlock_t tx_lock;
	unsigned char *tx_open_pkts;
	unsigned char *tx_seq_nr;
	unsigned char *tx_win_nr;
	unsigned int *bitstream;
	struct sk_buff_head *tx_stack_list;
	struct sk_buff_head *tx_queue_list;
	struct semaphore *tx_queue_sem;
};

struct fb_curr_priv {
	struct fb_crr_tx_priv *p;
};

struct mytimer {
	unsigned char *open_pkts;
	unsigned int *bitstream;
	struct tasklet_hrtimer mytimer;
	struct sk_buff_head *stack_list;
	rwlock_t *tx_lock;
};

struct mytimer my_timer[2*WIN_SZ];

/*
 * Attention: Pos [1...32]
 */

/*static unsigned char bit_is_set(unsigned int *bitstream, unsigned char pos)
{
	if (pos > 32) {
		printk(KERN_ERR "Unvalid bit position for int\n");
		return 0;
	}

	if (*bitstream & (1<<(pos-1))) 
		return 1;
	else 
		return 0;

}*/

static struct sk_buff *skb_get_nr(unsigned char n, struct sk_buff_head *list)
{

	struct sk_buff *curr = list->next;

	while (1) {
		if (*(curr->data + ETH_HDR_LEN) == n)
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

//static void fb_crr_tx_timeout(unsigned long args)
static enum hrtimer_restart fb_crr_tx_timeout(struct hrtimer *self)
{
	unsigned int queue_len;
	struct sk_buff *curr, *cloned_skb;
	//unsigned long flags;
	struct tasklet_hrtimer *thr = container_of(self, struct tasklet_hrtimer, timer);
	struct mytimer *timer = container_of(thr, struct mytimer, mytimer);
	//struct mytimer *timer = (struct mytimer *)args;

	write_lock_bh(timer->tx_lock);						// LOCK 

		
	if (*timer->open_pkts == 0) {
		printk(KERN_ERR "[TO]\tNo open packets\n");
		write_unlock_bh(timer->tx_lock);				// UNLOCK
		return HRTIMER_NORESTART;
	}

	if(!(queue_len = skb_queue_len(timer->stack_list))) {
		//BUG("[TO]\tBUG: Timeout with empty stack!\n");
		BUG();
		return HRTIMER_NORESTART;
	}
		
	curr = skb_dequeue(timer->stack_list);

	if (curr == NULL) {							// W send pkt again. first in list is oldest passed
		printk(KERN_ERR "[TO]\tError: Stack is empty!\n"); 		// BUG should never happen!
		timer->open_pkts -=1;						// W 
		write_unlock_bh(timer->tx_lock);				// UNLOCKa
		return HRTIMER_NORESTART;
	}

	printk(KERN_ERR "[TO]\tOpen packet!\n"); 	

	if ((cloned_skb = skb_copy(curr, GFP_ATOMIC))) {
		skb_queue_tail(timer->stack_list, curr);
		write_unlock_bh(timer->tx_lock);
		/* ACHTUNG!!! Vor process_packet muss ein rcu_read_lock() und
		 * danach ein rcu_read_unlock() gesetzt werden! */ 
		rcu_read_lock();
		process_packet(cloned_skb, TYPE_EGRESS);
		rcu_read_unlock();

		//engine_backlog_tail(cloned_skb, TYPE_EGRESS);
		printk(KERN_ERR "[TO]\t\tResent seq nr %d\tr %d!\n", *(curr->data+ETH_HDR_LEN), *(curr->data+ETH_HDR_LEN+2));	
	}
	else {
		skb_queue_tail(timer->stack_list, curr);	
		printk(KERN_ERR "[TO]\t\tError: Couldn't copy!\n");
		timer->open_pkts -=1;
		write_unlock_bh(timer->tx_lock);
	}

	//mod_timer(&timer->mytimer, jiffies + 10*HZ);				// restart timer 					// UNLOCKb
	tasklet_hrtimer_start(thr, ktime_set(0, 10000000000),
			      HRTIMER_MODE_REL);
	return HRTIMER_NORESTART;
}

static int fb_crr_tx_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int drop = 0;
	unsigned int queue_len;
	unsigned char seq, ack, currseq;
	//unsigned long flags;
	struct sk_buff *cloned_skb, *curr;
	struct fb_curr_priv __percpu *fb_priv_cpu;

	fb_priv_cpu = this_cpu_ptr(rcu_dereference_raw(fb->private_data));
#ifdef __DEBUG
	printk("Got skb on %p on ppe%d!\n", fb, smp_processor_id());
#endif
	prefetchw(skb->cb);
	do {
		seq = read_seqbegin(&fb_priv_cpu->p->lock);
		write_next_idp_to_skb(skb, fb->idp, fb_priv_cpu->p->port[*dir]);
		if (fb_priv_cpu->p->port[*dir] == IDP_UNKNOWN)
			drop = 1;
	} while (read_seqretry(&fb_priv_cpu->p->lock, seq));

	if (*dir == TYPE_EGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {	// Send 

		write_lock_bh(&fb_priv_cpu->p->tx_lock);			// LOCK

		currseq = *fb_priv_cpu->p->tx_seq_nr; 				// R tag packet with seq nr 
		*fb_priv_cpu->p->tx_seq_nr = (*fb_priv_cpu->p->tx_seq_nr % (2*WIN_SZ)) + 1; // W Increment seq nr for next packet 
		*(skb->data + ETH_HDR_LEN) = currseq;
		if (currseq == 1)						// new window change 'ACK'
			*fb_priv_cpu->p->tx_win_nr = ~*fb_priv_cpu->p->tx_win_nr;// Invert ACK
		*(skb->data + ETH_HDR_LEN + 1) = *fb_priv_cpu->p->tx_win_nr;	// Tag ACK in packet		
		queue_len = skb_queue_len(fb_priv_cpu->p->tx_queue_list);	
		printk(KERN_ERR "[TX]\tCurrseq: %d\tOpen_pkts: %d\tQlen: %d\n",
			currseq, *fb_priv_cpu->p->tx_open_pkts, queue_len);

		if (likely(*fb_priv_cpu->p->tx_open_pkts == WIN_SZ )) {		// Queue packet

			//write_unlock_bh(&fb_priv_cpu->p->tx_lock);		// UNLOCKa

			//down(fb_priv_cpu->p->tx_queue_sem);		// should not keep lock. may sleep!

			//write_lock_bh(&fb_priv_cpu->p->tx_lock);	// UNLOCKa
			skb_queue_tail(fb_priv_cpu->p->tx_queue_list, skb);// W
			printk(KERN_ERR "[TX]\tAdded to queue %d\n", *(skb->data + ETH_HDR_LEN + 2)); 
			write_unlock_bh(&fb_priv_cpu->p->tx_lock);		// UNLOCKa

			drop = 2;
			//}
			/*else {
				write_unlock_bh(&fb_priv_cpu->p->tx_lock);	// UNLOCKb
				//printk(KERN_ERR "Send UNLOCKED!\n");
				printk(KERN_ERR "[TX]\tQueue is full!\n");
				drop = 1;	
			}*/
		}
		else {								// FREE packets!
										
			if (unlikely(queue_len)) {				// Check if packets in queue need to be send first 
				skb_queue_tail(fb_priv_cpu->p->tx_queue_list, skb);// W Queue new packet at end of queue_list 
				curr = skb_dequeue(fb_priv_cpu->p->tx_queue_list);// W Dequeue first element of queue_list
				currseq = *(curr->data + ETH_HDR_LEN);		// Packet from queue -> new currseq

				if (currseq == 1 && *fb_priv_cpu->p->bitstream != 0) { // Packet back in queue and dont send  
					skb_queue_head(fb_priv_cpu->p->tx_queue_list, curr);
					printk(KERN_ERR "[TX]\tMissing ACKS before starting new round!\n");
					printk(KERN_ERR "[TX]\tAdded to queue %d\n", *(skb->data + ETH_HDR_LEN + 2)); 
					drop = 2;
					write_unlock_bh(&fb_priv_cpu->p->tx_lock);// UNLOCKc
					goto out;
				}
				if (likely((cloned_skb = skb_copy(curr, GFP_ATOMIC)))) { 
					skb_queue_tail(fb_priv_cpu->p->tx_stack_list, curr);// W Queue at end of stack_list 	
					rcu_read_lock();
					process_packet(cloned_skb, TYPE_EGRESS);// process packet
					rcu_read_unlock();			// idp and seq_nr should be correct. schedule for egress path
					//up(fb_priv_cpu->p->tx_queue_sem); 
					(*fb_priv_cpu->p->tx_open_pkts)++;
					*fb_priv_cpu->p->bitstream = SET_BIT(*fb_priv_cpu->p->bitstream, currseq);
					//*fb_priv_cpu->p->bitstream = *fb_priv_cpu->p->bitstream | (1<<(currseq-1)); // set bitstream	
					printk(KERN_ERR "[TX]\t\tSent %d from queue\tNr %d\tBitstream %d\n", currseq, *(curr->data+ETH_HDR_LEN+2), *fb_priv_cpu->p->bitstream);			
				}
				else {
					skb_queue_tail(fb_priv_cpu->p->tx_stack_list, curr);// W Queue at end of stack_list 
					printk(KERN_ERR "[TX]\tError: Couldn't copy!\n");	
				}		
				drop = 2;					// don't send and don't free, because in list
			}
			else {							// send packet and push on stack 
				

				if (seq == 1 && *fb_priv_cpu->p->bitstream != 0) { // Packet back in queue and dont send  
					skb_queue_head(fb_priv_cpu->p->tx_queue_list, skb);
					drop = 2;
					write_unlock_bh(&fb_priv_cpu->p->tx_lock);// UNLOCKc
					printk(KERN_ERR "[TX]\tMissing ACKS before starting new round!\n");
					printk(KERN_ERR "[TX]\tAdded to queue %d\n", *(skb->data + ETH_HDR_LEN + 2)); 
					goto out;
				}

				if (likely((cloned_skb = skb_copy(skb, GFP_ATOMIC)))) { 	
					skb_queue_tail(fb_priv_cpu->p->tx_stack_list, cloned_skb);// W 
					(*fb_priv_cpu->p->tx_open_pkts)++;				// W
					*fb_priv_cpu->p->bitstream = SET_BIT(*fb_priv_cpu->p->bitstream, currseq);
					//*fb_priv_cpu->p->bitstream = *fb_priv_cpu->p->bitstream | (1<<(currseq-1)); // set bitstream 
					printk(KERN_ERR "[TX]\t\tSent %d normal\tNr %d\tBitstream %d\n", currseq, *(skb->data+ETH_HDR_LEN+2), *fb_priv_cpu->p->bitstream);				
				}
				else {
					drop = 1;
					write_unlock_bh(&fb_priv_cpu->p->tx_lock);// UNLOCKc
					printk(KERN_ERR "[TX]\t\tError: Couldn't copy!\n");
					goto out;
				}
			}

			//mod_timer(&my_timer[currseq-1].mytimer, jiffies + currseq*10*HZ); 
			tasklet_hrtimer_start(&my_timer[currseq-1].mytimer, ktime_set(0, 10000000000),
					      HRTIMER_MODE_REL);
			write_unlock_bh(&fb_priv_cpu->p->tx_lock);		// UNLOCKc
		}
	}
	/* Receive */
	else if (*dir == TYPE_INGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) { // possible ACK 

		seq =  *skb->data;
		ack =  *(skb->data+1);
		
		
		if (unlikely(ack != 0xFF || seq == 0 || seq > 2*WIN_SZ))	// invalid packets
			goto out;

		write_lock_bh(&fb_priv_cpu->p->tx_lock);			// LOCK
		//printk(KERN_ERR "[RX]\tACK received\n");

		/*if (likely(!bit_is_set(fb_priv_cpu->p->bitstream, seq))) {
			write_unlock_bh(&fb_priv_cpu->p->tx_lock);
			goto out;
		}*/
	
		//del_timer_sync(&my_timer[seq-1].mytimer);			// We have 2*WIN_SZ timers now
		tasklet_hrtimer_cancel(&my_timer[seq-1].mytimer);
		(*fb_priv_cpu->p->tx_open_pkts)--;				// W 

		printk(KERN_ERR "[RX]\tACK %d with %d\tOpenpkts: %d\n", seq,
		*(skb->data+2) ,*fb_priv_cpu->p->tx_open_pkts);

		if (likely((curr = skb_get_nr(seq, fb_priv_cpu->p->tx_stack_list)))) {	// R get according element 
			skb_unlink(curr, fb_priv_cpu->p->tx_stack_list);		// W dequeue from list 
			kfree(curr);
		}
		
		drop = 1;							// drop pkt before user space
		*fb_priv_cpu->p->bitstream = UNSET_BIT(*fb_priv_cpu->p->bitstream, seq);
		printk(KERN_ERR "[RX]\tBitstream new: %d\n", *fb_priv_cpu->p->bitstream);
		//*fb_priv_cpu->p->bitstream = *fb_priv_cpu->p->bitstream & ~(1<<(seq-1)); // unset bit 
ACK_SEND:
		queue_len = skb_queue_len(fb_priv_cpu->p->tx_queue_list);	// R 

		if (likely(queue_len)) {					// && *fb_priv_cpu->p->tx_open_pkts <= MAX_OPEN_PKTS) {  R 
			curr = skb_dequeue(fb_priv_cpu->p->tx_queue_list);	// W Dequeue first element of queue_list
			seq = *(curr->data+ETH_HDR_LEN);


			if (seq == 1 && *fb_priv_cpu->p->bitstream != 0) { // Packet back in queue and dont send  
				skb_queue_head(fb_priv_cpu->p->tx_queue_list, curr);
				write_unlock_bh(&fb_priv_cpu->p->tx_lock);	// UNLOCKc
				printk(KERN_ERR "[RX]\tMissing ACKS before starting new round!\n");
				goto out;
			}

			if (likely((cloned_skb = skb_copy(curr, GFP_ATOMIC))))  {
				skb_queue_tail(fb_priv_cpu->p->tx_stack_list, curr);// W Queue at end of stack_list 			
				printk(KERN_ERR "[RX]\t\tSent %d \tNr %d\n", *(curr->data+ETH_HDR_LEN), *(curr->data+ETH_HDR_LEN+2));
				rcu_read_lock();
				process_packet(cloned_skb, TYPE_EGRESS);
				rcu_read_unlock();	// idp and seq_nr should be correct. schedule for egress path
				//up(fb_priv_cpu->p->tx_queue_sem);
				(*fb_priv_cpu->p->tx_open_pkts)++; 
				*fb_priv_cpu->p->bitstream = SET_BIT(*fb_priv_cpu->p->bitstream, seq);
				printk(KERN_ERR "[RX]\tBitstream new: %d\n", *fb_priv_cpu->p->bitstream);
				//mod_timer(&my_timer[seq-1].mytimer, jiffies + 10*HZ);
				tasklet_hrtimer_start(&my_timer[seq-1].mytimer, ktime_set(0, 10000000000),
						      HRTIMER_MODE_REL);  
				if (*fb_priv_cpu->p->tx_open_pkts < WIN_SZ)	// W
					goto ACK_SEND;
				//*fb_priv_cpu->p->bitstream = *fb_priv_cpu->p->bitstream | (1<<(seq-1)); 
			}
			else {
				skb_queue_tail(fb_priv_cpu->p->tx_stack_list, curr);// W Queue at end of stack_list
				//mod_timer(&my_timer[seq-1].mytimer, jiffies + 10*HZ); 
				tasklet_hrtimer_start(&my_timer[seq-1].mytimer, ktime_set(0, 10000000000),
						      HRTIMER_MODE_REL);
				printk(KERN_ERR "[RX]\t\tError: Couldn't copy!\n");
			}
		}
		write_unlock_bh(&fb_priv_cpu->p->tx_lock);				
		//printk(KERN_ERR "Receive UNLOCKED!\n");
	}
out:
	if (drop == 1) {
		kfree_skb(skb);
		//printk(KERN_ERR "Freed and dropped!\n");
		return PPE_DROPPED;
	}
	else if (drop == 2) {
		//printk(KERN_ERR "Dropped!\n");
		return PPE_DROPPED;
	}
	//printk(KERN_ERR "Passed on!\n");
	return PPE_SUCCESS;
}

static int fb_crr_tx_event(struct notifier_block *self, unsigned long cmd,
			  void *args)
{
	int ret = NOTIFY_OK;
	unsigned int cpu;
	struct fblock *fb;
	struct fb_curr_priv __percpu *fb_priv;

	rcu_read_lock();
	fb = rcu_dereference_raw(container_of(self, struct fblock_notifier, nb)->self);
	fb_priv = (struct fb_curr_priv __percpu *) rcu_dereference_raw(fb->private_data);
	rcu_read_unlock();

	//printk("Got event %lu on %p!\n", cmd, fb);

	switch (cmd) {
	case FBLOCK_BIND_IDP: {
		int bound = 0;
		struct fblock_bind_msg *msg = args;
		get_online_cpus();
		for_each_online_cpu(cpu) {
			struct fb_curr_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			//printk("XXXXbind: %u\n", fb_priv_cpu->p->port[msg->dir]);
			if (fb_priv_cpu->p->port[msg->dir] == IDP_UNKNOWN) {
				write_seqlock(&fb_priv_cpu->p->lock);
				fb_priv_cpu->p->port[msg->dir] = msg->idp;
				write_sequnlock(&fb_priv_cpu->p->lock);
				bound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
			break;
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
			struct fb_curr_priv *fb_priv_cpu;
			fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
			//printk("XXXXunbind: %u\n", fb_priv_cpu->p->port[msg->dir]);
			if (fb_priv_cpu->p->port[msg->dir] == msg->idp) {
				write_seqlock(&fb_priv_cpu->p->lock);
				fb_priv_cpu->p->port[msg->dir] = IDP_UNKNOWN;
				write_sequnlock(&fb_priv_cpu->p->lock);
				unbound = 1;
			} else {
				ret = NOTIFY_BAD;
				break;
			}
			break;
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
	unsigned char *tmp_open_pkts, *tmp_seq_nr, *tmp_win_nr;
	unsigned int i, cpu, *tmp_bitstream;
	struct sk_buff_head *tmp_stack_list, *tmp_queue_list;
	struct fblock *fb;
	struct fb_crr_tx_priv *priv;
	struct fb_curr_priv __percpu *fb_priv;
	struct semaphore *tmp_semaphore;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	tmp_semaphore = kzalloc(sizeof(struct semaphore), GFP_ATOMIC);
	if (unlikely(!tmp_semaphore)) 
		goto err_;

	priv = kzalloc(sizeof(*priv), GFP_ATOMIC);
	if (unlikely(!priv)) 
		goto err__;

	fb_priv = alloc_percpu(struct fb_curr_priv);
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

	if (unlikely((tmp_bitstream = kzalloc(sizeof(unsigned int), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err0;
	}

	if (unlikely((tmp_stack_list = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1;
	}

	if (unlikely((tmp_win_nr = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1_;
	}

	if (unlikely((tmp_queue_list = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1a;
	}

	*tmp_win_nr = 0;
	*tmp_open_pkts = 0;
	*tmp_bitstream = 0;
	*tmp_seq_nr = 1;

	sema_init(tmp_semaphore, MAX_QUEUE_LEN);

	skb_queue_head_init(tmp_stack_list);
	skb_queue_head_init(tmp_queue_list);

	for (i = 0; i < 2*WIN_SZ; i++) {
		//init_timer(&my_timer[i].mytimer);
		tasklet_hrtimer_init(&my_timer[i].mytimer,
				     fb_crr_tx_timeout,
				     CLOCK_REALTIME, HRTIMER_MODE_ABS);		
		my_timer[i].open_pkts = tmp_open_pkts;
		my_timer[i].stack_list = tmp_stack_list;
		my_timer[i].bitstream = tmp_bitstream;
	}

	seqlock_init(&priv->lock);
	rwlock_init(&priv->tx_lock);
	for (i = 0; i < 2*WIN_SZ; i++)
		my_timer[i].tx_lock = &priv->tx_lock;
	priv->port[0] = IDP_UNKNOWN;
	priv->port[1] = IDP_UNKNOWN;
	priv->tx_open_pkts = tmp_open_pkts;
	priv->tx_seq_nr = tmp_seq_nr;
	priv->tx_win_nr = tmp_win_nr;
	priv->bitstream = tmp_bitstream;
	priv->tx_stack_list = tmp_stack_list;
	priv->tx_queue_list = tmp_queue_list;
	priv->tx_queue_sem = tmp_semaphore;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_curr_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		fb_priv_cpu->p = priv;
	}
	put_online_cpus();

	/*for (i = 0; i < 2*WIN_SZ; i++) {
		my_timer[i].mytimer.expires = jiffies + 10*HZ;
		my_timer[i].mytimer.function = fb_crr_tx_timeout;
		my_timer[i].mytimer.data = (unsigned long)&my_timer[i];
		add_timer(&my_timer[i].mytimer);
	}*/

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
	for (i = 0; i < 2*WIN_SZ; i++) 
		//del_timer_sync(&my_timer[i].mytimer);
		tasklet_hrtimer_cancel(&my_timer[i].mytimer);
	kfree(tmp_queue_list);
err1a:
	kfree(tmp_win_nr);
err1_:
	kfree(tmp_stack_list);
err1:
	kfree(tmp_bitstream);
err0:
	kfree(tmp_seq_nr);
errb:
	kfree(tmp_open_pkts);	
erra:
	free_percpu(fb_priv);
err:
	kfree(priv);
err__:
	kfree(tmp_semaphore);
err_:
	kfree_fblock(fb);
	return NULL;
}

static void fb_crr_tx_dtor(struct fblock *fb)
{
	int i, queue_len;
	//unsigned long flags;
	struct fb_curr_priv *fb_priv_cpu;
	struct fb_curr_priv __percpu *fb_priv;
	struct sk_buff *tmp_skb;

	printk(KERN_ERR "[CRR TX] Deinit Start!\n");

	rcu_read_lock();
	fb_priv = (struct fb_curr_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);					/* CPUs share same priv. d */
	rcu_read_unlock();

	write_lock_bh(&fb_priv_cpu->p->tx_lock);					/* LOCK */
	printk(KERN_ERR "[CRR TX] Deinit LOCKED!\n");

	for (i = 0; i < 2*WIN_SZ; i++)
		tasklet_hrtimer_cancel(&my_timer[i].mytimer);
	printk(KERN_ERR "[CRR TX] Deinit Timers stopped\n");

	queue_len = skb_queue_len(fb_priv_cpu->p->tx_stack_list);
	printk(KERN_ERR "[CRR TX] Deinit Qlen stack: %d\n", queue_len);

	for (i = 0; i < queue_len; i++) {					/* delete remaining elements in stack list */
		tmp_skb = skb_dequeue(fb_priv_cpu->p->tx_stack_list);
		kfree(tmp_skb);
	}
	printk(KERN_ERR "[CRR TX] Deinit Qlen queue: %d\n", queue_len);
	queue_len = skb_queue_len(fb_priv_cpu->p->tx_queue_list);

	for (i = 0; i < queue_len; i++) {					/* delete remaining elements in queue list */
		tmp_skb = skb_dequeue(fb_priv_cpu->p->tx_queue_list);		
		kfree(tmp_skb);
	}
	printk(KERN_ERR "[CRR TX] Deinit Queues cleaned\n");

	kfree(fb_priv_cpu->p->tx_stack_list);
	kfree(fb_priv_cpu->p->tx_queue_list);
	printk(KERN_ERR "[CRR TX] Deinit lists freed\n");

	kfree(fb_priv_cpu->p->tx_open_pkts);
	kfree(fb_priv_cpu->p->tx_seq_nr);
	kfree(fb_priv_cpu->p->tx_win_nr);
	kfree(fb_priv_cpu->p->bitstream);
	printk(KERN_ERR "[CRR TX] Deinit pkts, bitstream and seq freed\n");

	kfree(fb_priv_cpu->p->tx_queue_sem);
	printk(KERN_ERR "[CRR TX] Deinit semaphore freed\n");

	write_unlock_bh(&fb_priv_cpu->p->tx_lock);					// UNLOCK
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
