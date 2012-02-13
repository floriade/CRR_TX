/*
 * Lightweight Autonomic Network Architecture
 *
 * crr_tx test module.
 *
 * Copyright 2011 Florian Deragisch <floriade@ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
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
#define MAX_RTT		1000 /* depends on jiffy */

struct fb_crr_tx_priv {
	idp_t port[2];
	seqlock_t lock;
	rwlock_t tx_lock;
	unsigned char tx_open_pkts;
	unsigned char tx_seq_nr;
	struct sk_buff_head *tx_stack_list;
	struct sk_buff_head *tx_queue_list;
	struct timer_list *timer1;
	struct timer_list *timer2;
};

struct mytimer {
	unsigned char nr;
	unsigned char *open_pkts;
	struct timer_list *mytimer;
	struct sk_buff_head *stack_list;
	rwlock_t *tx_lock;
};

static struct sk_buff *skb_get_nr(unsigned char n, struct sk_buff_head *list)
{
	int i;
	struct sk_buff *curr = list->next;

	for (i = 1; i < n; i++)
		curr = curr->next;

	return curr;
}

/* returns a pointer to the skb_buff with the following seq number */
static struct sk_buff *skb_get_pos(unsigned char seq, struct sk_buff_head *list)
{
	struct sk_buff *curr = list->next;

	/* list is empty */
	if (list->next == list->prev)
		return list->next;
	/* Second element */
	else if (seq == 2)
		return list->next;
	/* others */
	while(1) {
	if (curr->cb[47] > seq)
		break;

		if (curr->next == list->next)
			break;
		curr = curr->next;
	}
	return curr;
}

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
	/* send pkt again. first in list is oldest*/
	write_lock(timer->tx_lock);
	if ((curr = skb_dequeue(timer->stack_list)) == NULL) {
		printk(KERN_ERR "Error: Stack is empty!\n"); /* BUG */
		timer->open_pkts -=1;
		write_unlock(timer->tx_lock);	
		return;
	}

	skb_queue_tail(timer->stack_list, curr);

	if ((cloned_skb = skb_copy(curr, GFP_ATOMIC))) {
		/* idp should be correct. schedule for egress path */
		engine_backlog_tail(cloned_skb, TYPE_EGRESS);
	}
	else {
		printk(KERN_ERR "Error: Couldn't copy!\n");
		timer->open_pkts -=1;
	}

	/* restart timer */
	mod_timer(timer->mytimer, jiffies + MAX_RTT);
	write_unlock(timer->tx_lock);	
}

static int fb_crr_tx_netrx(const struct fblock * const fb,
			  struct sk_buff * const skb,
			  enum path_type * const dir)
{
	int drop = 0;
	unsigned int queue_length;
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
	/* Send */
	if (*dir == TYPE_EGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {
		currseq = *(skb->data + ETH_HDR_LEN) = (fb_priv_cpu->tx_seq_nr % (2 * WIN_SZ))+ 1; /* tag packet with seq nr */
		fb_priv_cpu->tx_seq_nr = (fb_priv_cpu->tx_seq_nr + 1) % (2 * WIN_SZ);
		queue_length = skb_queue_len(fb_priv_cpu->tx_queue_list);
												
		if (fb_priv_cpu->tx_open_pkts > MAX_OPEN_PKTS) {		/* Queue packet*/
			if (queue_length < MAX_QUEUE_LEN) {
				skb_queue_tail(fb_priv_cpu->tx_queue_list, skb);
				drop = 2;
			}
			else {
				printk(KERN_ERR "Queue is full!\n");
				drop = 1;	
			}
		}
		else {								/* Send packet and write to stack */
			if (queue_length) {					/* Check if packets in queue need to be send first */
				skb_queue_tail(fb_priv_cpu->tx_queue_list, skb);/* Queue at end of queue_list */
				curr = skb_dequeue(fb_priv_cpu->tx_queue_list);	/* Dequeue first element of queue_list */
				skb_queue_tail(fb_priv_cpu->tx_stack_list, curr);/* Queue at end of stack_list */			
				drop = 2;
			}
			/* send packet and push on stack */
			else {
				skb_queue_tail(fb_priv_cpu->tx_stack_list, skb);
				curr = skb;
			}

			if ((cloned_skb = skb_copy(curr, GFP_ATOMIC))) 
				engine_backlog_tail(cloned_skb, TYPE_EGRESS);	/* idp and seq_nr should be correct. schedule for egress path */
			else
				printk(KERN_ERR "Error: Couldn't copy!\n");
			
			if (!(currseq % 2))
				mod_timer(fb_priv_cpu->timer2, jiffies + MAX_RTT);
			else
				mod_timer(fb_priv_cpu->timer1, jiffies + MAX_RTT);

			fb_priv_cpu->tx_open_pkts++;
		}
	}
	/* Receive */
	else if (*dir == TYPE_INGRESS && ntohs(eth_hdr(skb)->h_proto) == 0xabba) {
		queue_length = skb_queue_len(fb_priv_cpu->tx_queue_list);
		custom = *(skb->data + ETH_HDR_LEN);
		seq = custom >> 4;
		ack = custom & 0xF;
		if (ack == 0xF) {						/* ACK received */
			if ((seq % 2) == 0)					/* Timer 2 */
				del_timer(fb_priv_cpu->timer2);
			else							/* Timer 1 */
				del_timer(fb_priv_cpu->timer1);
		
			fb_priv_cpu->tx_open_pkts--;

			curr = skb_get_nr(seq, fb_priv_cpu->tx_stack_list);	/* get according element */
			skb_unlink(curr, fb_priv_cpu->tx_stack_list);		/* dequeue from list */
			kfree(curr);						/* delete pkt from stack */
			drop = 1;						/* drop pkt before user space */
		}



		if (queue_length && fb_priv_cpu->tx_open_pkts <= MAX_OPEN_PKTS) {
			curr = skb_dequeue(fb_priv_cpu->tx_queue_list);		/* Dequeue first element of queue_list */
			skb_queue_tail(fb_priv_cpu->tx_stack_list, curr);	/* Queue at end of stack_list */

			if ((cloned_skb = skb_copy(curr, GFP_ATOMIC))) 
				engine_backlog_tail(cloned_skb, TYPE_EGRESS);	/* idp and seq_nr should be correct. schedule for egress path */
			else
				printk(KERN_ERR "Error: Couldn't copy!\n");
			
			if (!(seq % 2))						/* Start timers */
				mod_timer(fb_priv_cpu->timer2, jiffies + MAX_RTT);
			else
				mod_timer(fb_priv_cpu->timer1, jiffies + MAX_RTT);

			fb_priv_cpu->tx_open_pkts++;		
		}
	}

	if (drop == 1) {
		kfree_skb(skb);
		return PPE_DROPPED;
	}
	else if (drop == 2)
		return PPE_DROPPED;
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
	unsigned int cpu;
	struct timer_list tmp_timer1, tmp_timer2;
	struct sk_buff_head *tmp_list1, *tmp_list2;
	struct mytimer *timer1_arg, *timer2_arg;
	struct fblock *fb;
	struct fb_crr_tx_priv __percpu *fb_priv;

	fb = alloc_fblock(GFP_ATOMIC);
	if (!fb)
		return NULL;

	fb_priv = alloc_percpu(struct fb_crr_tx_priv);
	if (!fb_priv)
		goto err;

	if (unlikely((tmp_list1 = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1;
	}

		if (unlikely((tmp_list2 = kzalloc(sizeof(struct sk_buff_head), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1a;
	}

	if (unlikely((timer1_arg = kzalloc(sizeof(struct mytimer), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1b;
	}

	if (unlikely((timer2_arg = kzalloc(sizeof(struct mytimer), GFP_ATOMIC)) == NULL)) {
		printk(KERN_ERR "Allocation failed!\n");
		goto err1c;
	}

	timer1_arg->nr = 1;
	timer1_arg->mytimer = &tmp_timer1;
	timer1_arg->stack_list = tmp_list2;

	timer2_arg->nr = 2;
	timer2_arg->mytimer = &tmp_timer2;
	timer2_arg->stack_list = tmp_list2;

	skb_queue_head_init(tmp_list1);
	skb_queue_head_init(tmp_list2);
	init_timer(&tmp_timer1);
	init_timer(&tmp_timer1);

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct fb_crr_tx_priv *fb_priv_cpu;
		fb_priv_cpu = per_cpu_ptr(fb_priv, cpu);
		seqlock_init(&fb_priv_cpu->lock);
		rwlock_init(&fb_priv_cpu->tx_lock);
		timer1_arg->tx_lock = timer2_arg->tx_lock = &fb_priv_cpu->tx_lock;
		timer1_arg->open_pkts = timer2_arg->open_pkts = &fb_priv_cpu->tx_open_pkts;
		fb_priv_cpu->port[0] = IDP_UNKNOWN;
		fb_priv_cpu->port[1] = IDP_UNKNOWN;
		fb_priv_cpu->tx_open_pkts = 0;
		fb_priv_cpu->tx_seq_nr = 0;
		fb_priv_cpu->tx_stack_list = tmp_list1;
		fb_priv_cpu->tx_queue_list = tmp_list2;
		fb_priv_cpu->timer1 = &tmp_timer1;
		fb_priv_cpu->timer2 = &tmp_timer2;
	}
	put_online_cpus();

	tmp_timer1.expires = 0;
	tmp_timer1.function = fb_crr_tx_timeout;
	tmp_timer1.data = (unsigned long) timer1_arg;

	tmp_timer2.expires = 0;
	tmp_timer2.function = fb_crr_tx_timeout;
	tmp_timer2.data = (unsigned long) timer2_arg;

	ret = init_fblock(fb, name, fb_priv);
	if (ret)
		goto err2;
	fb->netfb_rx = fb_crr_tx_netrx;
	fb->event_rx = fb_crr_tx_event;
	ret = register_fblock_namespace(fb);
	if (ret)
		goto err3;
	__module_get(THIS_MODULE);
	printk(KERN_ERR "Initialization passed!\n");
	return fb;
err3:
	cleanup_fblock_ctor(fb);
err2:
	del_timer_sync(&tmp_timer1);
	del_timer_sync(&tmp_timer2);
	kfree(timer2_arg);
err1c:
	kfree(timer1_arg);
err1b:
	kfree(tmp_list2);
err1a:
	kfree(tmp_list1);
err1:
	free_percpu(fb_priv);
err:
	kfree_fblock(fb);
	return NULL;
}

static void fb_crr_tx_dtor(struct fblock *fb)
{
	int i;
	struct fb_crr_tx_priv *fb_priv_cpu;
	struct fb_crr_tx_priv __percpu *fb_priv;
	struct sk_buff *tmp_skb;

	rcu_read_lock();
	fb_priv = (struct fb_crr_tx_priv __percpu *) rcu_dereference_raw(fb->private_data);
	fb_priv_cpu = per_cpu_ptr(fb_priv, 0);	/* CPUs share same priv. d */
	rcu_read_unlock();

	write_lock(&fb_priv_cpu->tx_lock);

	/* delete remaining elements in stack list */
	/* TODO: use temp variable to store skb_queue_empty(list) */
	for (i = 0; i < fb_priv_cpu->tx_stack_list->qlen; i++) {
		tmp_skb = fb_priv_cpu->tx_stack_list->next;
		skb_unlink(fb_priv_cpu->tx_stack_list->next, fb_priv_cpu->tx_stack_list);
		kfree(tmp_skb);
	}
	/* delete remaining elements in queue list */
	for (i = 0; i < fb_priv_cpu->tx_queue_list->qlen; i++) {
		tmp_skb = fb_priv_cpu->tx_queue_list->next;
		skb_unlink(fb_priv_cpu->tx_queue_list->next, fb_priv_cpu->tx_queue_list);
		kfree(tmp_skb);
	}

	del_timer_sync(fb_priv_cpu->timer1);
	del_timer_sync(fb_priv_cpu->timer2);

	kfree(&fb_priv_cpu->timer1->data);
	kfree(&fb_priv_cpu->timer2->data);

	kfree(fb_priv_cpu->tx_stack_list);
	kfree(fb_priv_cpu->tx_queue_list);

	write_unlock(&fb_priv_cpu->tx_lock);

	free_percpu(rcu_dereference_raw(fb->private_data));
	module_put(THIS_MODULE);
	printk(KERN_ERR "Deinitialization passed!\n");
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
