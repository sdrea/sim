// Variant of SimpleScalar developed for modelling cache compression and prefetching
// Based on sim-wattch-1.02e - http://www.eecs.harvard.edu/~dbrooks/wattch-form.html
//
// changes wrapped in //sdrea-begin ... //sdrea-end
//
// Sean Rea
// sdrea@lakeheadu.ca
// 2016-2017
////////////////////////////////////////////////////////////////

/* cache.c - cache module routines */

/* SimpleScalar(TM) Tool Suite
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 * All Rights Reserved. 
 * 
 * THIS IS A LEGAL DOCUMENT, BY USING SIMPLESCALAR,
 * YOU ARE AGREEING TO THESE TERMS AND CONDITIONS.
 * 
 * No portion of this work may be used by any commercial entity, or for any
 * commercial purpose, without the prior, written permission of SimpleScalar,
 * LLC (info@simplescalar.com). Nonprofit and noncommercial use is permitted
 * as described below.
 * 
 * 1. SimpleScalar is provided AS IS, with no warranty of any kind, express
 * or implied. The user of the program accepts full responsibility for the
 * application of the program and the use of any results.
 * 
 * 2. Nonprofit and noncommercial use is encouraged. SimpleScalar may be
 * downloaded, compiled, executed, copied, and modified solely for nonprofit,
 * educational, noncommercial research, and noncommercial scholarship
 * purposes provided that this notice in its entirety accompanies all copies.
 * Copies of the modified software can be delivered to persons who use it
 * solely for nonprofit, educational, noncommercial research, and
 * noncommercial scholarship purposes provided that this notice in its
 * entirety accompanies all copies.
 * 
 * 3. ALL COMMERCIAL USE, AND ALL USE BY FOR PROFIT ENTITIES, IS EXPRESSLY
 * PROHIBITED WITHOUT A LICENSE FROM SIMPLESCALAR, LLC (info@simplescalar.com).
 * 
 * 4. No nonprofit user may place any restrictions on the use of this software,
 * including as modified by the user, by any other authorized user.
 * 
 * 5. Noncommercial and nonprofit users may distribute copies of SimpleScalar
 * in compiled or executable form as set forth in Section 2, provided that
 * either: (A) it is accompanied by the corresponding machine-readable source
 * code, or (B) it is accompanied by a written offer, with no time limit, to
 * give anyone a machine-readable copy of the corresponding source code in
 * return for reimbursement of the cost of distribution. This written offer
 * must permit verbatim duplication by anyone, or (C) it is distributed by
 * someone who received only the executable form, and is accompanied by a
 * copy of the written offer of source code.
 * 
 * 6. SimpleScalar was developed by Todd M. Austin, Ph.D. The tool suite is
 * currently maintained by SimpleScalar LLC (info@simplescalar.com). US Mail:
 * 2395 Timbercrest Court, Ann Arbor, MI 48105.
 * 
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "host.h"
#include "misc.h"
#include "machine.h"
#include "cache.h"

//sdrea-begin
////////////////////////////////////////////////////////////////

#include <time.h>
#include <string.h>

static counter_t count_check_lines = 0;
static counter_t count_compressible_any = 0;
static counter_t count_compressible_0000_zeros = 0;
static counter_t count_compressible_0001_repeats = 0;
static counter_t count_compressible_0010_b8d1 = 0;
static counter_t count_compressible_0011_b8d2 = 0;
static counter_t count_compressible_0100_b8d4 = 0;
static counter_t count_compressible_0101_b4d1 = 0;
static counter_t count_compressible_0110_b4d2 = 0;
static counter_t count_compressible_0111_b2d1 = 0;

static counter_t count_encode_lines = 0;
static counter_t count_encode_0000_zeros = 0;
static counter_t count_encode_0001_repeats = 0;
static counter_t count_encode_0010_b8d1 = 0;
static counter_t count_encode_0011_b8d2 = 0;
static counter_t count_encode_0100_b8d4 = 0;
static counter_t count_encode_0101_b4d1 = 0;
static counter_t count_encode_0110_b4d2 = 0;
static counter_t count_encode_0111_b2d1 = 0;
static counter_t count_encode_1111_uncompressed = 0;

static counter_t size_uncompressed = 0;
static counter_t size_compressed = 0;

static counter_t vcd_lines_compressor = 0;
static counter_t vcd_lines_decompressor = 0;
static counter_t vcd_redlines_compressor = 0;
static counter_t vcd_redlines_decompressor = 0;

FILE *fp;

char last_dvcdbuf2[516] = "";
char last_dvcdbuf3[8] = "";

char last_vcdbuf2[516] = "";

////////////////////////////////////////////////////////////////
//sdrea-end

/* cache access macros */
#define CACHE_TAG(cp, addr)	((addr) >> (cp)->tag_shift)
#define CACHE_SET(cp, addr)	(((addr) >> (cp)->set_shift) & (cp)->set_mask)
#define CACHE_BLK(cp, addr)	((addr) & (cp)->blk_mask)
#define CACHE_TAGSET(cp, addr)	((addr) & (cp)->tagset_mask)

/* extract/reconstruct a block address */
#define CACHE_BADDR(cp, addr)	((addr) & ~(cp)->blk_mask)
#define CACHE_MK_BADDR(cp, tag, set)					\
  (((tag) << (cp)->tag_shift)|((set) << (cp)->set_shift))

/* index an array of cache blocks, non-trivial due to variable length blocks */
#define CACHE_BINDEX(cp, blks, i)					\
  ((struct cache_blk_t *)(((char *)(blks)) +				\
			  (i)*(sizeof(struct cache_blk_t) +		\
			       ((cp)->balloc				\
				? (cp)->bsize*sizeof(byte_t) : 0))))

/* cache data block accessor, type parameterized */
#define __CACHE_ACCESS(type, data, bofs)				\
  (*((type *)(((char *)data) + (bofs))))

/* cache data block accessors, by type */
#define CACHE_DOUBLE(data, bofs)  __CACHE_ACCESS(double, data, bofs)
#define CACHE_FLOAT(data, bofs)	  __CACHE_ACCESS(float, data, bofs)
#define CACHE_WORD(data, bofs)	  __CACHE_ACCESS(unsigned int, data, bofs)
#define CACHE_HALF(data, bofs)	  __CACHE_ACCESS(unsigned short, data, bofs)
#define CACHE_BYTE(data, bofs)	  __CACHE_ACCESS(unsigned char, data, bofs)

/* cache block hashing macros, this macro is used to index into a cache
   set hash table (to find the correct block on N in an N-way cache), the
   cache set index function is CACHE_SET, defined above */
#define CACHE_HASH(cp, key)						\
  (((key >> 24) ^ (key >> 16) ^ (key >> 8) ^ key) & ((cp)->hsize-1))

/* copy data out of a cache block to buffer indicated by argument pointer p */
#define CACHE_BCOPY(cmd, blk, bofs, p, nbytes)	\
  if (cmd == Read)							\
    {									\
      switch (nbytes) {							\
      case 1:								\
	*((byte_t *)p) = CACHE_BYTE(&blk->data[0], bofs); break;	\
      case 2:								\
	*((half_t *)p) = CACHE_HALF(&blk->data[0], bofs); break;	\
      case 4:								\
	*((word_t *)p) = CACHE_WORD(&blk->data[0], bofs); break;	\
      default:								\
	{ /* >= 8, power of two, fits in block */			\
	  int words = nbytes >> 2;					\
	  while (words-- > 0)						\
	    {								\
	      *((word_t *)p) = CACHE_WORD(&blk->data[0], bofs);	\
	      p += 4; bofs += 4;					\
	    }\
	}\
      }\
    }\
  else /* cmd == Write */						\
    {									\
      switch (nbytes) {							\
      case 1:								\
	CACHE_BYTE(&blk->data[0], bofs) = *((byte_t *)p); break;	\
      case 2:								\
        CACHE_HALF(&blk->data[0], bofs) = *((half_t *)p); break;	\
      case 4:								\
	CACHE_WORD(&blk->data[0], bofs) = *((word_t *)p); break;	\
      default:								\
	{ /* >= 8, power of two, fits in block */			\
	  int words = nbytes >> 2;					\
	  while (words-- > 0)						\
	    {								\
	      CACHE_WORD(&blk->data[0], bofs) = *((word_t *)p);		\
	      p += 4; bofs += 4;					\
	    }\
	}\
    }\
  }

/* bound sqword_t/dfloat_t to positive int */
#define BOUND_POS(N)		((int)(MIN(MAX(0, (N)), 2147483647)))

/* unlink BLK from the hash table bucket chain in SET */
static void
unlink_htab_ent(struct cache_t *cp,		/* cache to update */
		struct cache_set_t *set,	/* set containing bkt chain */
		struct cache_blk_t *blk)	/* block to unlink */
{
  struct cache_blk_t *prev, *ent;
  int index = CACHE_HASH(cp, blk->tag);

  /* locate the block in the hash table bucket chain */
  for (prev=NULL,ent=set->hash[index];
       ent;
       prev=ent,ent=ent->hash_next)
    {
      if (ent == blk)
	break;
    }
  assert(ent);

  /* unlink the block from the hash table bucket chain */
  if (!prev)
    {
      /* head of hash bucket list */
      set->hash[index] = ent->hash_next;
    }
  else
    {
      /* middle or end of hash bucket list */
      prev->hash_next = ent->hash_next;
    }
  ent->hash_next = NULL;
}

/* insert BLK onto the head of the hash table bucket chain in SET */
static void
link_htab_ent(struct cache_t *cp,		/* cache to update */
	      struct cache_set_t *set,		/* set containing bkt chain */
	      struct cache_blk_t *blk)		/* block to insert */
{
  int index = CACHE_HASH(cp, blk->tag);

  /* insert block onto the head of the bucket chain */
  blk->hash_next = set->hash[index];
  set->hash[index] = blk;
}

/* where to insert a block onto the ordered way chain */
enum list_loc_t { Head, Tail };

/* insert BLK into the order way chain in SET at location WHERE */
static void
update_way_list(struct cache_set_t *set,	/* set contained way chain */
		struct cache_blk_t *blk,	/* block to insert */
		enum list_loc_t where)		/* insert location */
{
  /* unlink entry from the way list */
  if (!blk->way_prev && !blk->way_next)
    {
      /* only one entry in list (direct-mapped), no action */
      assert(set->way_head == blk && set->way_tail == blk);
      /* Head/Tail order already */
      return;
    }
  /* else, more than one element in the list */
  else if (!blk->way_prev)
    {
      assert(set->way_head == blk && set->way_tail != blk);
      if (where == Head)
	{
	  /* already there */
	  return;
	}
      /* else, move to tail */
      set->way_head = blk->way_next;
      blk->way_next->way_prev = NULL;
    }
  else if (!blk->way_next)
    {
      /* end of list (and not front of list) */
      assert(set->way_head != blk && set->way_tail == blk);
      if (where == Tail)
	{
	  /* already there */
	  return;
	}
      set->way_tail = blk->way_prev;
      blk->way_prev->way_next = NULL;
    }
  else
    {
      /* middle of list (and not front or end of list) */
      assert(set->way_head != blk && set->way_tail != blk);
      blk->way_prev->way_next = blk->way_next;
      blk->way_next->way_prev = blk->way_prev;
    }

  /* link BLK back into the list */
  if (where == Head)
    {
      /* link to the head of the way list */
      blk->way_next = set->way_head;
      blk->way_prev = NULL;
      set->way_head->way_prev = blk;
      set->way_head = blk;
    }
  else if (where == Tail)
    {
      /* link to the tail of the way list */
      blk->way_prev = set->way_tail;
      blk->way_next = NULL;
      set->way_tail->way_next = blk;
      set->way_tail = blk;
    }
  else
    panic("bogus WHERE designator");
}

/* create and initialize a general cache structure */
struct cache_t *			/* pointer to cache created */
cache_create(char *name,		/* name of the cache */
	     int nsets,			/* total number of sets in cache */
	     int bsize,			/* block (line) size of cache */
	     int balloc,		/* allocate data space for blocks? */
	     int usize,			/* size of user data to alloc w/blks */
	     int assoc,			/* associativity of cache */
	     enum cache_policy policy,	/* replacement policy w/in sets */
	     /* block access function, see description w/in struct cache def */
	     unsigned int (*blk_access_fn)(enum mem_cmd cmd,
					   md_addr_t baddr, int bsize,
					   struct cache_blk_t *blk,
					   tick_t now),
	     unsigned int hit_latency)	/* latency in cycles for a hit */
{
  struct cache_t *cp;
  struct cache_blk_t *blk;
  int i, j, bindex;

  /* check all cache parameters */
  if (nsets <= 0)
    fatal("cache size (in sets) `%d' must be non-zero", nsets);
  if ((nsets & (nsets-1)) != 0)
    fatal("cache size (in sets) `%d' is not a power of two", nsets);
  /* blocks must be at least one datum large, i.e., 8 bytes for SS */
  if (bsize < 8)
    fatal("cache block size (in bytes) `%d' must be 8 or greater", bsize);
  if ((bsize & (bsize-1)) != 0)
    fatal("cache block size (in bytes) `%d' must be a power of two", bsize);
  if (usize < 0)
    fatal("user data size (in bytes) `%d' must be a positive value", usize);
  if (assoc <= 0)
    fatal("cache associativity `%d' must be non-zero and positive", assoc);
  if ((assoc & (assoc-1)) != 0)
    fatal("cache associativity `%d' must be a power of two", assoc);
  if (!blk_access_fn)
    fatal("must specify miss/replacement functions");

  /* allocate the cache structure */
  cp = (struct cache_t *)
    calloc(1, sizeof(struct cache_t) + (nsets-1)*sizeof(struct cache_set_t));
  if (!cp)
    fatal("out of virtual memory");

  /* initialize user parameters */
  cp->name = mystrdup(name);
  cp->nsets = nsets;
  cp->bsize = bsize;
  cp->balloc = balloc;
  cp->usize = usize;
  cp->assoc = assoc;
  cp->policy = policy;
  cp->hit_latency = hit_latency;

  /* miss/replacement functions */
  cp->blk_access_fn = blk_access_fn;

  /* compute derived parameters */
  cp->hsize = CACHE_HIGHLY_ASSOC(cp) ? (assoc >> 2) : 0;
  cp->blk_mask = bsize-1;
  cp->set_shift = log_base2(bsize);
  cp->set_mask = nsets-1;
  cp->tag_shift = cp->set_shift + log_base2(nsets);
  cp->tag_mask = (1 << (32 - cp->tag_shift))-1;
  cp->tagset_mask = ~cp->blk_mask;
  cp->bus_free = 0;

  /* print derived parameters during debug */
  debug("%s: cp->hsize     = %d", cp->name, cp->hsize);
  debug("%s: cp->blk_mask  = 0x%08x", cp->name, cp->blk_mask);
  debug("%s: cp->set_shift = %d", cp->name, cp->set_shift);
  debug("%s: cp->set_mask  = 0x%08x", cp->name, cp->set_mask);
  debug("%s: cp->tag_shift = %d", cp->name, cp->tag_shift);
  debug("%s: cp->tag_mask  = 0x%08x", cp->name, cp->tag_mask);

  /* initialize cache stats */
  cp->hits = 0;
  cp->misses = 0;
  cp->replacements = 0;
  cp->writebacks = 0;
  cp->invalidations = 0;

//sdrea-begin
////////////////////////////////////////////////////////////////

cp->bdi_check = 0;
cp->bdi_compress = 0;
cp->sim_tag_static_power = 0;
cp->sim_tag_read_dynamic_energy = 0;
cp->sim_tag_write_dynamic_energy = 0;
cp->sim_data_static_power = 0;
cp->sim_data_read_dynamic_energy = 0;
cp->sim_data_write_dynamic_energy = 0;
cp->last_cache_access = 0;

cp->compressed_hits = 0;
cp->last_compressed_size = 64;

////////////////////////////////////////////////////////////////
//sdrea-end

  /* blow away the last block accessed */
  cp->last_tagset = 0;
  cp->last_blk = NULL;

  /* allocate data blocks */
  cp->data = (byte_t *)calloc(nsets * assoc,
			      sizeof(struct cache_blk_t) +
			      (cp->balloc ? (bsize*sizeof(byte_t)) : 0));
  if (!cp->data)
    fatal("out of virtual memory");

  /* slice up the data blocks */
  for (bindex=0,i=0; i<nsets; i++)
    {
      cp->sets[i].way_head = NULL;
      cp->sets[i].way_tail = NULL;
      /* get a hash table, if needed */
      if (cp->hsize)
	{
	  cp->sets[i].hash =
	    (struct cache_blk_t **)calloc(cp->hsize,
					  sizeof(struct cache_blk_t *));
	  if (!cp->sets[i].hash)
	    fatal("out of virtual memory");
	}
      /* NOTE: all the blocks in a set *must* be allocated contiguously,
	 otherwise, block accesses through SET->BLKS will fail (used
	 during random replacement selection) */
      cp->sets[i].blks = CACHE_BINDEX(cp, cp->data, bindex);
      
      /* link the data blocks into ordered way chain and hash table bucket
         chains, if hash table exists */
      for (j=0; j<assoc; j++)
	{
	  /* locate next cache block */
	  blk = CACHE_BINDEX(cp, cp->data, bindex);
	  bindex++;

	  /* invalidate new cache block */
	  blk->status = 0;
	  blk->tag = 0;
	  blk->ready = 0;

//sdrea-begin
////////////////////////////////////////////////////////////////

	blk->bdi_encode = (byte_t) -1;
	blk->bdi_mask = (sword_t) -1;

////////////////////////////////////////////////////////////////
//sdrea-end

	  blk->user_data = (usize != 0
			    ? (byte_t *)calloc(usize, sizeof(byte_t)) : NULL);

	  /* insert cache block into set hash table */
	  if (cp->hsize)
	    link_htab_ent(cp, &cp->sets[i], blk);

	  /* insert into head of way list, order is arbitrary at this point */
	  blk->way_next = cp->sets[i].way_head;
	  blk->way_prev = NULL;
	  if (cp->sets[i].way_head)
	    cp->sets[i].way_head->way_prev = blk;
	  cp->sets[i].way_head = blk;
	  if (!cp->sets[i].way_tail)
	    cp->sets[i].way_tail = blk;
	}
    }
  return cp;
}

/* parse policy */
enum cache_policy			/* replacement policy enum */
cache_char2policy(char c)		/* replacement policy as a char */
{
  switch (c) {
  case 'l': return LRU;
  case 'r': return Random;
  case 'f': return FIFO;
  default: fatal("bogus replacement policy, `%c'", c);
  }
}

/* print cache configuration */
void
cache_config(struct cache_t *cp,	/* cache instance */
	     FILE *stream)		/* output stream */
{
  fprintf(stream,
	  "cache: %s: %d sets, %d byte blocks, %d bytes user data/block\n",
	  cp->name, cp->nsets, cp->bsize, cp->usize);
  fprintf(stream,
	  "cache: %s: %d-way, `%s' replacement policy, write-back\n",
	  cp->name, cp->assoc,
	  cp->policy == LRU ? "LRU"
	  : cp->policy == Random ? "Random"
	  : cp->policy == FIFO ? "FIFO"
	  : (abort(), ""));
}

/* register cache stats */
void
cache_reg_stats(struct cache_t *cp,	/* cache instance */
		struct stat_sdb_t *sdb)	/* stats database */
{

  char buf[512], buf1[512], *name;

  /* get a name for this cache */
  if (!cp->name || !cp->name[0])
    name = "<unknown>";
  else
    name = cp->name;

  sprintf(buf, "%s.accesses", name);
  sprintf(buf1, "%s.hits + %s.misses", name, name);
  stat_reg_formula(sdb, buf, "total number of accesses", buf1, "%12.0f");
  sprintf(buf, "%s.hits", name);
  stat_reg_counter(sdb, buf, "total number of hits", &cp->hits, 0, NULL);
  sprintf(buf, "%s.misses", name);
  stat_reg_counter(sdb, buf, "total number of misses", &cp->misses, 0, NULL);
  sprintf(buf, "%s.replacements", name);
  stat_reg_counter(sdb, buf, "total number of replacements",
		 &cp->replacements, 0, NULL);
  sprintf(buf, "%s.writebacks", name);
  stat_reg_counter(sdb, buf, "total number of writebacks",
		 &cp->writebacks, 0, NULL);
  sprintf(buf, "%s.invalidations", name);
  stat_reg_counter(sdb, buf, "total number of invalidations",
		 &cp->invalidations, 0, NULL);
  sprintf(buf, "%s.miss_rate", name);
  sprintf(buf1, "%s.misses / %s.accesses", name, name);
  stat_reg_formula(sdb, buf, "miss rate (i.e., misses/ref)", buf1, NULL);
  sprintf(buf, "%s.repl_rate", name);
  sprintf(buf1, "%s.replacements / %s.accesses", name, name);
  stat_reg_formula(sdb, buf, "replacement rate (i.e., repls/ref)", buf1, NULL);
  sprintf(buf, "%s.wb_rate", name);
  sprintf(buf1, "%s.writebacks / %s.accesses", name, name);
  stat_reg_formula(sdb, buf, "writeback rate (i.e., wrbks/ref)", buf1, NULL);
  sprintf(buf, "%s.inv_rate", name);
  sprintf(buf1, "%s.invalidations / %s.accesses", name, name);
  stat_reg_formula(sdb, buf, "invalidation rate (i.e., invs/ref)", buf1, NULL);

//sdrea-begin
////////////////////////////////////////////////////////////////

  sprintf(buf, "%s_sim_tag_static_power", name);
  sprintf(buf1, "%s Cache Tag Leakage Power (mW-cycles)", name);
  stat_reg_double(sdb, buf,
               buf1,
               &cp->sim_tag_static_power, 0, "%30.6f");

  sprintf(buf, "%s_sim_tag_read_dynamic_energy", name);
  sprintf(buf1, "%s Cache Tag Dynamic Read Energy (nJ)", name);
  stat_reg_double(sdb, buf,
               buf1,
               &cp->sim_tag_read_dynamic_energy, 0, "%23.6f");

  sprintf(buf, "%s_sim_tag_write_dynamic_energy", name);
  sprintf(buf1, "%s Cache Tag Dynamic Write Energy (nJ)", name);
  stat_reg_double(sdb, buf,
               buf1,
               &cp->sim_tag_write_dynamic_energy, 0, "%22.6f");

  sprintf(buf, "%s_sim_data_static_power", name);
  sprintf(buf1, "%s Cache Data Leakage Power (mW-cycles)", name);
  stat_reg_double(sdb, buf,
               buf1,
               &cp->sim_data_static_power, 0, "%29.6f");

  sprintf(buf, "%s_sim_data_read_dynamic_energy", name);
  sprintf(buf1, "%s Cache Data Dynamic Read Energy (nJ)", name);
  stat_reg_double(sdb, buf,
               buf1,
               &cp->sim_data_read_dynamic_energy, 0, "%22.6f");

  sprintf(buf, "%s_sim_data_write_dynamic_energy", name);
  sprintf(buf1, "%s Cache Data Dynamic Write Energy (nJ)", name);
  stat_reg_double(sdb, buf,
               buf1,
               &cp->sim_data_write_dynamic_energy, 0, "%21.6f");

if(cp->bdi_check)

{
stat_reg_counter(sdb, "count_check_lines", "Cache lines checked for compressibility", &count_check_lines, 0, "%32d");
stat_reg_counter(sdb, "count_compressible_any", "Count of cache lines compressible", &count_compressible_any, 0, "%32d");
stat_reg_counter(sdb, "count_compressible_0000_zeros", "Count of cache lines compressible as zeros", &count_compressible_0000_zeros, 0, "%25d");
stat_reg_counter(sdb, "count_compressible_0001_repeats", "Count of cache lines compressible as repeating values", &count_compressible_0001_repeats, 0, "%23d");
stat_reg_counter(sdb, "count_compressible_0010_b8d1", "Count of cache lines compressible as b8d1", &count_compressible_0010_b8d1, 0, "%26d");
stat_reg_counter(sdb, "count_compressible_0011_b8d2", "Count of cache lines compressible as b8d2", &count_compressible_0011_b8d2, 0, "%26d");
stat_reg_counter(sdb, "count_compressible_0100_b8d4", "Count of cache lines compressible as b8d4", &count_compressible_0100_b8d4, 0, "%26d");
stat_reg_counter(sdb, "count_compressible_0101_b4d1", "Count of cache lines compressible as b4d1", &count_compressible_0101_b4d1, 0, "%26d");
stat_reg_counter(sdb, "count_compressible_0110_b4d2", "Count of cache lines compressible as b4d2", &count_compressible_0110_b4d2, 0, "%26d");
stat_reg_counter(sdb, "count_compressible_0111_b2d1", "Count of cache lines compressible as b2d1", &count_compressible_0111_b2d1, 0, "%26d");
stat_reg_formula(sdb, "rate_compressible_any", "Percentage of cache lines compressible",     "100 * count_compressible_any / count_check_lines", "%32.1f");
stat_reg_formula(sdb, "rate_compressible_0000_zeros", "Percentage of cache lines compressible as zeros",     "100 * count_compressible_0000_zeros / count_check_lines", "%26.1f");
stat_reg_formula(sdb, "rate_compressible_0001_repeats", "Percentage of cache lines compressible as repeats", "100 * count_compressible_0001_repeats / count_check_lines", "%24.1f");
stat_reg_formula(sdb, "rate_compressible_0010_b8d1", "Percentage of cache lines compressible as b8d1",       "100 * count_compressible_0010_b8d1 / count_check_lines", "%27.1f");
stat_reg_formula(sdb, "rate_compressible_0011_b8d2", "Percentage of cache lines compressible as b8d2",       "100 * count_compressible_0011_b8d2 / count_check_lines", "%27.1f");
stat_reg_formula(sdb, "rate_compressible_0100_b8d4", "Percentage of cache lines compressible as b8d4",       "100 * count_compressible_0100_b8d4 / count_check_lines", "%27.1f");
stat_reg_formula(sdb, "rate_compressible_0101_b4d1", "Percentage of cache lines compressible as b4d1",       "100 * count_compressible_0101_b4d1 / count_check_lines", "%27.1f");
stat_reg_formula(sdb, "rate_compressible_0110_b4d2", "Percentage of cache lines compressible as b4d2",       "100 * count_compressible_0110_b4d2 / count_check_lines", "%27.1f");
stat_reg_formula(sdb, "rate_compressible_0111_b2d1", "Percentage of cache lines compressible as b2d1",       "100 * count_compressible_0111_b2d1 / count_check_lines", "%27.1f");
}


if(cp->bdi_compress)

{
stat_reg_counter(sdb, "count_encode_lines", "Cache lines checked for compression", &count_encode_lines, 0, "%32d");
stat_reg_counter(sdb, "count_encode_0000_zeros", "Cache blocks compressed as zeros", &count_encode_0000_zeros, 0, "%31d");
stat_reg_counter(sdb, "count_encode_0001_repeats", "Cache blocks compressed as repeating values", &count_encode_0001_repeats, 0, "%29d");
stat_reg_counter(sdb, "count_encode_0010_b8d1", "Cache blocks compressed as base 8 delta 1", &count_encode_0010_b8d1, 0, "%32d");
stat_reg_counter(sdb, "count_encode_0011_b8d2", "Cache blocks compressed as base 8 delta 2", &count_encode_0011_b8d2, 0,"%32d");
stat_reg_counter(sdb, "count_encode_0100_b8d4", "Cache blocks compressed as base 8 delta 4", &count_encode_0100_b8d4, 0, "%32d");
stat_reg_counter(sdb, "count_encode_0101_b4d1", "Cache blocks compressed as base 4 delta 1", &count_encode_0101_b4d1, 0, "%32d");
stat_reg_counter(sdb, "count_encode_0110_b4d2", "Cache blocks compressed as base 4 delta 2", &count_encode_0110_b4d2, 0, "%32d");
stat_reg_counter(sdb, "count_encode_0111_b2d1", "Cache blocks compressed as base 2 delta 1", &count_encode_0111_b2d1, 0, "%32d");
stat_reg_counter(sdb, "count_encode_1111_uncompressed", "Uncompressed cache lines", &count_encode_1111_uncompressed, 0, "%24d");
stat_reg_formula(sdb, "rate_encode_0000_zeros", "Percentage of cache lines compressed as zeros",     "100 * count_encode_0000_zeros / count_encode_lines", "%32.1f");
stat_reg_formula(sdb, "rate_encode_0001_repeats", "Percentage of cache lines compressed as repeats", "100 * count_encode_0001_repeats / count_encode_lines", "%30.1f");
stat_reg_formula(sdb, "rate_encode_0010_b8d1", "Percentage of cache lines compressed as b8d1",       "100 * count_encode_0010_b8d1 / count_encode_lines", "%32.1f");
stat_reg_formula(sdb, "rate_encode_0011_b8d2", "Percentage of cache lines compressed as b8d2",       "100 * count_encode_0011_b8d2 / count_encode_lines", "%32.1f");
stat_reg_formula(sdb, "rate_encode_0100_b8d4", "Percentage of cache lines compressed as b8d4",       "100 * count_encode_0100_b8d4 / count_encode_lines", "%32.1f");
stat_reg_formula(sdb, "rate_encode_0101_b4d1", "Percentage of cache lines compressed as b4d1",       "100 * count_encode_0101_b4d1 / count_encode_lines", "%32.1f");
stat_reg_formula(sdb, "rate_encode_0110_b4d2", "Percentage of cache lines compressed as b4d2",       "100 * count_encode_0110_b4d2 / count_encode_lines", "%32.1f");
stat_reg_formula(sdb, "rate_encode_0111_b2d1", "Percentage of cache lines compressed as b2d1",       "100 * count_encode_0111_b2d1 / count_encode_lines", "%32.1f");
stat_reg_counter(sdb, "size_compressed", "Size of compressed cache lines", &size_compressed, 0, "%32d");
stat_reg_counter(sdb, "size_uncompressed", "Size of uncompressed cache lines", &size_uncompressed, 0, "%32d");
stat_reg_formula(sdb, "compression_ratio", "Compression Ratio",       "size_uncompressed / size_compressed", "%32.5f");

stat_reg_counter(sdb, "vcd_lines_compressor", "Number of changes written to compressor VCD", &vcd_lines_compressor, 0, "%32d");
stat_reg_counter(sdb, "vcd_lines_decompressor", "Number of changes written to decompressor VCD", &vcd_lines_decompressor, 0, "%32d");

stat_reg_formula(sdb, "vcd_filesize_compressor", "Approximate VCD filesize for compressor in MB", "(vcd_lines_compressor+204) / 1925", "%31.3f");
stat_reg_formula(sdb, "vcd_filesize_decompressor", "Approximate VCD filesize for decompressor in MB", "(vcd_lines_decompressor+235) / 1900", "%29.3f");

stat_reg_counter(sdb, "vcd_redlines_compressor", "REDUCED: Number of changes written to compressor VCD", &vcd_redlines_compressor, 0, "%31d");
stat_reg_counter(sdb, "vcd_redlines_decompressor", "REDUCED: Number of changes written to decompressor VCD", &vcd_redlines_decompressor, 0, "%29d");

stat_reg_formula(sdb, "vcd_redfilesize_compressor", "REDUCED: Approximate VCD filesize for compressor in MB", "(vcd_redlines_compressor+204) / 1925", "%28.3f");
stat_reg_formula(sdb, "vcd_redfilesize_decompressor", "REDUCED: Approximate VCD filesize for decompressor in MB", "(vcd_redlines_decompressor+235) / 1900", "%26.3f");
}

////////////////////////////////////////////////////////////////
//sdrea-end

}

/* print cache stats */
void
cache_stats(struct cache_t *cp,		/* cache instance */
	    FILE *stream)		/* output stream */
{
  double sum = (double)(cp->hits + cp->misses);

  fprintf(stream,
	  "cache: %s: %.0f hits %.0f misses %.0f repls %.0f invalidations\n",
	  cp->name, (double)cp->hits, (double)cp->misses,
	  (double)cp->replacements, (double)cp->invalidations);
  fprintf(stream,
	  "cache: %s: miss rate=%f  repl rate=%f  invalidation rate=%f\n",
	  cp->name,
	  (double)cp->misses/sum, (double)(double)cp->replacements/sum,
	  (double)cp->invalidations/sum);
}

/* access a cache, perform a CMD operation on cache CP at address ADDR,
   places NBYTES of data at *P, returns latency of operation if initiated
   at NOW, places pointer to block user data in *UDATA, *P is untouched if
   cache blocks are not allocated (!CP->BALLOC), UDATA should be NULL if no
   user data is attached to blocks */
unsigned int				/* latency of access in cycles */
cache_access(struct cache_t *cp,	/* cache to access */
	     enum mem_cmd cmd,		/* access type, Read or Write */
	     md_addr_t addr,		/* address of access */
	     void *vp,			/* ptr to buffer for input/output */
	     int nbytes,		/* number of bytes to access */
	     tick_t now,		/* time of access */
	     byte_t **udata,		/* for return of user data ptr */

//sdrea-begin
////////////////////////////////////////////////////////////////

//	     md_addr_t *repl_addr)	/* for address of replaced block */

	     md_addr_t *repl_addr,	/* for address of replaced block */
	     char *cbuf,
	     char *dbuf,
             struct mem_t *mem)

////////////////////////////////////////////////////////////////
//sdrea-end

{
  byte_t *p = vp;
  md_addr_t tag = CACHE_TAG(cp, addr);
  md_addr_t set = CACHE_SET(cp, addr);
  md_addr_t bofs = CACHE_BLK(cp, addr);
  struct cache_blk_t *blk, *repl;
  int lat = 0;

//sdrea-begin
////////////////////////////////////////////////////////////////

  bool_t zeros = 1, repeats = 1, delta81 = 1, delta82 = 1, delta84 = 1, delta41 = 1, delta42 = 1, delta21 = 1;
  qword_t delta81mask = -1, delta82mask = -1, delta84mask = -1, delta41mask = -1, delta42mask = -1, delta21mask = -1;
  signed long long db[64], db8[64];
  signed long db4[64];
  signed short db2[64];
  char vcddb[64];
  int i, j;
  int bdi_size = 64;

  byte_t bdi_encode = -1;
  qword_t bdi_mask = -1;

////////////////////////////////////////////////////////////////
//sdrea-end

  /* default replacement address */
  if (repl_addr)
    *repl_addr = 0;

  /* check alignments */
  if ((nbytes & (nbytes-1)) != 0 || (addr & (nbytes-1)) != 0)
    fatal("cache: access error: bad size or alignment, addr 0x%08x", addr);

  /* access must fit in cache block */
  /* FIXME:
     ((addr + (nbytes - 1)) > ((addr & ~cp->blk_mask) + (cp->bsize - 1))) */
  if ((addr + nbytes) > ((addr & ~cp->blk_mask) + cp->bsize))
    fatal("cache: access error: access spans block, addr 0x%08x", addr);

  /* permissions are checked on cache misses */

  /* check for a fast hit: access to same block */
  if (CACHE_TAGSET(cp, addr) == cp->last_tagset)
    {
      /* hit in the same block */
      blk = cp->last_blk;
      goto cache_fast_hit;
    }
    
  if (cp->hsize)
    {
      /* higly-associativity cache, access through the per-set hash tables */
      int hindex = CACHE_HASH(cp, tag);

      for (blk=cp->sets[set].hash[hindex];
	   blk;
	   blk=blk->hash_next)
	{
	  if (blk->tag == tag && (blk->status & CACHE_BLK_VALID))
	    goto cache_hit;
	}
    }
  else
    {
      /* low-associativity cache, linear search the way list */
      for (blk=cp->sets[set].way_head;
	   blk;
	   blk=blk->way_next)
	{
	  if (blk->tag == tag && (blk->status & CACHE_BLK_VALID))
	    goto cache_hit;
	}
    }

  /* cache block not found */

  /* **MISS** */
  cp->misses++;

//sdrea-begin
////////////////////////////////////////////////////////////////

  if (mem != NULL)
    {

        for (i = 0; i < 64; i++)
          {
            db[i] = 0;
            vcddb[i] = 0;
            db8[i] = 0;
            db4[i] = 0;
            db2[i] = 0;
          }

        for (i = 0; i < cp->bsize; i++)
          {
            vcddb[i]  = MEM_READ_BYTE(mem, addr - bofs + i);
            db[i]  = MEM_READ_BYTE(mem, addr - bofs + i);
            db8[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            db4[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            db2[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            if (db[i] != 0) zeros = 0;
          }

        for (i = 0; i < cp->bsize; i+=8)
          {
            db8[i] += db8[i+1] <<  8;
            db8[i] += db8[i+2] << 16;
            db8[i] += db8[i+3] << 24;
            db8[i] += db8[i+4] << 32;
            db8[i] += db8[i+5] << 40;
            db8[i] += db8[i+6] << 48;
            db8[i] += db8[i+7] << 56;

            if (db8[i] != db8[0]) repeats = 0;
            if ( ( ( db8[i] - db8[0] < (signed char)        -128 ) || ( db8[i] - db8[0] > (signed char)        127 ) ) && ( ( db8[i] < (signed char)        -128 ) || ( db8[i] > (signed char)        127 ) ) ) delta81 = 0;
            if ( ( ( db8[i] - db8[0] < (signed short)     -32768 ) || ( db8[i] - db8[0] > (signed short)     32767 ) ) && ( ( db8[i] < (signed short)     -32768 ) || ( db8[i] > (signed short)     32767 ) ) ) delta82 = 0;
            if ( ( ( db8[i] - db8[0] < (signed long) -2147483648 ) || ( db8[i] - db8[0] > (signed long) 2147483647 ) ) && ( ( db8[i] < (signed long) -2147483648 ) || ( db8[i] > (signed long) 2147483647 ) ) ) delta84 = 0;
            if ( ( ( db8[i] - db8[0] < (signed char)        -128 ) || ( db8[i] - db8[0] > (signed char)        127 ) ) && delta81 == 1 ) delta81mask = delta81mask & ~((qword_t) 255 << i); // immediate value was used
            if ( ( ( db8[i] - db8[0] < (signed short)     -32768 ) || ( db8[i] - db8[0] > (signed short)     32767 ) ) && delta82 == 1 ) delta82mask = delta82mask & ~((qword_t) 255 << i); // immediate value was used
            if ( ( ( db8[i] - db8[0] < (signed long) -2147483648 ) || ( db8[i] - db8[0] > (signed long) 2147483647 ) ) && delta84 == 1 ) delta84mask = delta84mask & ~((qword_t) 255 << i); // immediate value was used

          }

        for (i = 0; i < cp->bsize; i+=4)
          {
            db4[i] += db4[i+1] <<  8;
            db4[i] += db4[i+2] << 16;
            db4[i] += db4[i+3] << 24;

            if ( ( ( db4[i] - db4[0] < (signed char)    -128 ) || ( db4[i] - db4[0] > (signed char)    127 ) ) && ( ( db4[i] < (signed char)    -128 ) || ( db4[i] > (signed char)    127 ) ) ) delta41 = 0;
            if ( ( ( db4[i] - db4[0] < (signed short) -32768 ) || ( db4[i] - db4[0] > (signed short) 32767 ) ) && ( ( db4[i] < (signed short) -32768 ) || ( db4[i] > (signed short) 32767 ) ) ) delta42 = 0;
            if ( ( ( db4[i] - db4[0] < (signed char)    -128 ) || ( db4[i] - db4[0] > (signed char)    127 ) ) && delta41 == 1 ) delta41mask = delta41mask & ~((qword_t) 15 << i); // immediate value was used
            if ( ( ( db4[i] - db4[0] < (signed short) -32768 ) || ( db4[i] - db4[0] > (signed short) 32767 ) ) && delta42 == 1 ) delta42mask = delta42mask & ~((qword_t) 15 << i); // immediate value was used

          }

        for (i = 0; i < cp->bsize; i+=2)
          {
            db2[i] += db2[i+1] <<  8;

            if ( ( ( db2[i] - db2[0] < (signed char) -128 ) || ( db2[i] - db2[0] > (signed char) 127 ) ) && ( ( db2[i] < (signed char) -128 ) || ( db2[i] > (signed char) 127 ) ) ) delta21 = 0;
            if ( ( ( db2[i] - db2[0] < (signed char) -128 ) || ( db2[i] - db2[0] > (signed char) 127 ) ) && delta21 == 1 ) delta21mask = delta21mask & ~((qword_t) 3 << i); // immediate value was used

          }

          if (cp->bdi_compress) 
            {

              if (zeros == 1)         { bdi_encode = 0; bdi_mask = -1; }
              else if (repeats == 1)  { bdi_encode = 1; bdi_mask = -1;}
              else if (delta81 == 1)  { bdi_encode = 2; bdi_mask = delta81mask;}
              else if (delta41 == 1)  { bdi_encode = 5; bdi_mask = delta41mask;}
              else if (delta82 == 1)  { bdi_encode = 3; bdi_mask = delta82mask;}
              else if (delta21 == 1)  { bdi_encode = 7; bdi_mask = delta21mask;}
              else if (delta42 == 1)  { bdi_encode = 6; bdi_mask = delta42mask;}
              else if (delta84 == 1)  { bdi_encode = 4; bdi_mask = delta84mask;}
              else                    { bdi_encode = 15; bdi_mask = -1;}

            }

          if (cp->bdi_check)
            {

	      count_check_lines++;

              if (zeros == 1)    { count_compressible_0000_zeros++;}
              if (repeats == 1)  { count_compressible_0001_repeats++;}
              if (delta81 == 1)  { count_compressible_0010_b8d1++;}
              if (delta82 == 1)  { count_compressible_0011_b8d2++;}
              if (delta84 == 1)  { count_compressible_0100_b8d4++;}
              if (delta41 == 1)  { count_compressible_0101_b4d1++;}
              if (delta42 == 1)  { count_compressible_0110_b4d2++;}
              if (delta21 == 1)  { count_compressible_0111_b2d1++;}
              if (zeros == 1 || repeats == 1 || delta81 == 1 || delta82 == 1 || delta84 == 1 || delta41 == 1 || delta42 == 1 || delta21 == 1) {count_compressible_any++;}
            }


  if (cp->bdi_compress)
    {

      count_encode_lines++;

      switch (bdi_encode)
        {
          case 0:
            //zeros
            count_encode_0000_zeros++;
            bdi_size = 8; // 1 segment, 8 bytes
          break;
          case 1:
            //repeats
            count_encode_0001_repeats++;
            bdi_size = 8; // 1 segment, 8 bytes
          break;
          case 2:
            //base 8 delta 1
            count_encode_0010_b8d1++;
            bdi_size = 16; // 2 segments, 16 bytes
          break;
          case 3:
            //base 8 delta 2
            count_encode_0011_b8d2++;
            bdi_size = 24; // 3 segments, 24 bytes
          break;
          case 4:
            //base 8 delta 4
            count_encode_0100_b8d4++;
            bdi_size = 40; // 5 segments, 40 bytes
          break;
          case 5:
            //base 4 delta 1
            count_encode_0101_b4d1++;
            bdi_size = 24; // 3 segments, 24 bytes
          break;
          case 6:
            //base 4 delta 2
            count_encode_0110_b4d2++;
            bdi_size = 40; // 5 segments, 40 bytes
          break;
          case 7:
            //base 2 delta 1
            count_encode_0111_b2d1++;
            bdi_size = 40; // 5 segments, 40 bytes
          break;
          case 15:
            //decompressed
            count_encode_1111_uncompressed++;
            bdi_size = 64; // 8 segments, 64 bytes
          break;
        }

    size_uncompressed += 64;
    size_compressed += bdi_size;

      struct cache_blk_t *bdi_blk1, *bdi_blk2;

      int bdi_blk_size;

      bdi_blk_size=0;

      for (bdi_blk2=cp->sets[set].way_head; bdi_blk2; bdi_blk2=bdi_blk2->way_next)
        {
          switch (bdi_blk2->bdi_encode)
            {
              case 0:
                //zeros
                bdi_blk_size += 8; // 1 segment, 8 bytes
              break;
              case 1:
                //repeats
                bdi_blk_size += 8; // 1 segment, 8 bytes
              break;
              case 2:
                //base 8 delta 1
                bdi_blk_size += 16; // 2 segments, 16 bytes
              break;
              case 3:
                //base 8 delta 2
                bdi_blk_size += 24; // 3 segments, 24 bytes
              break;
              case 4:
                //base 8 delta 4
                bdi_blk_size += 40; // 5 segments, 40 bytes
              break;
              case 5:
                //base 4 delta 1
                bdi_blk_size += 24; // 3 segments, 24 bytes
              break;
              case 6:
                //base 4 delta 2
                bdi_blk_size += 40; // 5 segments, 40 bytes
              break;
              case 7:
                //base 2 delta 1
                bdi_blk_size += 40; // 5 segments, 40 bytes
              break;
              case 15:
                //decompressed
                bdi_blk_size += 64; // 8 segments, 64 bytes
              break;
            }
        }

      if (bdi_size + bdi_blk_size > cp->bsize * cp->assoc / 2) {

        // todo
        // compressed cache size is about to change.
        // calc weighted cache size (bdi_blk_size * (now - cp->last_compression_change))

      }

      for (bdi_blk1=cp->sets[set].way_tail; bdi_blk1 && (bdi_size + bdi_blk_size > cp->bsize * cp->assoc / 2); bdi_blk1=bdi_blk1->way_prev)
        {

          //invalidate from tail up until there is room

	  bdi_blk1->status = 0;
          bdi_blk1->tag = 0;
          bdi_blk1->ready = 0;
	  bdi_blk1->bdi_encode = (byte_t) -1;
	  bdi_blk1->bdi_mask = (sword_t) -1; 

          bdi_blk_size=0;

          for (bdi_blk2=cp->sets[set].way_head; bdi_blk2; bdi_blk2=bdi_blk2->way_next)
            {
              switch (bdi_blk2->bdi_encode) 
                {
                  case 0:
                    //zeros
                    bdi_blk_size += 8; // 1 segment, 8 bytes
                  break;
                  case 1:
                    //repeats
                    bdi_blk_size += 8; // 1 segment, 8 bytes
                  break;
                  case 2:
                    //base 8 delta 1
                    bdi_blk_size += 16; // 2 segments, 16 bytes
                  break;
                  case 3:
                    //base 8 delta 2
                    bdi_blk_size += 24; // 3 segments, 24 bytes
                  break;
                  case 4:
                    //base 8 delta 4
                    bdi_blk_size += 40; // 5 segments, 40 bytes
                  break;
                  case 5:
                    //base 4 delta 1
                    bdi_blk_size += 24; // 3 segments, 24 bytes
                  break;
                  case 6:
                    //base 4 delta 2
                    bdi_blk_size += 40; // 5 segments, 40 bytes
                  break;
                  case 7:
                    //base 2 delta 1
                    bdi_blk_size += 40; // 5 segments, 40 bytes
                  break;
                  case 15:
                    //decompressed
                    bdi_blk_size += 64; // 8 segments, 64 bytes
                  break;
                  default:
                    //no data in the "way"
                    bdi_blk_size += 0; // unused way
                  break;
                }
            }
        }
    }

  // Static energy is updated every cache access, regardless of operation and hit result  

  cp->sim_tag_static_power += (now - cp->last_cache_access) * cp->cacti_tag_static_power;
  cp->sim_data_static_power += (now - cp->last_cache_access) * cp->cacti_data_static_power;

  // On cache miss, tag read will occur for read and write operation

  cp->sim_tag_read_dynamic_energy += cp->cacti_tag_read_dynamic_energy;

  // On cache miss, read operation, there will be 1 tag write, 1 data write, 0 data read

  if (cmd == Read) {
                     cp->sim_tag_write_dynamic_energy += cp->cacti_tag_write_dynamic_energy;
                     cp->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cacti_data_write_dynamic_energy;
                   }

  // On cache miss, write operation, there will be 1 tag write (plus a dirty bit write), 1 data write, 0 data reads

  if (cmd == Write) {
                      cp->sim_tag_write_dynamic_energy += cp->cacti_tag_write_dynamic_energy;
                      cp->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cacti_data_write_dynamic_energy;
                      // todo - dirty bit
                    }

  cp->last_cache_access = now;

  char vcdbuf1[32];
  sprintf(vcdbuf1, "#%d", cp->compressor_frequency*now);

  char vcdbuf2[516];
  vcdbuf2[0] = 'b';
  vcdbuf2[513] = ' ';
  vcdbuf2[514] = '!';
  vcdbuf2[515] = '\0';

  for (i = 0; i < 64; i++) {
  for (j = 0; j < 8; j++) {
        vcdbuf2[504-(i*8)+8-j]  = (vcddb[i] & 1) + '0';
        vcddb[i] >>= 1;
  }}

  if ( strcmp(last_vcdbuf2,vcdbuf2) ) {

  if  ( cbuf[0] != '\0' ) {
  fp = fopen(cbuf, "a");
  fprintf(fp, vcdbuf1);
  fprintf(fp, "\n");
  fprintf(fp, vcdbuf2);
  fprintf(fp, "\n");
  fclose(fp);
  }

  vcd_redlines_compressor++;
  }

  vcd_lines_compressor++;
  strcpy(last_vcdbuf2, vcdbuf2);

}
else
{

// mem is null in cache_access call

}

////////////////////////////////////////////////////////////////
//sdrea-end

  /* select the appropriate block to replace, and re-link this entry to
     the appropriate place in the way list */
  switch (cp->policy) {
  case LRU:
  case FIFO:
    repl = cp->sets[set].way_tail;
    update_way_list(&cp->sets[set], repl, Head);
    break;
  case Random:
    {
      int bindex = myrand() & (cp->assoc - 1);
      repl = CACHE_BINDEX(cp, cp->sets[set].blks, bindex);
    }
    break;
  default:
    panic("bogus replacement policy");
  }

  /* remove this block from the hash bucket chain, if hash exists */
  if (cp->hsize)
    unlink_htab_ent(cp, &cp->sets[set], repl);

  /* blow away the last block to hit */
  cp->last_tagset = 0;
  cp->last_blk = NULL;

  /* write back replaced block data */
  if (repl->status & CACHE_BLK_VALID)
    {
      cp->replacements++;

      if (repl_addr)
	*repl_addr = CACHE_MK_BADDR(cp, repl->tag, set);
 
      /* don't replace the block until outstanding misses are satisfied */
      lat += BOUND_POS(repl->ready - now);
 
      /* stall until the bus to next level of memory is available */
      lat += BOUND_POS(cp->bus_free - (now + lat));
 
      /* track bus resource usage */
      cp->bus_free = MAX(cp->bus_free, (now + lat)) + 1;

      if (repl->status & CACHE_BLK_DIRTY)
	{
	  /* write back the cache block */
	  cp->writebacks++;
	  lat += cp->blk_access_fn(Write,
				   CACHE_MK_BADDR(cp, repl->tag, set),
				   cp->bsize, repl, now+lat);
	}
    }

  /* update block tags */
  repl->tag = tag;
  repl->status = CACHE_BLK_VALID;	/* dirty bit set on update */

//sdrea-begin
////////////////////////////////////////////////////////////////

  repl->bdi_encode = bdi_encode;
  repl->bdi_mask = bdi_mask;

////////////////////////////////////////////////////////////////
//sdrea-end

  /* read data block */
  lat += cp->blk_access_fn(Read, CACHE_BADDR(cp, addr), cp->bsize,
			   repl, now+lat);

  /* copy data out of cache block */
  if (cp->balloc)
    {
      CACHE_BCOPY(cmd, repl, bofs, p, nbytes);
    }

  /* update dirty status */
  if (cmd == Write)
    repl->status |= CACHE_BLK_DIRTY;

  /* get user block data, if requested and it exists */
  if (udata)
    *udata = repl->user_data;

  /* update block status */
  repl->ready = now+lat;

  /* link this entry back into the hash table */
  if (cp->hsize)
    link_htab_ent(cp, &cp->sets[set], repl);

  /* return latency of the operation */
  return lat;


 cache_hit: /* slow hit handler */
  
  /* **HIT** */
  cp->hits++;


//sdrea-begin
////////////////////////////////////////////////////////////////

if (mem != NULL)
    {
        for (i = 0; i < 64; i++)
          {
            vcddb[i] = 0;
	    db[i] = 0;
            db8[i] = 0;
            db4[i] = 0;
            db2[i] = 0;
          }

        for (i = 0; i < 64; i++)
          {
            db[i] = MEM_READ_BYTE(mem, addr - bofs + i);
	    db8[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            db4[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            db2[i] = MEM_READ_BYTE(mem, addr - bofs + i);
          }

        for (i = 0; i < 64; i+=8)
          {
            db8[i] += db8[i+1] <<  8;
            db8[i] += db8[i+2] << 16;
            db8[i] += db8[i+3] << 24;
            db8[i] += db8[i+4] << 32;
            db8[i] += db8[i+5] << 40;
            db8[i] += db8[i+6] << 48;
            db8[i] += db8[i+7] << 56;
          }

        for (i = 0; i < 64; i+=4)
          {
            db4[i] += db4[i+1] <<  8;
            db4[i] += db4[i+2] << 16;
            db4[i] += db4[i+3] << 24;
          }

        for (i = 0; i < 64; i+=2)
          {
            db2[i] += db2[i+1] <<  8;
          }

  // need bdi size
      switch (blk->bdi_encode)
        {
          case 0:
            //zeros
            bdi_size = 8; // 1 segment, 8 bytes
          break;
          case 1:
            //repeats
            bdi_size = 8; // 1 segment, 8 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
          break;
          case 2:
            //base 8 delta 1
            bdi_size = 16; // 2 segments, 16 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[8] = ((blk->bdi_mask) & (1<<0)) ? (signed char) db8[0]-db8[0] : (signed char) db8[0];
                vcddb[9] = ((blk->bdi_mask) & (1<<8)) ? (signed char) db8[8]-db8[0] : (signed char) db8[8];
                vcddb[10] = ((blk->bdi_mask) & (1<<16)) ? (signed char) db8[16]-db8[0] : (signed char) db8[16];
                vcddb[11] = ((blk->bdi_mask) & (1<<24)) ? (signed char) db8[24]-db8[0] : (signed char) db8[24];
                vcddb[12] = ((blk->bdi_mask) & (1<<32)) ? (signed char) db8[32]-db8[0] : (signed char) db8[32];
                vcddb[13] = ((blk->bdi_mask) & (1<<40)) ? (signed char) db8[40]-db8[0] : (signed char) db8[40];
                vcddb[14] = ((blk->bdi_mask) & (1<<48)) ? (signed char) db8[48]-db8[0] : (signed char) db8[48];
                vcddb[15] = ((blk->bdi_mask) & (1<<56)) ? (signed char) db8[56]-db8[0] : (signed char) db8[56];
          break;
          case 3:
            //base 8 delta 2
            bdi_size = 24; // 3 segments, 24 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[8] =  (((blk->bdi_mask) & (1<<0)) ? (signed short) db8[0]-db8[0] : (signed short) db8[0]) &  255;
                vcddb[9] =  ((((blk->bdi_mask) & (1<<0)) ? (signed short) db8[0]-db8[0] : (signed short) db8[0]) & -256) >> 8;
                vcddb[10] = (((blk->bdi_mask) & (1<<8)) ? (signed short) db8[8]-db8[0] : (signed short) db8[8]) &  255;
                vcddb[11] = ((((blk->bdi_mask) & (1<<8)) ? (signed short) db8[8]-db8[0] : (signed short) db8[8]) & -256) >> 8;
                vcddb[12] = (((blk->bdi_mask) & (1<<16)) ? (signed short) db8[16]-db8[0] : (signed short) db8[16]) &  255;
                vcddb[13] = ((((blk->bdi_mask) & (1<<16)) ? (signed short) db8[16]-db8[0] : (signed short) db8[16]) &  -256) >> 8;
                vcddb[14] = (((blk->bdi_mask) & (1<<24)) ? (signed short) db8[24]-db8[0] : (signed short) db8[24]) &  255;
                vcddb[15] = ((((blk->bdi_mask) & (1<<24)) ? (signed short) db8[24]-db8[0] : (signed short) db8[24]) &  -256) >> 8;
                vcddb[16] = (((blk->bdi_mask) & (1<<32)) ? (signed short) db8[32]-db8[0] : (signed short) db8[32]) &  255;
                vcddb[17] = ((((blk->bdi_mask) & (1<<32)) ? (signed short) db8[32]-db8[0] : (signed short) db8[32]) &  -256) >> 8;
                vcddb[18] = (((blk->bdi_mask) & (1<<40)) ? (signed short) db8[40]-db8[0] : (signed short) db8[40]) &  255;
                vcddb[19] = ((((blk->bdi_mask) & (1<<40)) ? (signed short) db8[40]-db8[0] : (signed short) db8[40]) &  -256) >> 8;
                vcddb[20] = (((blk->bdi_mask) & (1<<48)) ? (signed short) db8[48]-db8[0] : (signed short) db8[48]) &  255;
                vcddb[21] = ((((blk->bdi_mask) & (1<<48)) ? (signed short) db8[48]-db8[0] : (signed short) db8[48]) &  -256) >> 8;
                vcddb[22] = (((blk->bdi_mask) & (1<<56)) ? (signed short) db8[56]-db8[0] : (signed short) db8[56]) &  255;
                vcddb[23] = ((((blk->bdi_mask) & (1<<56)) ? (signed short) db8[56]-db8[0] : (signed short) db8[56]) &  -256) >> 8;
          break;
          case 4:
            //base 8 delta 4
            bdi_size = 40; // 5 segments, 40 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[8] =  (((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) & 255;
                vcddb[9] =  ((((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) & 65280) >> 8;
                vcddb[10] =  ((((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) &  16711680) >> 16;
                vcddb[11] =  ((((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) & -16777216) >> 24;
                vcddb[12] =  (((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) & 255;
                vcddb[13] =  ((((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) & 65280) >> 8;
                vcddb[14] =  ((((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) &  16711680) >> 16;
                vcddb[15] =  ((((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) & -16777216) >> 24;
                vcddb[16] =  (((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) & 255;
                vcddb[17] =  ((((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) & 65280) >> 8;
                vcddb[18] =  ((((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) &  16711680) >> 16;
                vcddb[19] =  ((((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) & -16777216) >> 24;
                vcddb[20] =  (((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) & 255;
                vcddb[21] =  ((((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) & 65280) >> 8;
                vcddb[22] =  ((((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) &  16711680) >> 16;
                vcddb[23] =  ((((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) & -16777216) >> 24;
                vcddb[24] =  (((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) & 255;
                vcddb[25] =  ((((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) & 65280) >> 8;
                vcddb[26] =  ((((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) &  16711680) >> 16;
                vcddb[27] =  ((((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) & -16777216) >> 24;
                vcddb[28] =  (((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) & 255;
                vcddb[29] =  ((((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) & 65280) >> 8;
                vcddb[30] =  ((((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) &  16711680) >> 16;
                vcddb[31] =  ((((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) & -16777216) >> 24;
                vcddb[32] =  (((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) & 255;
                vcddb[33] =  ((((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) & 65280) >> 8;
                vcddb[34] =  ((((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) &  16711680) >> 16;
                vcddb[35] =  ((((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) & -16777216) >> 24;
                vcddb[36] =  (((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) & 255;
                vcddb[37] =  ((((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) & 65280) >> 8;
                vcddb[38] =  ((((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) &  16711680) >> 16;
                vcddb[39] =  ((((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) & -16777216) >> 24;

          break;
          case 5:
            //base 4 delta 1
            bdi_size = 24; // 3 segments, 24 bytes
	    for (i = 0; i < 4; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[4] = ((blk->bdi_mask) & (1<<0)) ? (signed char) db4[0]-db4[0] : (signed char) db4[0];
                vcddb[5] = ((blk->bdi_mask) & (1<<4)) ? (signed char) db4[4]-db4[0] : (signed char) db4[4];
                vcddb[6] = ((blk->bdi_mask) & (1<<8)) ? (signed char) db4[8]-db4[0] : (signed char) db4[8];
                vcddb[7] = ((blk->bdi_mask) & (1<<12)) ? (signed char) db4[12]-db4[0] : (signed char) db4[12];
                vcddb[8] = ((blk->bdi_mask) & (1<<16)) ? (signed char) db4[16]-db4[0] : (signed char) db4[16];
                vcddb[9] = ((blk->bdi_mask) & (1<<20)) ? (signed char) db4[20]-db4[0] : (signed char) db4[20];
                vcddb[10] = ((blk->bdi_mask) & (1<<24)) ? (signed char) db4[24]-db4[0] : (signed char) db4[24];
                vcddb[11] = ((blk->bdi_mask) & (1<<28)) ? (signed char) db4[28]-db4[0] : (signed char) db4[28];
                vcddb[12] = ((blk->bdi_mask) & (1<<32)) ? (signed char) db4[32]-db4[0] : (signed char) db4[32];
                vcddb[13] = ((blk->bdi_mask) & (1<<36)) ? (signed char) db4[36]-db4[0] : (signed char) db4[36];
                vcddb[14] = ((blk->bdi_mask) & (1<<40)) ? (signed char) db4[40]-db4[0] : (signed char) db4[40];
                vcddb[15] = ((blk->bdi_mask) & (1<<44)) ? (signed char) db4[44]-db4[0] : (signed char) db4[44];
                vcddb[16] = ((blk->bdi_mask) & (1<<48)) ? (signed char) db4[48]-db4[0] : (signed char) db4[48];
                vcddb[17] = ((blk->bdi_mask) & (1<<52)) ? (signed char) db4[52]-db4[0] : (signed char) db4[52];
                vcddb[18] = ((blk->bdi_mask) & (1<<56)) ? (signed char) db4[56]-db4[0] : (signed char) db4[56];
                vcddb[19] = ((blk->bdi_mask) & (1<<60)) ? (signed char) db4[60]-db4[0] : (signed char) db4[60];

          break;
          case 6:
            //base 4 delta 2
            bdi_size = 40; // 5 segments, 40 bytes
	    for (i = 0; i < 4; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[4] = (((blk->bdi_mask) & (1<<0)) ? (signed short) db4[0]-db4[0] : (signed short) db4[0]) & 255;
                vcddb[5] = ((((blk->bdi_mask) & (1<<0)) ? (signed short) db4[0]-db4[0] : (signed short) db4[0]) & -256) >> 8;
                vcddb[6] = (((blk->bdi_mask) & (1<<4)) ? (signed short) db4[4]-db4[0] : (signed short) db4[4]) & 255;
                vcddb[7] = ((((blk->bdi_mask) & (1<<4)) ? (signed short) db4[4]-db4[0] : (signed short) db4[4]) & -256) >> 8;
                vcddb[8] = (((blk->bdi_mask) & (1<<8)) ? (signed short) db4[8]-db4[0] : (signed short) db4[8]) & 255;
                vcddb[9] = ((((blk->bdi_mask) & (1<<8)) ? (signed short) db4[8]-db4[0] : (signed short) db4[8]) & -256) >> 8;
                vcddb[10] = (((blk->bdi_mask) & (1<<12)) ? (signed short) db4[12]-db4[0] : (signed short) db4[12]) & 255;
                vcddb[11] = ((((blk->bdi_mask) & (1<<12)) ? (signed short) db4[12]-db4[0] : (signed short) db4[12]) & -256) >> 8;
                vcddb[12] = (((blk->bdi_mask) & (1<<16)) ? (signed short) db4[16]-db4[0] : (signed short) db4[16]) & 255;
                vcddb[13] = ((((blk->bdi_mask) & (1<<16)) ? (signed short) db4[16]-db4[0] : (signed short) db4[16]) & -256) >> 8;
                vcddb[14] = (((blk->bdi_mask) & (1<<20)) ? (signed short) db4[20]-db4[0] : (signed short) db4[20]) & 255;
                vcddb[15] = ((((blk->bdi_mask) & (1<<20)) ? (signed short) db4[20]-db4[0] : (signed short) db4[20]) & -256) >> 8;
                vcddb[16] = (((blk->bdi_mask) & (1<<24)) ? (signed short) db4[24]-db4[0] : (signed short) db4[24]) & 255;
                vcddb[17] = ((((blk->bdi_mask) & (1<<24)) ? (signed short) db4[24]-db4[0] : (signed short) db4[24]) & -256) >> 8;
                vcddb[18] = (((blk->bdi_mask) & (1<<28)) ? (signed short) db4[28]-db4[0] : (signed short) db4[28]) & 255;
                vcddb[19] = ((((blk->bdi_mask) & (1<<28)) ? (signed short) db4[28]-db4[0] : (signed short) db4[28]) & -256) >> 8;
                vcddb[20] = (((blk->bdi_mask) & (1<<32)) ? (signed short) db4[32]-db4[0] : (signed short) db4[32]) & 255;
                vcddb[21] = ((((blk->bdi_mask) & (1<<32)) ? (signed short) db4[32]-db4[0] : (signed short) db4[32]) & -256) >> 8;
                vcddb[22] = (((blk->bdi_mask) & (1<<36)) ? (signed short) db4[36]-db4[0] : (signed short) db4[36]) & 255;
                vcddb[23] = ((((blk->bdi_mask) & (1<<36)) ? (signed short) db4[36]-db4[0] : (signed short) db4[36]) & -256) >> 8;
                vcddb[24] = (((blk->bdi_mask) & (1<<40)) ? (signed short) db4[40]-db4[0] : (signed short) db4[40]) & 255;
                vcddb[25] = ((((blk->bdi_mask) & (1<<40)) ? (signed short) db4[40]-db4[0] : (signed short) db4[40]) & -256) >> 8;
                vcddb[26] = (((blk->bdi_mask) & (1<<44)) ? (signed short) db4[44]-db4[0] : (signed short) db4[44]) & 255;
                vcddb[27] = ((((blk->bdi_mask) & (1<<44)) ? (signed short) db4[44]-db4[0] : (signed short) db4[44]) & -256) >> 8;
                vcddb[28] = (((blk->bdi_mask) & (1<<48)) ? (signed short) db4[48]-db4[0] : (signed short) db4[48]) & 255;
                vcddb[29] = ((((blk->bdi_mask) & (1<<48)) ? (signed short) db4[48]-db4[0] : (signed short) db4[48]) & -256) >> 8;
                vcddb[30] = (((blk->bdi_mask) & (1<<52)) ? (signed short) db4[52]-db4[0] : (signed short) db4[52]) & 255;
                vcddb[31] = ((((blk->bdi_mask) & (1<<52)) ? (signed short) db4[52]-db4[0] : (signed short) db4[52]) & -256) >> 8;
                vcddb[32] = (((blk->bdi_mask) & (1<<56)) ? (signed short) db4[56]-db4[0] : (signed short) db4[56]) & 255;
                vcddb[33] = ((((blk->bdi_mask) & (1<<56)) ? (signed short) db4[56]-db4[0] : (signed short) db4[56]) & -256) >> 8;
                vcddb[34] = (((blk->bdi_mask) & (1<<60)) ? (signed short) db4[60]-db4[0] : (signed short) db4[60]) & 255;
                vcddb[35] = ((((blk->bdi_mask) & (1<<60)) ? (signed short) db4[60]-db4[0] : (signed short) db4[60]) & -256) >> 8;

          break;
          case 7:
            //base 2 delta 1
            bdi_size = 40; // 5 segments, 40 bytes
	    for (i = 0; i < 2; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[2] = ((blk->bdi_mask) & (1<<0)) ? (signed char) db2[0]-db2[0] : (signed char) db2[0];
                vcddb[3] = ((blk->bdi_mask) & (1<<2)) ? (signed char) db2[2]-db2[0] : (signed char) db2[2];
                vcddb[4] = ((blk->bdi_mask) & (1<<4)) ? (signed char) db2[4]-db2[0] : (signed char) db2[4];
                vcddb[5] = ((blk->bdi_mask) & (1<<6)) ? (signed char) db2[6]-db2[0] : (signed char) db2[6];
                vcddb[6] = ((blk->bdi_mask) & (1<<8)) ? (signed char) db2[8]-db2[0] : (signed char) db2[8];
                vcddb[7] = ((blk->bdi_mask) & (1<<10)) ? (signed char) db2[10]-db2[0] : (signed char) db2[10];
                vcddb[8] = ((blk->bdi_mask) & (1<<12)) ? (signed char) db2[12]-db2[0] : (signed char) db2[12];
                vcddb[9] = ((blk->bdi_mask) & (1<<14)) ? (signed char) db2[14]-db2[0] : (signed char) db2[14];
                vcddb[10] = ((blk->bdi_mask) & (1<<16)) ? (signed char) db2[16]-db2[0] : (signed char) db2[16];
                vcddb[11] = ((blk->bdi_mask) & (1<<18)) ? (signed char) db2[18]-db2[0] : (signed char) db2[18];
                vcddb[12] = ((blk->bdi_mask) & (1<<20)) ? (signed char) db2[20]-db2[0] : (signed char) db2[20];
                vcddb[13] = ((blk->bdi_mask) & (1<<22)) ? (signed char) db2[22]-db2[0] : (signed char) db2[22];
                vcddb[14] = ((blk->bdi_mask) & (1<<24)) ? (signed char) db2[24]-db2[0] : (signed char) db2[24];
                vcddb[15] = ((blk->bdi_mask) & (1<<26)) ? (signed char) db2[26]-db2[0] : (signed char) db2[26];
                vcddb[16] = ((blk->bdi_mask) & (1<<28)) ? (signed char) db2[28]-db2[0] : (signed char) db2[28];
                vcddb[17] = ((blk->bdi_mask) & (1<<30)) ? (signed char) db2[30]-db2[0] : (signed char) db2[30];
                vcddb[18] = ((blk->bdi_mask) & (1<<32)) ? (signed char) db2[32]-db2[0] : (signed char) db2[32];
                vcddb[19] = ((blk->bdi_mask) & (1<<34)) ? (signed char) db2[34]-db2[0] : (signed char) db2[34];
                vcddb[20] = ((blk->bdi_mask) & (1<<36)) ? (signed char) db2[36]-db2[0] : (signed char) db2[36];
                vcddb[21] = ((blk->bdi_mask) & (1<<38)) ? (signed char) db2[38]-db2[0] : (signed char) db2[38];
                vcddb[22] = ((blk->bdi_mask) & (1<<40)) ? (signed char) db2[40]-db2[0] : (signed char) db2[40];
                vcddb[23] = ((blk->bdi_mask) & (1<<42)) ? (signed char) db2[42]-db2[0] : (signed char) db2[42];
                vcddb[24] = ((blk->bdi_mask) & (1<<44)) ? (signed char) db2[44]-db2[0] : (signed char) db2[44];
                vcddb[25] = ((blk->bdi_mask) & (1<<46)) ? (signed char) db2[46]-db2[0] : (signed char) db2[46];
                vcddb[26] = ((blk->bdi_mask) & (1<<48)) ? (signed char) db2[48]-db2[0] : (signed char) db2[48];
                vcddb[27] = ((blk->bdi_mask) & (1<<50)) ? (signed char) db2[50]-db2[0] : (signed char) db2[50];
                vcddb[28] = ((blk->bdi_mask) & (1<<52)) ? (signed char) db2[52]-db2[0] : (signed char) db2[52];
                vcddb[29] = ((blk->bdi_mask) & (1<<54)) ? (signed char) db2[54]-db2[0] : (signed char) db2[54];
                vcddb[30] = ((blk->bdi_mask) & (1<<56)) ? (signed char) db2[56]-db2[0] : (signed char) db2[56];
                vcddb[31] = ((blk->bdi_mask) & (1<<58)) ? (signed char) db2[58]-db2[0] : (signed char) db2[58];
                vcddb[32] = ((blk->bdi_mask) & (1<<60)) ? (signed char) db2[60]-db2[0] : (signed char) db2[60];
                vcddb[33] = ((blk->bdi_mask) & (1<<62)) ? (signed char) db2[62]-db2[0] : (signed char) db2[62];

          break;
          case 15:
            //decompressed
            bdi_size = 64; // 8 segments, 64 bytes
	    for (i = 0; i < 64; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
          break;
        }

if (bdi_size != 64) {

 
 char dvcdbuf1[32];
  sprintf(dvcdbuf1, "#%d", cp->compressor_frequency*now);

  //db[0-63].. is the cache line being read from memory / written into cache / compressed
  

  char dvcdbuf2[516];
  dvcdbuf2[0] = 'b';
  dvcdbuf2[513] = ' ';
  dvcdbuf2[514] = '!';
  dvcdbuf2[515] = '\0';


  for (i = 0; i < 64; i++) {
  for (j = 0; j < 8; j++) {
        dvcdbuf2[504-(i*8)+8-j]  = (vcddb[i] & 1) + '0';
        vcddb[i] >>= 1;
    }
  }

  char dvcdbuf3[8];
  dvcdbuf3[0] = 'b';
  dvcdbuf3[1] = ((blk->bdi_encode >> 3) & 1) + '0';
  dvcdbuf3[2] = ((blk->bdi_encode >> 2) & 1) + '0';
  dvcdbuf3[3] = ((blk->bdi_encode >> 1) & 1) + '0';
  dvcdbuf3[4] = ((blk->bdi_encode) & 1) + '0';
  dvcdbuf3[5] = ' ';
  dvcdbuf3[6] = '$';
  dvcdbuf3[7] = '\0';

  if (strcmp(last_dvcdbuf2,dvcdbuf2) || strcmp(last_dvcdbuf3,dvcdbuf3)) {

  if  ( dbuf[0] != '\0' ) {
  fp = fopen(dbuf, "a");
  fprintf(fp, dvcdbuf1);
  fprintf(fp, "\n");
  fprintf(fp, dvcdbuf2);
  fprintf(fp, "\n");
  fprintf(fp, dvcdbuf3);
  fprintf(fp, "\n");
  fclose(fp);
  }

  vcd_redlines_decompressor++;
  }

  vcd_lines_decompressor++;
  strcpy(last_dvcdbuf2, dvcdbuf2);
  strcpy(last_dvcdbuf3, dvcdbuf3);
}
}
  // Static energy is updated every cache access, regardless of operation and hit result  

  cp->sim_tag_static_power += (now - cp->last_cache_access) * cp->cacti_tag_static_power;
  cp->sim_data_static_power += (now - cp->last_cache_access) * cp->cacti_data_static_power;

  // On cache hit, tag read will occur for read and write operation

  cp->sim_tag_read_dynamic_energy += cp->cacti_tag_read_dynamic_energy;

  // On cache hit, read operation, there will be 0 tag writes, 0 data writes, 1 data read

  if (cmd == Read) { 

    cp->sim_data_read_dynamic_energy += (double) bdi_size / cp->bsize * cp->cacti_data_read_dynamic_energy;

  }

  // On cache hit, write operation, there will be 0 tag writes, 1 data write, 0 data reads

  if (cmd == Write) {
                      cp->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cacti_data_write_dynamic_energy;
                    }

  cp->last_cache_access = now;

////////////////////////////////////////////////////////////////
//sdrea-end

  /* copy data out of cache block, if block exists */
  if (cp->balloc)
    {
      CACHE_BCOPY(cmd, blk, bofs, p, nbytes);
    }

  /* update dirty status */
  if (cmd == Write)
    blk->status |= CACHE_BLK_DIRTY;

  /* if LRU replacement and this is not the first element of list, reorder */
  if (blk->way_prev && cp->policy == LRU)
    {
      /* move this block to head of the way (MRU) list */
      update_way_list(&cp->sets[set], blk, Head);
    }

  /* tag is unchanged, so hash links (if they exist) are still valid */

  /* record the last block to hit */
  cp->last_tagset = CACHE_TAGSET(cp, addr);
  cp->last_blk = blk;

  /* get user block data, if requested and it exists */
  if (udata)
    *udata = blk->user_data;

  /* return first cycle data is available to access */

//sdrea-begin
////////////////////////////////////////////////////////////////

//  return (int) MAX(cp->hit_latency, (blk->ready - now));

  if (cmd == Read && cp->bdi_compress && bdi_size != 64) { 
    cp->compressed_hits++;
    cp->last_compressed_size = bdi_size;
    return (int) MAX( (cp->hit_latency + cp->decompression_latency), (blk->ready - now) );
  }
  else {
    return (int) MAX( cp->hit_latency, (blk->ready - now) );
  }

////////////////////////////////////////////////////////////////
//sdrea-end

 cache_fast_hit: /* fast hit handler */
  
  /* **FAST HIT** */
  cp->hits++;


//sdrea-begin
////////////////////////////////////////////////////////////////

if (mem != NULL)
    {
        for (i = 0; i < 64; i++)
          {
            vcddb[i] = 0;
	    db[i] = 0;
            db8[i] = 0;
            db4[i] = 0;
            db2[i] = 0;
          }

        for (i = 0; i < 64; i++)
          {
            db[i] = MEM_READ_BYTE(mem, addr - bofs + i);
	    db8[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            db4[i] = MEM_READ_BYTE(mem, addr - bofs + i);
            db2[i] = MEM_READ_BYTE(mem, addr - bofs + i);
          }

        for (i = 0; i < 64; i+=8)
          {
            db8[i] += db8[i+1] <<  8;
            db8[i] += db8[i+2] << 16;
            db8[i] += db8[i+3] << 24;
            db8[i] += db8[i+4] << 32;
            db8[i] += db8[i+5] << 40;
            db8[i] += db8[i+6] << 48;
            db8[i] += db8[i+7] << 56;
          }

        for (i = 0; i < 64; i+=4)
          {
            db4[i] += db4[i+1] <<  8;
            db4[i] += db4[i+2] << 16;
            db4[i] += db4[i+3] << 24;
          }

        for (i = 0; i < 64; i+=2)
          {
            db2[i] += db2[i+1] <<  8;
          }

  // need bdi size
      switch (blk->bdi_encode)
        {
          case 0:
            //zeros
            bdi_size = 8; // 1 segment, 8 bytes
          break;
          case 1:
            //repeats
            bdi_size = 8; // 1 segment, 8 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
          break;
          case 2:
            //base 8 delta 1
            bdi_size = 16; // 2 segments, 16 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[8] = ((blk->bdi_mask) & (1<<0)) ? (signed char) db8[0]-db8[0] : (signed char) db8[0];
                vcddb[9] = ((blk->bdi_mask) & (1<<8)) ? (signed char) db8[8]-db8[0] : (signed char) db8[8];
                vcddb[10] = ((blk->bdi_mask) & (1<<16)) ? (signed char) db8[16]-db8[0] : (signed char) db8[16];
                vcddb[11] = ((blk->bdi_mask) & (1<<24)) ? (signed char) db8[24]-db8[0] : (signed char) db8[24];
                vcddb[12] = ((blk->bdi_mask) & (1<<32)) ? (signed char) db8[32]-db8[0] : (signed char) db8[32];
                vcddb[13] = ((blk->bdi_mask) & (1<<40)) ? (signed char) db8[40]-db8[0] : (signed char) db8[40];
                vcddb[14] = ((blk->bdi_mask) & (1<<48)) ? (signed char) db8[48]-db8[0] : (signed char) db8[48];
                vcddb[15] = ((blk->bdi_mask) & (1<<56)) ? (signed char) db8[56]-db8[0] : (signed char) db8[56];
          break;
          case 3:
            //base 8 delta 2
            bdi_size = 24; // 3 segments, 24 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[8] =  (((blk->bdi_mask) & (1<<0)) ? (signed short) db8[0]-db8[0] : (signed short) db8[0]) &  255;
                vcddb[9] =  ((((blk->bdi_mask) & (1<<0)) ? (signed short) db8[0]-db8[0] : (signed short) db8[0]) & -256) >> 8;
                vcddb[10] = (((blk->bdi_mask) & (1<<8)) ? (signed short) db8[8]-db8[0] : (signed short) db8[8]) &  255;
                vcddb[11] = ((((blk->bdi_mask) & (1<<8)) ? (signed short) db8[8]-db8[0] : (signed short) db8[8]) & -256) >> 8;
                vcddb[12] = (((blk->bdi_mask) & (1<<16)) ? (signed short) db8[16]-db8[0] : (signed short) db8[16]) &  255;
                vcddb[13] = ((((blk->bdi_mask) & (1<<16)) ? (signed short) db8[16]-db8[0] : (signed short) db8[16]) &  -256) >> 8;
                vcddb[14] = (((blk->bdi_mask) & (1<<24)) ? (signed short) db8[24]-db8[0] : (signed short) db8[24]) &  255;
                vcddb[15] = ((((blk->bdi_mask) & (1<<24)) ? (signed short) db8[24]-db8[0] : (signed short) db8[24]) &  -256) >> 8;
                vcddb[16] = (((blk->bdi_mask) & (1<<32)) ? (signed short) db8[32]-db8[0] : (signed short) db8[32]) &  255;
                vcddb[17] = ((((blk->bdi_mask) & (1<<32)) ? (signed short) db8[32]-db8[0] : (signed short) db8[32]) &  -256) >> 8;
                vcddb[18] = (((blk->bdi_mask) & (1<<40)) ? (signed short) db8[40]-db8[0] : (signed short) db8[40]) &  255;
                vcddb[19] = ((((blk->bdi_mask) & (1<<40)) ? (signed short) db8[40]-db8[0] : (signed short) db8[40]) &  -256) >> 8;
                vcddb[20] = (((blk->bdi_mask) & (1<<48)) ? (signed short) db8[48]-db8[0] : (signed short) db8[48]) &  255;
                vcddb[21] = ((((blk->bdi_mask) & (1<<48)) ? (signed short) db8[48]-db8[0] : (signed short) db8[48]) &  -256) >> 8;
                vcddb[22] = (((blk->bdi_mask) & (1<<56)) ? (signed short) db8[56]-db8[0] : (signed short) db8[56]) &  255;
                vcddb[23] = ((((blk->bdi_mask) & (1<<56)) ? (signed short) db8[56]-db8[0] : (signed short) db8[56]) &  -256) >> 8;
          break;
          case 4:
            //base 8 delta 4
            bdi_size = 40; // 5 segments, 40 bytes
	    for (i = 0; i < 8; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[8] =  (((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) & 255;
                vcddb[9] =  ((((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) & 65280) >> 8;
                vcddb[10] =  ((((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) &  16711680) >> 16;
                vcddb[11] =  ((((blk->bdi_mask) & (1<<0)) ? (signed long) db8[0]-db8[0] : (signed long) db8[0]) & -16777216) >> 24;
                vcddb[12] =  (((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) & 255;
                vcddb[13] =  ((((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) & 65280) >> 8;
                vcddb[14] =  ((((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) &  16711680) >> 16;
                vcddb[15] =  ((((blk->bdi_mask) & (1<<8)) ? (signed long) db8[8]-db8[0] : (signed long) db8[8]) & -16777216) >> 24;
                vcddb[16] =  (((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) & 255;
                vcddb[17] =  ((((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) & 65280) >> 8;
                vcddb[18] =  ((((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) &  16711680) >> 16;
                vcddb[19] =  ((((blk->bdi_mask) & (1<<16)) ? (signed long) db8[16]-db8[0] : (signed long) db8[16]) & -16777216) >> 24;
                vcddb[20] =  (((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) & 255;
                vcddb[21] =  ((((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) & 65280) >> 8;
                vcddb[22] =  ((((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) &  16711680) >> 16;
                vcddb[23] =  ((((blk->bdi_mask) & (1<<24)) ? (signed long) db8[24]-db8[0] : (signed long) db8[24]) & -16777216) >> 24;
                vcddb[24] =  (((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) & 255;
                vcddb[25] =  ((((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) & 65280) >> 8;
                vcddb[26] =  ((((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) &  16711680) >> 16;
                vcddb[27] =  ((((blk->bdi_mask) & (1<<32)) ? (signed long) db8[32]-db8[0] : (signed long) db8[32]) & -16777216) >> 24;
                vcddb[28] =  (((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) & 255;
                vcddb[29] =  ((((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) & 65280) >> 8;
                vcddb[30] =  ((((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) &  16711680) >> 16;
                vcddb[31] =  ((((blk->bdi_mask) & (1<<40)) ? (signed long) db8[40]-db8[0] : (signed long) db8[40]) & -16777216) >> 24;
                vcddb[32] =  (((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) & 255;
                vcddb[33] =  ((((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) & 65280) >> 8;
                vcddb[34] =  ((((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) &  16711680) >> 16;
                vcddb[35] =  ((((blk->bdi_mask) & (1<<48)) ? (signed long) db8[48]-db8[0] : (signed long) db8[48]) & -16777216) >> 24;
                vcddb[36] =  (((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) & 255;
                vcddb[37] =  ((((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) & 65280) >> 8;
                vcddb[38] =  ((((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) &  16711680) >> 16;
                vcddb[39] =  ((((blk->bdi_mask) & (1<<56)) ? (signed long) db8[56]-db8[0] : (signed long) db8[56]) & -16777216) >> 24;

          break;
          case 5:
            //base 4 delta 1
            bdi_size = 24; // 3 segments, 24 bytes
	    for (i = 0; i < 4; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[4] = ((blk->bdi_mask) & (1<<0)) ? (signed char) db4[0]-db4[0] : (signed char) db4[0];
                vcddb[5] = ((blk->bdi_mask) & (1<<4)) ? (signed char) db4[4]-db4[0] : (signed char) db4[4];
                vcddb[6] = ((blk->bdi_mask) & (1<<8)) ? (signed char) db4[8]-db4[0] : (signed char) db4[8];
                vcddb[7] = ((blk->bdi_mask) & (1<<12)) ? (signed char) db4[12]-db4[0] : (signed char) db4[12];
                vcddb[8] = ((blk->bdi_mask) & (1<<16)) ? (signed char) db4[16]-db4[0] : (signed char) db4[16];
                vcddb[9] = ((blk->bdi_mask) & (1<<20)) ? (signed char) db4[20]-db4[0] : (signed char) db4[20];
                vcddb[10] = ((blk->bdi_mask) & (1<<24)) ? (signed char) db4[24]-db4[0] : (signed char) db4[24];
                vcddb[11] = ((blk->bdi_mask) & (1<<28)) ? (signed char) db4[28]-db4[0] : (signed char) db4[28];
                vcddb[12] = ((blk->bdi_mask) & (1<<32)) ? (signed char) db4[32]-db4[0] : (signed char) db4[32];
                vcddb[13] = ((blk->bdi_mask) & (1<<36)) ? (signed char) db4[36]-db4[0] : (signed char) db4[36];
                vcddb[14] = ((blk->bdi_mask) & (1<<40)) ? (signed char) db4[40]-db4[0] : (signed char) db4[40];
                vcddb[15] = ((blk->bdi_mask) & (1<<44)) ? (signed char) db4[44]-db4[0] : (signed char) db4[44];
                vcddb[16] = ((blk->bdi_mask) & (1<<48)) ? (signed char) db4[48]-db4[0] : (signed char) db4[48];
                vcddb[17] = ((blk->bdi_mask) & (1<<52)) ? (signed char) db4[52]-db4[0] : (signed char) db4[52];
                vcddb[18] = ((blk->bdi_mask) & (1<<56)) ? (signed char) db4[56]-db4[0] : (signed char) db4[56];
                vcddb[19] = ((blk->bdi_mask) & (1<<60)) ? (signed char) db4[60]-db4[0] : (signed char) db4[60];

          break;
          case 6:
            //base 4 delta 2
            bdi_size = 40; // 5 segments, 40 bytes
	    for (i = 0; i < 4; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[4] = (((blk->bdi_mask) & (1<<0)) ? (signed short) db4[0]-db4[0] : (signed short) db4[0]) & 255;
                vcddb[5] = ((((blk->bdi_mask) & (1<<0)) ? (signed short) db4[0]-db4[0] : (signed short) db4[0]) & -256) >> 8;
                vcddb[6] = (((blk->bdi_mask) & (1<<4)) ? (signed short) db4[4]-db4[0] : (signed short) db4[4]) & 255;
                vcddb[7] = ((((blk->bdi_mask) & (1<<4)) ? (signed short) db4[4]-db4[0] : (signed short) db4[4]) & -256) >> 8;
                vcddb[8] = (((blk->bdi_mask) & (1<<8)) ? (signed short) db4[8]-db4[0] : (signed short) db4[8]) & 255;
                vcddb[9] = ((((blk->bdi_mask) & (1<<8)) ? (signed short) db4[8]-db4[0] : (signed short) db4[8]) & -256) >> 8;
                vcddb[10] = (((blk->bdi_mask) & (1<<12)) ? (signed short) db4[12]-db4[0] : (signed short) db4[12]) & 255;
                vcddb[11] = ((((blk->bdi_mask) & (1<<12)) ? (signed short) db4[12]-db4[0] : (signed short) db4[12]) & -256) >> 8;
                vcddb[12] = (((blk->bdi_mask) & (1<<16)) ? (signed short) db4[16]-db4[0] : (signed short) db4[16]) & 255;
                vcddb[13] = ((((blk->bdi_mask) & (1<<16)) ? (signed short) db4[16]-db4[0] : (signed short) db4[16]) & -256) >> 8;
                vcddb[14] = (((blk->bdi_mask) & (1<<20)) ? (signed short) db4[20]-db4[0] : (signed short) db4[20]) & 255;
                vcddb[15] = ((((blk->bdi_mask) & (1<<20)) ? (signed short) db4[20]-db4[0] : (signed short) db4[20]) & -256) >> 8;
                vcddb[16] = (((blk->bdi_mask) & (1<<24)) ? (signed short) db4[24]-db4[0] : (signed short) db4[24]) & 255;
                vcddb[17] = ((((blk->bdi_mask) & (1<<24)) ? (signed short) db4[24]-db4[0] : (signed short) db4[24]) & -256) >> 8;
                vcddb[18] = (((blk->bdi_mask) & (1<<28)) ? (signed short) db4[28]-db4[0] : (signed short) db4[28]) & 255;
                vcddb[19] = ((((blk->bdi_mask) & (1<<28)) ? (signed short) db4[28]-db4[0] : (signed short) db4[28]) & -256) >> 8;
                vcddb[20] = (((blk->bdi_mask) & (1<<32)) ? (signed short) db4[32]-db4[0] : (signed short) db4[32]) & 255;
                vcddb[21] = ((((blk->bdi_mask) & (1<<32)) ? (signed short) db4[32]-db4[0] : (signed short) db4[32]) & -256) >> 8;
                vcddb[22] = (((blk->bdi_mask) & (1<<36)) ? (signed short) db4[36]-db4[0] : (signed short) db4[36]) & 255;
                vcddb[23] = ((((blk->bdi_mask) & (1<<36)) ? (signed short) db4[36]-db4[0] : (signed short) db4[36]) & -256) >> 8;
                vcddb[24] = (((blk->bdi_mask) & (1<<40)) ? (signed short) db4[40]-db4[0] : (signed short) db4[40]) & 255;
                vcddb[25] = ((((blk->bdi_mask) & (1<<40)) ? (signed short) db4[40]-db4[0] : (signed short) db4[40]) & -256) >> 8;
                vcddb[26] = (((blk->bdi_mask) & (1<<44)) ? (signed short) db4[44]-db4[0] : (signed short) db4[44]) & 255;
                vcddb[27] = ((((blk->bdi_mask) & (1<<44)) ? (signed short) db4[44]-db4[0] : (signed short) db4[44]) & -256) >> 8;
                vcddb[28] = (((blk->bdi_mask) & (1<<48)) ? (signed short) db4[48]-db4[0] : (signed short) db4[48]) & 255;
                vcddb[29] = ((((blk->bdi_mask) & (1<<48)) ? (signed short) db4[48]-db4[0] : (signed short) db4[48]) & -256) >> 8;
                vcddb[30] = (((blk->bdi_mask) & (1<<52)) ? (signed short) db4[52]-db4[0] : (signed short) db4[52]) & 255;
                vcddb[31] = ((((blk->bdi_mask) & (1<<52)) ? (signed short) db4[52]-db4[0] : (signed short) db4[52]) & -256) >> 8;
                vcddb[32] = (((blk->bdi_mask) & (1<<56)) ? (signed short) db4[56]-db4[0] : (signed short) db4[56]) & 255;
                vcddb[33] = ((((blk->bdi_mask) & (1<<56)) ? (signed short) db4[56]-db4[0] : (signed short) db4[56]) & -256) >> 8;
                vcddb[34] = (((blk->bdi_mask) & (1<<60)) ? (signed short) db4[60]-db4[0] : (signed short) db4[60]) & 255;
                vcddb[35] = ((((blk->bdi_mask) & (1<<60)) ? (signed short) db4[60]-db4[0] : (signed short) db4[60]) & -256) >> 8;

          break;
          case 7:
            //base 2 delta 1
            bdi_size = 40; // 5 segments, 40 bytes
	    for (i = 0; i < 2; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
                vcddb[2] = ((blk->bdi_mask) & (1<<0)) ? (signed char) db2[0]-db2[0] : (signed char) db2[0];
                vcddb[3] = ((blk->bdi_mask) & (1<<2)) ? (signed char) db2[2]-db2[0] : (signed char) db2[2];
                vcddb[4] = ((blk->bdi_mask) & (1<<4)) ? (signed char) db2[4]-db2[0] : (signed char) db2[4];
                vcddb[5] = ((blk->bdi_mask) & (1<<6)) ? (signed char) db2[6]-db2[0] : (signed char) db2[6];
                vcddb[6] = ((blk->bdi_mask) & (1<<8)) ? (signed char) db2[8]-db2[0] : (signed char) db2[8];
                vcddb[7] = ((blk->bdi_mask) & (1<<10)) ? (signed char) db2[10]-db2[0] : (signed char) db2[10];
                vcddb[8] = ((blk->bdi_mask) & (1<<12)) ? (signed char) db2[12]-db2[0] : (signed char) db2[12];
                vcddb[9] = ((blk->bdi_mask) & (1<<14)) ? (signed char) db2[14]-db2[0] : (signed char) db2[14];
                vcddb[10] = ((blk->bdi_mask) & (1<<16)) ? (signed char) db2[16]-db2[0] : (signed char) db2[16];
                vcddb[11] = ((blk->bdi_mask) & (1<<18)) ? (signed char) db2[18]-db2[0] : (signed char) db2[18];
                vcddb[12] = ((blk->bdi_mask) & (1<<20)) ? (signed char) db2[20]-db2[0] : (signed char) db2[20];
                vcddb[13] = ((blk->bdi_mask) & (1<<22)) ? (signed char) db2[22]-db2[0] : (signed char) db2[22];
                vcddb[14] = ((blk->bdi_mask) & (1<<24)) ? (signed char) db2[24]-db2[0] : (signed char) db2[24];
                vcddb[15] = ((blk->bdi_mask) & (1<<26)) ? (signed char) db2[26]-db2[0] : (signed char) db2[26];
                vcddb[16] = ((blk->bdi_mask) & (1<<28)) ? (signed char) db2[28]-db2[0] : (signed char) db2[28];
                vcddb[17] = ((blk->bdi_mask) & (1<<30)) ? (signed char) db2[30]-db2[0] : (signed char) db2[30];
                vcddb[18] = ((blk->bdi_mask) & (1<<32)) ? (signed char) db2[32]-db2[0] : (signed char) db2[32];
                vcddb[19] = ((blk->bdi_mask) & (1<<34)) ? (signed char) db2[34]-db2[0] : (signed char) db2[34];
                vcddb[20] = ((blk->bdi_mask) & (1<<36)) ? (signed char) db2[36]-db2[0] : (signed char) db2[36];
                vcddb[21] = ((blk->bdi_mask) & (1<<38)) ? (signed char) db2[38]-db2[0] : (signed char) db2[38];
                vcddb[22] = ((blk->bdi_mask) & (1<<40)) ? (signed char) db2[40]-db2[0] : (signed char) db2[40];
                vcddb[23] = ((blk->bdi_mask) & (1<<42)) ? (signed char) db2[42]-db2[0] : (signed char) db2[42];
                vcddb[24] = ((blk->bdi_mask) & (1<<44)) ? (signed char) db2[44]-db2[0] : (signed char) db2[44];
                vcddb[25] = ((blk->bdi_mask) & (1<<46)) ? (signed char) db2[46]-db2[0] : (signed char) db2[46];
                vcddb[26] = ((blk->bdi_mask) & (1<<48)) ? (signed char) db2[48]-db2[0] : (signed char) db2[48];
                vcddb[27] = ((blk->bdi_mask) & (1<<50)) ? (signed char) db2[50]-db2[0] : (signed char) db2[50];
                vcddb[28] = ((blk->bdi_mask) & (1<<52)) ? (signed char) db2[52]-db2[0] : (signed char) db2[52];
                vcddb[29] = ((blk->bdi_mask) & (1<<54)) ? (signed char) db2[54]-db2[0] : (signed char) db2[54];
                vcddb[30] = ((blk->bdi_mask) & (1<<56)) ? (signed char) db2[56]-db2[0] : (signed char) db2[56];
                vcddb[31] = ((blk->bdi_mask) & (1<<58)) ? (signed char) db2[58]-db2[0] : (signed char) db2[58];
                vcddb[32] = ((blk->bdi_mask) & (1<<60)) ? (signed char) db2[60]-db2[0] : (signed char) db2[60];
                vcddb[33] = ((blk->bdi_mask) & (1<<62)) ? (signed char) db2[62]-db2[0] : (signed char) db2[62];

          break;
          case 15:
            //decompressed
            bdi_size = 64; // 8 segments, 64 bytes
	    for (i = 0; i < 64; i++)
              {
                vcddb[i] = MEM_READ_BYTE(mem, addr - bofs + i);
              }
          break;
        }

if (bdi_size != 64) {

  char dvcdbuf1[32];
  sprintf(dvcdbuf1, "#%d", cp->compressor_frequency*now);

  //db[0-63].. is the cache line being read from memory / written into cache / compressed


  char dvcdbuf2[516];
  dvcdbuf2[0] = 'b';
  dvcdbuf2[513] = ' ';
  dvcdbuf2[514] = '!';
  dvcdbuf2[515] = '\0';


  for (i = 0; i < 64; i++) {
  for (j = 0; j < 8; j++) {
        dvcdbuf2[504-(i*8)+8-j]  = (vcddb[i] & 1) + '0';
        vcddb[i] >>= 1;
    }
  }

  char dvcdbuf3[8];
  dvcdbuf3[0] = 'b';
  dvcdbuf3[1] = ((blk->bdi_encode >> 3) & 1) + '0';
  dvcdbuf3[2] = ((blk->bdi_encode >> 2) & 1) + '0';
  dvcdbuf3[3] = ((blk->bdi_encode >> 1) & 1) + '0';
  dvcdbuf3[4] = ((blk->bdi_encode) & 1) + '0';
  dvcdbuf3[5] = ' ';
  dvcdbuf3[6] = '$';
  dvcdbuf3[7] = '\0';

  if (strcmp(last_dvcdbuf2,dvcdbuf2) || strcmp(last_dvcdbuf3,dvcdbuf3)) {

  if  ( dbuf[0] != '\0' ) {
  fp = fopen(dbuf, "a");
  fprintf(fp, dvcdbuf1);
  fprintf(fp, "\n");
  fprintf(fp, dvcdbuf2);
  fprintf(fp, "\n");
  fprintf(fp, dvcdbuf3);
  fprintf(fp, "\n");
  fclose(fp);
  }

  vcd_redlines_decompressor++;
  }

  vcd_lines_decompressor++;
  strcpy(last_dvcdbuf2, dvcdbuf2);
  strcpy(last_dvcdbuf3, dvcdbuf3);

}
}
  // Static energy is updated every cache access, regardless of operation and hit result  

  cp->sim_tag_static_power += (now - cp->last_cache_access) * cp->cacti_tag_static_power;
  cp->sim_data_static_power += (now - cp->last_cache_access) * cp->cacti_data_static_power;

  // On cache hit, tag read will occur for read and write operation

  cp->sim_tag_read_dynamic_energy += cp->cacti_tag_read_dynamic_energy;

  // On cache hit, read operation, there will be 0 tag writes, 0 data writes, 1 data read

  if (cmd == Read) { 

    cp->sim_data_read_dynamic_energy += (double) bdi_size / cp->bsize * cp->cacti_data_read_dynamic_energy;

  }

  // On cache hit, write operation, there will be 0 tag writes (but a dirty bit write), 1 data write, 0 data reads

  if (cmd == Write) {
                      cp->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cacti_data_write_dynamic_energy;
                    }

  cp->last_cache_access = now;

////////////////////////////////////////////////////////////////
//sdrea-end

  /* copy data out of cache block, if block exists */
  if (cp->balloc)
    {
      CACHE_BCOPY(cmd, blk, bofs, p, nbytes);
    }

  /* update dirty status */
  if (cmd == Write)
    blk->status |= CACHE_BLK_DIRTY;

  /* this block hit last, no change in the way list */

  /* tag is unchanged, so hash links (if they exist) are still valid */

  /* get user block data, if requested and it exists */
  if (udata)
    *udata = blk->user_data;

  /* record the last block to hit */
  cp->last_tagset = CACHE_TAGSET(cp, addr);
  cp->last_blk = blk;

  /* return first cycle data is available to access */

//sdrea-begin
////////////////////////////////////////////////////////////////

//  return (int) MAX(cp->hit_latency, (blk->ready - now));

  if (cmd == Read && cp->bdi_compress) { 
    cp->compressed_hits++;
    cp->last_compressed_size = bdi_size;
    return (int) MAX( (cp->hit_latency + cp->decompression_latency), (blk->ready - now) );
  }
  else {
    return (int) MAX( cp->hit_latency, (blk->ready - now) );
  }

////////////////////////////////////////////////////////////////
//sdrea-end

}

/* return non-zero if block containing address ADDR is contained in cache
   CP, this interface is used primarily for debugging and asserting cache
   invariants */
int					/* non-zero if access would hit */
cache_probe(struct cache_t *cp,		/* cache instance to probe */
	    md_addr_t addr)		/* address of block to probe */
{
  md_addr_t tag = CACHE_TAG(cp, addr);
  md_addr_t set = CACHE_SET(cp, addr);
  struct cache_blk_t *blk;

  /* permissions are checked on cache misses */

  if (cp->hsize)
  {
    /* higly-associativity cache, access through the per-set hash tables */
    int hindex = CACHE_HASH(cp, tag);
    
    for (blk=cp->sets[set].hash[hindex];
	 blk;
	 blk=blk->hash_next)
    {	
      if (blk->tag == tag && (blk->status & CACHE_BLK_VALID))
	  return TRUE;
    }
  }
  else
  {
    /* low-associativity cache, linear search the way list */
    for (blk=cp->sets[set].way_head;
	 blk;
	 blk=blk->way_next)
    {
      if (blk->tag == tag && (blk->status & CACHE_BLK_VALID))
	  return TRUE;
    }
  }
  
  /* cache block not found */
  return FALSE;
}

/* flush the entire cache, returns latency of the operation */
unsigned int				/* latency of the flush operation */
cache_flush(struct cache_t *cp,		/* cache instance to flush */
	    tick_t now)			/* time of cache flush */
{
  int i, lat = cp->hit_latency; /* min latency to probe cache */
  struct cache_blk_t *blk;

  /* blow away the last block to hit */
  cp->last_tagset = 0;
  cp->last_blk = NULL;

  /* no way list updates required because all blocks are being invalidated */
  for (i=0; i<cp->nsets; i++)
    {
      for (blk=cp->sets[i].way_head; blk; blk=blk->way_next)
	{
	  if (blk->status & CACHE_BLK_VALID)
	    {
	      cp->invalidations++;
	      blk->status &= ~CACHE_BLK_VALID;

	      if (blk->status & CACHE_BLK_DIRTY)
		{
		  /* write back the invalidated block */
          	  cp->writebacks++;
		  lat += cp->blk_access_fn(Write,
					   CACHE_MK_BADDR(cp, blk->tag, i),
					   cp->bsize, blk, now+lat);
		}
	    }
	}
    }

  /* return latency of the flush operation */
  return lat;
}

/* flush the block containing ADDR from the cache CP, returns the latency of
   the block flush operation */
unsigned int				/* latency of flush operation */
cache_flush_addr(struct cache_t *cp,	/* cache instance to flush */
		 md_addr_t addr,	/* address of block to flush */
		 tick_t now)		/* time of cache flush */
{
  md_addr_t tag = CACHE_TAG(cp, addr);
  md_addr_t set = CACHE_SET(cp, addr);
  struct cache_blk_t *blk;
  int lat = cp->hit_latency; /* min latency to probe cache */

  if (cp->hsize)
    {
      /* higly-associativity cache, access through the per-set hash tables */
      int hindex = CACHE_HASH(cp, tag);

      for (blk=cp->sets[set].hash[hindex];
	   blk;
	   blk=blk->hash_next)
	{
	  if (blk->tag == tag && (blk->status & CACHE_BLK_VALID))
	    break;
	}
    }
  else
    {
      /* low-associativity cache, linear search the way list */
      for (blk=cp->sets[set].way_head;
	   blk;
	   blk=blk->way_next)
	{
	  if (blk->tag == tag && (blk->status & CACHE_BLK_VALID))
	    break;
	}
    }

  if (blk)
    {
      cp->invalidations++;
      blk->status &= ~CACHE_BLK_VALID;

      /* blow away the last block to hit */
      cp->last_tagset = 0;
      cp->last_blk = NULL;

      if (blk->status & CACHE_BLK_DIRTY)
	{
	  /* write back the invalidated block */
          cp->writebacks++;
	  lat += cp->blk_access_fn(Write,
				   CACHE_MK_BADDR(cp, blk->tag, set),
				   cp->bsize, blk, now+lat);
	}
      /* move this block to tail of the way (LRU) list */
      update_way_list(&cp->sets[set], blk, Tail);
    }

  /* return latency of the operation */
  return lat;
}
