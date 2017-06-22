/* 
 * cfetch - a variant of SimpleScalar developed for modelling cache compression and prefetching
 * based on sim-wattch-1.02e - http://www.eecs.harvard.edu/~dbrooks/wattch-form.html
 * changes are commented //sdrea
 *
 * Sean Rea
 * sdrea@lakeheadu.ca
 * 2016-2017
 */

/* cfetch.c - compression and prefetching routines */

#include "machine.h"
#include "memory.h"
#include "cache.h"
#include "cfetch.h"
#include <string.h>

#define CACHE_TAG(cp, addr)	((addr) >> (cp)->tag_shift)
#define CACHE_SET(cp, addr)	(((addr) >> (cp)->set_shift) & (cp)->set_mask)
#define CACHE_BLK(cp, addr)	((addr) & (cp)->blk_mask)

static char last_dvcdbuf2[516] = "";
static char last_dvcdbuf3[8] = "";
static char last_vcdbuf2[516] = "";

FILE *fp;

void cfetch_cache_reg_stats ( struct cache_t *cp,
		    struct stat_sdb_t *sdb )	
{

  char buf[512], buf1[512], *name;

  if (!cp->name || !cp->name[0]) name = "<unknown>";
  else name = cp->name;

  sprintf(buf, "%s_sim_tag_static_power", name);
  sprintf(buf1, "%s Cache Tag Leakage Power (mW-cycles)", name);
  stat_reg_double(sdb, buf, buf1, &cp->cfetch->sim_tag_static_power, 0, "%30.6f");

  sprintf(buf, "%s_sim_tag_read_dynamic_energy", name);
  sprintf(buf1, "%s Cache Tag Dynamic Read Energy (nJ)", name);
  stat_reg_double(sdb, buf, buf1, &cp->cfetch->sim_tag_read_dynamic_energy, 0, "%23.6f");

  sprintf(buf, "%s_sim_tag_write_dynamic_energy", name);
  sprintf(buf1, "%s Cache Tag Dynamic Write Energy (nJ)", name);
  stat_reg_double(sdb, buf, buf1, &cp->cfetch->sim_tag_write_dynamic_energy, 0, "%22.6f");

  sprintf(buf, "%s_sim_data_static_power", name);
  sprintf(buf1, "%s Cache Data Leakage Power (mW-cycles)", name);
  stat_reg_double(sdb, buf, buf1, &cp->cfetch->sim_data_static_power, 0, "%29.6f");

  sprintf(buf, "%s_sim_data_read_dynamic_energy", name);
  sprintf(buf1, "%s Cache Data Dynamic Read Energy (nJ)", name);
  stat_reg_double(sdb, buf, buf1, &cp->cfetch->sim_data_read_dynamic_energy, 0, "%22.6f");

  sprintf(buf, "%s_sim_data_write_dynamic_energy", name);
  sprintf(buf1, "%s Cache Data Dynamic Write Energy (nJ)", name);
  stat_reg_double(sdb, buf, buf1, &cp->cfetch->sim_data_write_dynamic_energy, 0, "%21.6f");

  sprintf(buf, "%s_count_check_lines", name);
  sprintf(buf1, "%s Cache lines checked for compressibility", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_check_lines, 0, "%32d");

  sprintf(buf, "%s_count_compressible_any", name);
  sprintf(buf1, "%s Count of cache lines compressible", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_compressible_any, 0, "%32d");

  sprintf(buf, "%s_count_encode_lines", name);
  sprintf(buf1, "%s Cache lines checked for compression", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_lines, 0, "%32d");

  sprintf(buf, "%s_count_encode_0000_zeros", name);
  sprintf(buf1, "%s Cache blocks compressed as zeros", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0000_zeros, 0, "%31d");

  sprintf(buf, "%s_count_encode_0001_repeats", name);
  sprintf(buf1, "%s Cache blocks compressed as repeating values", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0001_repeats, 0, "%29d");

  sprintf(buf, "%s_count_encode_0010_b8d1", name);
  sprintf(buf1, "%s Cache blocks compressed as base 8 delta 1", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0010_b8d1, 0, "%32d");

  sprintf(buf, "%s_count_encode_0011_b8d2", name);
  sprintf(buf1, "%s Cache blocks compressed as base 8 delta 2", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0011_b8d2, 0,"%32d");

  sprintf(buf, "%s_count_encode_0100_b8d4", name);
  sprintf(buf1, "%s Cache blocks compressed as base 8 delta 4", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0100_b8d4, 0, "%32d");

  sprintf(buf, "%s_count_encode_0101_b4d1", name);
  sprintf(buf1, "%s Cache blocks compressed as base 4 delta 1", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0101_b4d1, 0, "%32d");

  sprintf(buf, "%s_count_encode_0110_b4d2", name);
  sprintf(buf1, "%s Cache blocks compressed as base 4 delta 2", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0110_b4d2, 0, "%32d");

  sprintf(buf, "%s_count_encode_0111_b2d1", name);
  sprintf(buf1, "%s Cache blocks compressed as base 2 delta 1", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_0111_b2d1, 0, "%32d");

  sprintf(buf, "%s_count_encode_1111_uncompressed", name);
  sprintf(buf1, "%s Uncompressed cache lines", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->count_encode_1111_uncompressed, 0, "%24d");

  sprintf(buf, "%s_size_compressed", name);
  sprintf(buf1, "%s Size of compressed cache lines", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->size_compressed, 0, "%32d");

  sprintf(buf, "%s_size_uncompressed", name);
  sprintf(buf1, "%s Size of uncompressed cache lines", name);
  stat_reg_counter(sdb, buf, buf1, &cp->cfetch->size_uncompressed, 0, "%32d");

}


//


void cfetch_cache_miss (enum mem_cmd cmd, struct cache_t *cp, struct mem_t *mem, md_addr_t addr, tick_t now, byte_t *encode, qword_t *mask) {

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

  md_addr_t tag = CACHE_TAG(cp, addr);
  md_addr_t set = CACHE_SET(cp, addr);
  md_addr_t bofs = CACHE_BLK(cp, addr);

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

	      cp->cfetch->count_check_lines++;
              if (zeros == 1 || repeats == 1 || delta81 == 1 || delta82 == 1 || delta84 == 1 || delta41 == 1 || delta42 == 1 || delta21 == 1) {cp->cfetch->count_compressible_any++;}

          if (cp->cfetch->bdi_compress) 
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


      cp->cfetch->count_encode_lines++;

      switch (bdi_encode)
        {
          case 0:
            //zeros
            cp->cfetch->count_encode_0000_zeros++;
            bdi_size = 8; // 1 segment, 8 bytes
          break;
          case 1:
            //repeats
            cp->cfetch->count_encode_0001_repeats++;
            bdi_size = 8; // 1 segment, 8 bytes
          break;
          case 2:
            //base 8 delta 1
            cp->cfetch->count_encode_0010_b8d1++;
            bdi_size = 16; // 2 segments, 16 bytes
          break;
          case 3:
            //base 8 delta 2
            cp->cfetch->count_encode_0011_b8d2++;
            bdi_size = 24; // 3 segments, 24 bytes
          break;
          case 4:
            //base 8 delta 4
            cp->cfetch->count_encode_0100_b8d4++;
            bdi_size = 40; // 5 segments, 40 bytes
          break;
          case 5:
            //base 4 delta 1
            cp->cfetch->count_encode_0101_b4d1++;
            bdi_size = 24; // 3 segments, 24 bytes
          break;
          case 6:
            //base 4 delta 2
            cp->cfetch->count_encode_0110_b4d2++;
            bdi_size = 40; // 5 segments, 40 bytes
          break;
          case 7:
            //base 2 delta 1
            cp->cfetch->count_encode_0111_b2d1++;
            bdi_size = 40; // 5 segments, 40 bytes
          break;
          case 15:
            //decompressed
            cp->cfetch->count_encode_1111_uncompressed++;
            bdi_size = 64; // 8 segments, 64 bytes
          break;
        }

    cp->cfetch->size_uncompressed += 64;
    cp->cfetch->size_compressed += bdi_size;

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

  cp->cfetch->sim_tag_static_power += (now - cp->cfetch->last_cache_access) * cp->cfetch->cacti_tag_static_power;
  cp->cfetch->sim_data_static_power += (now - cp->cfetch->last_cache_access) * cp->cfetch->cacti_data_static_power;

  // On cache miss, tag read will occur for read and write operation

  cp->cfetch->sim_tag_read_dynamic_energy += cp->cfetch->cacti_tag_read_dynamic_energy;

  // On cache miss, read operation, there will be 1 tag write, 1 data write, 0 data read

  if (cmd == Read) {
                     cp->cfetch->sim_tag_write_dynamic_energy += cp->cfetch->cacti_tag_write_dynamic_energy;
                     cp->cfetch->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cfetch->cacti_data_write_dynamic_energy;
                   }

  // On cache miss, write operation, there will be 1 tag write (plus a dirty bit write), 1 data write, 0 data reads

  if (cmd == Write) {
                      cp->cfetch->sim_tag_write_dynamic_energy += cp->cfetch->cacti_tag_write_dynamic_energy;
                      cp->cfetch->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cfetch->cacti_data_write_dynamic_energy;
  
                    }

  cp->cfetch->last_cache_access = now;

  char vcdbuf1[32];
  sprintf(vcdbuf1, "#%llu", (unsigned long long) (1000/cp->cfetch->compressor_frequency)*now);

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

  if  ( cp->cfetch->cVCDname[0] != '\0' && cp->cfetch->bdi_compress) {
  fp = fopen(cp->cfetch->cVCDname, "a");
  fprintf(fp, vcdbuf1);
  fprintf(fp, "\n");
  fprintf(fp, vcdbuf2);
  fprintf(fp, "\n");
  fclose(fp);
  }

  }

  strcpy(last_vcdbuf2, vcdbuf2);

}
else
{

// mem is null in cache_access call

}

*encode = bdi_encode;
*mask = bdi_mask;

}


//

int cfetch_cache_hit (enum mem_cmd cmd, struct cache_t *cp, struct mem_t *mem, md_addr_t addr, tick_t now, struct cache_blk_t *blk) {

  signed long long db[64], db8[64];
  signed long db4[64];
  signed short db2[64];
  char vcddb[64];
  int i, j;

  int bdi_size = 64;

  md_addr_t tag = CACHE_TAG(cp, addr);
  md_addr_t set = CACHE_SET(cp, addr);
  md_addr_t bofs = CACHE_BLK(cp, addr);

//TODO only do this on read, not write hit, what to do on write?

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

  // This is a compressed HIT
  // blk->ready = now + cp->hit_latency + cp->decompression_latency;

  char dvcdbuf1[32];
  sprintf(dvcdbuf1, "#%llu", (unsigned long long) (1000/cp->cfetch->compressor_frequency)*now);

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

  if  ( cp->cfetch->dVCDname[0] != '\0' ) {
  fp = fopen(cp->cfetch->dVCDname, "a");
  fprintf(fp, dvcdbuf1);
  fprintf(fp, "\n");
  fprintf(fp, dvcdbuf2);
  fprintf(fp, "\n");
  fprintf(fp, dvcdbuf3);
  fprintf(fp, "\n");
  fclose(fp);
  }

  }

  strcpy(last_dvcdbuf2, dvcdbuf2);
  strcpy(last_dvcdbuf3, dvcdbuf3);
}
}
  // Static energy is updated every cache access, regardless of operation and hit result  

  cp->cfetch->sim_tag_static_power += (now - cp->cfetch->last_cache_access) * cp->cfetch->cacti_tag_static_power;
  cp->cfetch->sim_data_static_power += (now - cp->cfetch->last_cache_access) * cp->cfetch->cacti_data_static_power;

  // On cache hit, tag read will occur for read and write operation

  cp->cfetch->sim_tag_read_dynamic_energy += cp->cfetch->cacti_tag_read_dynamic_energy;

  // On cache hit, read operation, there will be 0 tag writes, 0 data writes, 1 data read

  if (cmd == Read) { 

    cp->cfetch->sim_data_read_dynamic_energy += (double) bdi_size / cp->bsize * cp->cfetch->cacti_data_read_dynamic_energy;

  }

  // On cache hit, write operation, there will be 0 tag writes, 1 data write, 0 data reads

  if (cmd == Write) {
                      cp->cfetch->sim_data_write_dynamic_energy += (double) bdi_size / cp->bsize * cp->cfetch->cacti_data_write_dynamic_energy;
                    }

  cp->cfetch->last_cache_access = now;






if (cmd == Read && cp->cfetch->bdi_compress && bdi_size != 64) { 
    cp->cfetch->compressed_hits++;
    cp->cfetch->last_compressed_size = bdi_size;
    return cp->hit_latency + cp->cfetch->decompression_latency;
  }
  else {
    return cp->hit_latency;
  }


}


//



struct cfetch_io *cfetch_init_cache (struct cache_t *cp) {

struct cfetch_io *cf;
cf = (struct cfetch_io *) malloc ( sizeof (struct cfetch_io) );

cf->bdi_check = 0;
cf->bdi_compress = 0;
cf->write_vcd = 0;

cf->sim_tag_static_power = 0;
cf->sim_tag_read_dynamic_energy = 0;
cf->sim_tag_write_dynamic_energy = 0;
cf->sim_data_static_power = 0;
cf->sim_data_read_dynamic_energy = 0;
cf->sim_data_write_dynamic_energy = 0;
cf->last_cache_access = 0;

cf->compressed_hits = 0;
cf->last_compressed_size = 64;

cf->count_check_lines = 0;
cf->count_compressible_any = 0;

cf->count_encode_lines = 0;
cf->count_encode_0000_zeros = 0;
cf->count_encode_0001_repeats = 0;
cf->count_encode_0010_b8d1 = 0;
cf->count_encode_0011_b8d2 = 0;
cf->count_encode_0100_b8d4 = 0;
cf->count_encode_0101_b4d1 = 0;
cf->count_encode_0110_b4d2 = 0;
cf->count_encode_0111_b2d1 = 0;
cf->count_encode_1111_uncompressed = 0;

cf->size_uncompressed = 0;
cf->size_compressed = 0;

strcpy(cf->cVCDname, "");
strcpy(cf->dVCDname, "");

return cf;

}

void cfetch_init_blk (struct cache_blk_t *blk) {
	blk->bdi_encode = (byte_t) -1;
	blk->bdi_mask = (sword_t) -1;

}

void cfetch_update_blk (struct cache_blk_t *blk, byte_t bdi_encode, qword_t bdi_mask) {
	blk->bdi_encode = (byte_t) bdi_encode;
        blk->bdi_mask = (sword_t) bdi_mask;
}
