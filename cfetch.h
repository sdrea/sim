/* 
 * cfetch - a variant of SimpleScalar developed for modelling cache compression and prefetching
 * based on sim-wattch-1.02e - http://www.eecs.harvard.edu/~dbrooks/wattch-form.html
 * changes are commented //sdrea
 *
 * Sean Rea
 * sdrea@lakeheadu.ca
 * 2016-2017
 */

/* cfetch.h - compression and prefetching interfaces */

void cfetch_cache_reg_stats ( struct cache_t *cp, struct stat_sdb_t *sdb );
struct cfetch_io *cfetch_init_cache (struct cache_t *cp) ;
void cfetch_init_blk (struct cache_blk_t *blk) ;
void cfetch_update_blk (struct cache_blk_t *blk, byte_t bdi_encode, qword_t bdi_mask) ;
void cfetch_cache_miss (enum mem_cmd cmd, struct cache_t *cp, struct mem_t *mem, md_addr_t addr, tick_t now, byte_t *bdi_encode, qword_t *bdi_mask) ;
int cfetch_cache_hit (enum mem_cmd cmd, struct cache_t *cp, struct mem_t *mem, md_addr_t addr, tick_t now, struct cache_blk_t *blk) ;

struct cfetch_io {

  int bdi_compress; 
  int bdi_check;
  int write_vcd; 


  double cacti_tag_static_power;
  double cacti_tag_read_dynamic_energy;
  double cacti_tag_write_dynamic_energy;
  double cacti_data_static_power;
  double cacti_data_read_dynamic_energy;
  double cacti_data_write_dynamic_energy;


  int decompression_latency;


  double sim_tag_static_power;
  double sim_tag_read_dynamic_energy;
  double sim_tag_write_dynamic_energy;
  double sim_data_static_power;
  double sim_data_read_dynamic_energy;
  double sim_data_write_dynamic_energy;


  tick_t last_cache_access;


  int compressor_frequency;


  tick_t compressed_hits;
  int last_compressed_size;

 
  counter_t count_check_lines;
  counter_t count_compressible_any;


  counter_t count_encode_lines;
  counter_t count_encode_0000_zeros;
  counter_t count_encode_0001_repeats;
  counter_t count_encode_0010_b8d1;
  counter_t count_encode_0011_b8d2;
  counter_t count_encode_0100_b8d4;
  counter_t count_encode_0101_b4d1;
  counter_t count_encode_0110_b4d2;
  counter_t count_encode_0111_b2d1;
  counter_t count_encode_1111_uncompressed;


  counter_t size_uncompressed;
  counter_t size_compressed;


  char cVCDname[256];
  char dVCDname[256];


};


