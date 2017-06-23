//rcp_cache.h

void rcp_cache_reg_stats ( struct cache_t *cp, struct stat_sdb_t *sdb );
void rcp_init_cache (struct cache_t *cp) ;
void rcp_init_blk (struct cache_blk_t *blk) ;
void rcp_update_blk (struct cache_blk_t *blk, byte_t bdi_encode, qword_t bdi_mask) ;
void rcp_cache_miss (enum mem_cmd cmd, struct cache_t *cp, struct mem_t *mem, md_addr_t addr, tick_t now, byte_t *bdi_encode, qword_t *bdi_mask) ;
int rcp_cache_hit (enum mem_cmd cmd, struct cache_t *cp, struct mem_t *mem, md_addr_t addr, tick_t now, struct cache_blk_t *blk) ;




