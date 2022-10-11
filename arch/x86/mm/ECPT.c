
#include <asm/ECPT.h>
#include <asm/ECPT_defs.h>
#include <asm/ECPT_interface.h>

#include <linux/panic.h>

#include <asm/pgalloc.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/slab.h>

#include "ecpt_crc.h"

#ifdef CONFIG_DEBUG_BEFORE_CONSOLE
#include <asm/early_debug.h>
#else

#undef DEBUG_STR
#define DEBUG_STR(__x)
#undef DEBUG_VAR
#define DEBUG_VAR(__x)

#endif


uint32_t way_to_crN[ECPT_MAX_WAY]= {ECPT_WAY_TO_CR_SEQ};
pte_t pte_default = {.pte = 0};


#define puthex_tabtabln(num) { \
		debug_putstr(tab); \
		debug_putstr(tab); \
		debug_puthex(num); \
		debug_putstr(line_break); \
	}

static uint64_t gen_hash_64(uint64_t vpn, uint64_t size, uint32_t way) {
	uint64_t hash = ecpt_crc64_hash(vpn, way);
    hash = hash % size;

    return hash;
}

static uint64_t early_gen_hash_64(uint64_t vpn, uint64_t size, uint32_t way, uint64_t kernel_start, uint64_t physaddr) {
	uint64_t hash;
	hash = ecpt_crc64_hash_early(vpn, way, kernel_start, physaddr);
	hash = hash % size;
    return hash;
}

// #define puthexln(num)
// #define puthex_tabln(num)

 #define puthexln(num) { \
		debug_puthex(num); \
		debug_putstr(line_break); \
	} 

#define puthex_tabln(num) { \
		debug_putstr(tab); \
		debug_puthex(num); \
		debug_putstr(line_break); \
	}

/**
 * @brief Get a way different from @cur_way
 * 
 * @param cur_way 	current way number
 * @param n_way 	number of ways in this ECPT
 * @return uint32_t 
 */
static uint32_t get_diff_rand(uint32_t cur_way, uint32_t n_way) {
	
	uint32_t way = cur_way;


	if (n_way == 1) return way;

	// DEBUG_VAR(rng_is_initialized());
	
	do
	{
		if (rng_is_initialized()) {
			// pr_info_verbose("call get random\n");
			way = get_random_u32();
		} else {
			way += 1;
		}

		way = way % n_way;
	} while (way == cur_way);
	
	return way;
}

static uint32_t round_robin_way = 0;
static uint32_t get_rand_way(uint32_t n_way) {
	uint32_t way = 0;

	if (rng_is_initialized()) {
		way = get_random_u32();
	} else {
		way = round_robin_way++;
	}

	return way % n_way;	
}

/**
 * @brief 
 * 
 * @param ecpt  pointer has not been fixed up, but cr values should be fixed up
 * @param vaddr 
 * @param paddr 
 * @param prot 
 * @param kernel_start 
 * @param physaddr 
 * @return int 
 */

static void * fixup_pointer(void *ptr, uint64_t kernel_start, uint64_t physaddr)
{
	return (void * )((uint64_t) ptr - kernel_start + physaddr);
} 



int early_ecpt_insert(
	ECPT_desc_t * ecpt,
	uint64_t vaddr, 
	uint64_t paddr, 
	ecpt_pgprot_t prot, 
	uint64_t kernel_start, 
	uint64_t physaddr
) {

	uint64_t size;
	uint64_t hash;
	uint64_t vpn;
	uint64_t cr;

	ECPT_desc_t * ecpt_fixed;
	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr;

	ecpt_entry_t entry, temp;
	static uint16_t way = 0;
	uint16_t tries = 0;

	char tab[2] = "\t";
	char line_break[2] = "\n";

	if (!ECPT_2M_WAY) return -1;
	ecpt_fixed = (ECPT_desc_t *) fixup_pointer(ecpt, kernel_start, physaddr);

	/* this function always run with two 2MB */
	way += 1;
	way = way % ECPT_2M_WAY;
	// get_random_bytes(&way, 2);
	// way = way % ECPT_2M_WAY;
	

	vpn = ADDR_TO_PAGE_NUM_2MB(vaddr);

	entry.pte = ADDR_REMOVE_OFFSET_2MB(paddr) | ecpt_pgprot_val(prot);
	entry.VPN_tag = vpn;

	if (!(entry.pte & _PAGE_PRESENT)) {
		return 0;
	}

	puthexln(vaddr);

	for (tries = 0; tries < ECPT_INSERT_MAX_TRIES; tries++) {
		// puthex_tabln(way);
		cr = ecpt_fixed->table[ECPT_4K_WAY + way];

		/* fixup cr here, because it is the virtual address to ecpt table */
		cr = (uint64_t) fixup_pointer((void *) cr, kernel_start, physaddr);
		
		size = GET_HPT_SIZE(cr);
		// puthex_tabln(vpn);

		hash = early_gen_hash_64(entry.VPN_tag, size, ECPT_4K_WAY + way, kernel_start, physaddr);
		// puthex_tabln(hash);
		ecpt_base = (ecpt_entry_t *) GET_HPT_BASE_VIRT(cr);
		entry_ptr = &ecpt_base[hash];
		
		if (!ecpt_entry_present(entry_ptr)) {
			/* can insert here */
						
			set_ecpt_entry(entry_ptr, entry);
			puthex_tabln((uint64_t) entry_ptr);
			puthex_tabln(entry_ptr->pte);

			ecpt_fixed->occupied[ECPT_4K_WAY + way] += 1;
			return 0;
		} else {
			/* swap and insert again */

			temp = *entry_ptr;
			set_ecpt_entry(entry_ptr, entry);
			entry = temp;
		}	
		
		way += 1;
		way = way % ECPT_2M_WAY;
	// 	do
	// 	{
	// 		way += 1;
	// way = way % ECPT_2M_WAY;
	// 	} while (way == new_way);
		
		// way = new_way;

	}

	debug_putstr(line_break);

	return -1;

}

int early_ecpt_invalidate(ECPT_desc_t * ecpt, uint64_t vaddr) {
	uint32_t way_start = ECPT_4K_WAY;
	uint32_t way_end = ECPT_4K_WAY + ECPT_2M_WAY;
	uint32_t w;

	uint64_t cr, size, hash;
	uint64_t vpn = ADDR_TO_PAGE_NUM_2MB(vaddr);

	ecpt_entry_t *entry_ptr, *ecpt_base;
	// DEBUG_VAR(vaddr);
	if (!ECPT_2M_WAY) return -2;

	for (w = way_start; w < way_end; w++) {


		cr = ecpt->table[w];
		size = GET_HPT_SIZE(cr);

		if (size == 0) {
			/* early tables shoundn't hit here */
			BUG();
		}

		hash = gen_hash_64(vpn, size, w);
		
		/* stay with current hash table */
		ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);
		entry_ptr = &ecpt_base[hash];

		if (entry_ptr->VPN_tag == vpn) {
			// DEBUG_VAR((uint64_t)entry_ptr);
			break;
		} else {
			/* not found move on */
			entry_ptr = NULL;
		}
	}

	if (!entry_ptr) {
		return -1;
	}
	/* clear entry  */
	memset(entry_ptr, 0, sizeof(*entry_ptr));
	ecpt->occupied[w] -= 1;
	return 0;
}

/*
static Granularity way_to_granularity(uint32_t way) {
	if (way < ECPT_4K_WAY) {
		return page_4KB;
	} else if (way < ECPT_4K_WAY + ECPT_2M_WAY) {
		return page_2MB;
	} else if (way < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
		return page_1GB;
	} else {
		return unknown;
	}
}
*/

static uint64_t way_to_vpn(uint32_t way, uint64_t vaddr) {
	if (way < ECPT_4K_WAY) {
		return ADDR_TO_PAGE_NUM_4KB(vaddr); 
	} 
	else if (way < ECPT_4K_WAY + ECPT_2M_WAY) {
		return ADDR_TO_PAGE_NUM_2MB(vaddr); 
	} 
	else if (way < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
		return ADDR_TO_PAGE_NUM_1GB(vaddr); 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {
		return ADDR_TO_PAGE_NUM_4KB(vaddr); 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
		return ADDR_TO_PAGE_NUM_2MB(vaddr); 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY) {
		return ADDR_TO_PAGE_NUM_1GB(vaddr); 
	}
	else {
		BUG();
		return 0;
	}
}

static uint64_t way_to_gran(uint32_t way) {
	if (way < ECPT_4K_WAY) {
		return page_4KB; 
	} 
	else if (way < ECPT_4K_WAY + ECPT_2M_WAY) {
		return page_2MB; 
	} 
	else if (way < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
		return page_1GB; 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {
		return page_4KB; 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
		return page_2MB;
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY) {
		return page_1GB;
	}
	else {
		BUG();
		return 0;
	}
}

/* LOG helper function, support integer up to 32 bits */
#define LOG_1(n) (((n) >= 2) ? 1 : 0)
#define LOG_2(n) (((n) >= 1<<2) ? (2 + LOG_1((n)>>2)) : LOG_1(n))
#define LOG_4(n) (((n) >= 1<<4) ? (4 + LOG_2((n)>>4)) : LOG_2(n))
#define LOG_8(n) (((n) >= 1<<8) ? (8 + LOG_4((n)>>8)) : LOG_4(n))
#define LOG(n)   (((n) >= 1<<16) ? (16 + LOG_8((n)>>16)) : LOG_8(n))

static uint64_t alloc_way_default(uint32_t n_entries) {
	uint64_t addr, cr;
	uint64_t nr_pages = EPCT_NUM_ENTRY_TO_NR_PAGES (n_entries);
	uint32_t order = LOG(nr_pages);
	
	// pr_info_verbose("order=%x\n", order);
	WARN(n_entries * sizeof(ecpt_entry_t) != nr_pages << PAGE_SHIFT,
		"Page trunc off n_entries=%x nr_pages=%llx\n", n_entries, nr_pages );
	WARN(1 << order != nr_pages, 
		"Trunc off during log operation order=%x nr_pages=%llx\n", order, nr_pages );
	addr = __get_free_pages(GFP_PGTABLE_USER, order);

	if (!addr) {
		return 0;
	}
	
	WARN(addr & HPT_SIZE_MASK, "addr=%llx not 4K aligned\n", addr);

	cr = addr + HPT_NUM_ENTRIES_TO_CR3(n_entries);
	return cr;
}

static void free_one_way(uint64_t cr) {
	uint32_t n_entries = GET_HPT_SIZE(cr);
	uint64_t nr_pages = EPCT_NUM_ENTRY_TO_NR_PAGES (n_entries);
	uint32_t order = LOG(nr_pages);

	uint64_t base = GET_HPT_BASE_VIRT(cr);
	
	WARN(n_entries * sizeof(ecpt_entry_t) != nr_pages << PAGE_SHIFT,
		"Page trunc off n_entries=%x nr_pages=%llx\n", n_entries, nr_pages );
	WARN(1 << order != nr_pages, 
		"Trunc off during log operation order=%x nr_pages=%llx\n", order, nr_pages );

	free_pages(base, order);
}

static inline uint64_t alloc_4K_way_default(void) {
	uint64_t cr = alloc_way_default(ECPT_4K_PER_WAY_ENTRIES);
	WARN(!cr, "cannot allocate %x entries total size=%lx\n",
		ECPT_4K_PER_WAY_ENTRIES, ECPT_4K_PER_WAY_ENTRIES * sizeof(ecpt_entry_t));
	return cr;
}

static inline uint64_t alloc_2M_way_default(void) {
	uint64_t cr = alloc_way_default(ECPT_2M_PER_WAY_ENTRIES);
	WARN(!cr, "cannot allocate %x entries total size=%lx\n",
		ECPT_2M_PER_WAY_ENTRIES, ECPT_2M_PER_WAY_ENTRIES * sizeof(ecpt_entry_t));
	return cr;
}

static inline uint64_t alloc_1G_way_default(void) {
	uint64_t cr = alloc_way_default(ECPT_1G_PER_WAY_ENTRIES);
	WARN(!cr, "cannot allocate %x entries total size=%lx\n",
		ECPT_1G_PER_WAY_ENTRIES, ECPT_1G_PER_WAY_ENTRIES * sizeof(ecpt_entry_t));
	return cr;
}

/**
 * @brief 
 * 	only allocate user ways. kernel ways are copied from init_mm.map_desc
 * 		or the PTI kernel ways
 * @return void* The ECPT desc
 */
static ECPT_desc_t * map_desc_alloc_default(void) {
	ECPT_desc_t * desc;
	uint16_t way = ECPT_KERNEL_WAY;
	desc = kzalloc(sizeof(ECPT_desc_t), GFP_PGTABLE_USER);
	
	WARN(!desc, "cannot allocate ecpt_desc=%lx\n", sizeof(ECPT_desc_t));
	if (desc == NULL)
		goto out;

	// dump_stack();
	// mm->map_desc = desc;

	for (; way < ECPT_TOTAL_WAY; way++) {
		if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {

			if (ECPT_4K_WAY_EAGER) {
				desc->table[way] = alloc_4K_way_default();
			} else {
				desc->table[way] = 0;
			}

		} else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
			
			if (ECPT_2M_WAY_EAGER) {
				desc->table[way] = alloc_2M_way_default();
			} else {
				desc->table[way] = 0;
			}
				
		} else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY) {
			
			if (ECPT_2M_WAY_EAGER) {
				desc->table[way] = alloc_1G_way_default();
			} else {
				desc->table[way] = 0;
			}
		
		} else {
			/* should not enter here */
			BUG();
		}
	}

	return desc;
out:
	return NULL;
}


/**
 * @brief copy all kernel entries 
 * 		Right now, copy all since we don't have user entries yet
 * 
 * @param dest 
 * @param src 
 */
static void ecpt_kernel_copy(ECPT_desc_t * dest, ECPT_desc_t * src) {
	// uint16_t w = 0;
	WARN(src != &ecpt_desc, 
			"copy from %llx (not kernel ecpt_desc) to %llx",
			(uint64_t) src, (uint64_t) dest);

	/* ad hoc cuz we only have kernel mapping entries for now */
	memcpy(dest->table, src->table, sizeof(dest->table[0]) * ECPT_KERNEL_WAY);
	memcpy(dest->occupied, src->occupied, sizeof(dest->occupied[0]) * ECPT_KERNEL_WAY);
}

static inline void ecpt_set_mm(ECPT_desc_t * ecpt, struct mm_struct *mm) {
	ecpt->mm = mm; 
}

static inline void ecpt_list_add(ECPT_desc_t * ecpt) {
	list_add(&ecpt->lru, &pgd_list);
}

static inline void ecpt_list_del(ECPT_desc_t * ecpt) {
	list_del(&ecpt->lru);
}

static void ecpt_ctor(struct mm_struct *mm, ECPT_desc_t * new_desc) {

	ecpt_kernel_copy(new_desc, (ECPT_desc_t *) init_mm.map_desc);
	
	/* list required to sync kernel mapping updates */
	if (!SHARED_KERNEL_PMD) {
		ecpt_set_mm(new_desc, mm);
		ecpt_list_add(new_desc);
	}
}

static void ecpt_dtor(ECPT_desc_t * ecpt)
{
	if (SHARED_KERNEL_PMD)
		return;

	spin_lock(&pgd_lock);
	ecpt_list_del(ecpt);
	spin_unlock(&pgd_lock);
}

/**
 * TODO: fix name
 * 
 * @param mm 
 * @return void* 
 */
void * pgd_alloc(struct mm_struct *mm) {
	void* desc = map_desc_alloc_default();
	uint32_t n_entries = 0, i = 0, bytes_need;

	WARN(!desc, "map_desc_alloc_default fails\n");
	
	mm->map_desc = desc;

	/**
	 * no need to preallocate any PMD or copy kernel PGD entries here
	 * 	we don't need such preallocation 
	 */
	
	spin_lock(&pgd_lock);
	ecpt_ctor(mm, desc);
	spin_unlock(&pgd_lock);

	/* Update pgtables_bytes */
	for (i = ECPT_KERNEL_WAY; i < ECPT_TOTAL_WAY; i++) {
		n_entries = GET_HPT_SIZE(((ECPT_desc_t * ) desc)->table[i]);
		bytes_need = n_entries * sizeof(ecpt_entry_t);
		atomic_long_add(bytes_need,  &mm->pgtables_bytes); 
	}

	pr_info_verbose("Create ecpt at %llx for mm at %llx\n",
		(uint64_t) desc, (uint64_t) mm);
	return desc;
}


/**
 * @brief free pgd in the ECPT way
 * 
 * @param mm  
 * @param map_desc we save the type of pgd_t to avoid change the entire code base
 */
void pgd_free(struct mm_struct *mm, pgd_t *map_desc) {
	// ECPT_desc_t * ecpt = (ECPT_desc_t *) map_desc;
	ECPT_desc_t * ecpt = (ECPT_desc_t *) mm->map_desc;
	uint16_t i = 0;
	uint32_t n_entries = 0, bytes_need;
	pr_info_verbose("Destroy ecpt at %llx\n", (uint64_t) ecpt);
	// dump_stack();
	// print_ecpt(ecpt);
	
	for (i = ECPT_KERNEL_WAY; i < ECPT_TOTAL_WAY; i++) {
		free_one_way(ecpt->table[i]);

		n_entries = GET_HPT_SIZE(ecpt->table[i]);
		bytes_need = n_entries * sizeof(ecpt_entry_t);
		atomic_long_sub(bytes_need,  &mm->pgtables_bytes); 
	}



	ecpt_dtor(ecpt);
	kfree(ecpt);
}
/**
 * @brief based on vaddr and granularity
 * 	select all possible ways that can contain such entries
 */

static void select_way(
	uint64_t vaddr, Granularity gran, /* input */
	uint32_t * way_start, uint32_t * way_end, uint64_t * vpn /* output */
) {
	uint16_t is_kernel_vaddr = IS_KERNEL_MAP(vaddr);

	if (gran == page_4KB) {	
		if (is_kernel_vaddr) {
			*way_start = 0;
			*way_end = ECPT_4K_WAY;
		} else {
			*way_start = ECPT_KERNEL_WAY;
			*way_end = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY;
		}
		
		*vpn = ADDR_TO_PAGE_NUM_4KB(vaddr); 
	} 
	else if (gran == page_2MB) {
		if (is_kernel_vaddr) {
			*way_start = ECPT_4K_WAY;
			*way_end = ECPT_4K_WAY + ECPT_2M_WAY;
		} else {
			*way_start = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY;
			*way_end = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY;
		}

		*vpn = ADDR_TO_PAGE_NUM_2MB(vaddr); 
	} 
	else if (gran == page_1GB) {
		if (is_kernel_vaddr) {
			*way_start = ECPT_4K_WAY + ECPT_2M_WAY;
			*way_end = ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY;
		} else {
			*way_start = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY;
			*way_end = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY;
		}

		*vpn = ADDR_TO_PAGE_NUM_1GB(vaddr); 
	} 
	else if (gran == unknown) {
		/* unknown granularity */
		if (is_kernel_vaddr) {
			*way_start = 0;
			*way_end = ECPT_KERNEL_WAY;
		} else {
			*way_start = ECPT_KERNEL_WAY;
			*way_end = ECPT_KERNEL_WAY + ECPT_USER_WAY;
		}

		*vpn = 0;
	} else {
		BUG();
	}

}

static void fix_lazy_ECPT(ECPT_desc_t * ecpt , Granularity gran) {
	uint64_t (*way_allocator) (void);
	uint32_t way_start, way_end, way;
	uint64_t tmp;

	if (gran == page_4KB) {
		way_allocator = &alloc_4K_way_default;
	} else if (gran == page_2MB) {
		way_allocator = &alloc_2M_way_default;
	} else if (gran == page_1GB) {
		way_allocator = &alloc_1G_way_default;
	} else {
		way_allocator = NULL;
		WARN(1, "gran=%d\n", gran);
		return;
	}

	select_way(
		0x1000, /* we only fix up user page table */
		gran,
		&way_start,
		&way_end,
		&tmp /* place holder */
	);

	pr_info_verbose("fixup for way_start=%x way_end=%x\n", way_start, way_end);
	for (way = way_start; way < way_end; way++) {
		ecpt->table[way] = way_allocator();
	}
	
}	

ecpt_entry_t * get_hpt_entry(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity * g, uint32_t * way) {

	uint64_t size, hash, vpn, cr, rehash_ptr = 0;

	uint32_t w = 0, way_start, way_end;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr = NULL;
	ecpt_entry_t entry;
	Granularity gran = *g;
	/* this m */
	
	select_way(
		vaddr, gran,		/* input */
		&way_start, &way_end, &vpn	/* output */
	);


	for (w = way_start; w < way_end; w++) {
		if (gran == unknown) {
			vpn = way_to_vpn(w, vaddr);
		}

		cr = ecpt->table[w];
		size = GET_HPT_SIZE(cr);

		if (size == 0) {
			/* way that has not been built becuase of lazy alloc of ECPT */
			continue;
		}

		hash = gen_hash_64(vpn, size, w);
		
		// DEBUG_VAR(hash);
		// DEBUG_VAR(w);

		if (hash < rehash_ptr) {
            /* not supported for resizing now */
            /* rehash_ptr MBZ right now */
            panic("no rehash support!\n");
        } else {
			/* stay with current hash table */
            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);
            entry_ptr = &ecpt_base[hash];

		}
		// pr_info_verbose("looking at entry_ptr at %llx {.vpn=%llx .pte=%llx} vpn=%llx\n", 
			// (uint64_t) entry_ptr, entry_ptr->VPN_tag, entry_ptr->pte, vpn);
        entry = *entry_ptr;

		// DEBUG_VAR(entry.VPN_tag);
		if (entry.VPN_tag == vpn) {
			// pr_info_verbose("found at %llx vaddr=%llx\n", (uint64_t) entry_ptr, vaddr);
			// DEBUG_VAR((uint64_t) entry_ptr);
			if (gran == unknown) *g = way_to_gran(w);
			*way = w;
			return entry_ptr;
		} else {
			/* not found move on */
			entry_ptr = NULL;
		}
	}
	// pr_info_verbose("Not Found! vaddr=%llx\n", vaddr);
	*g = unknown;
	*way = -1;
	return entry_ptr;
}

ecpt_entry_t * ecpt_search_fit(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity gran) {

	uint64_t size, hash, vpn, cr, rehash_ptr = 0;

	uint32_t w = 0, way_start, way_end;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr = NULL;
	ecpt_entry_t entry;
	/* this m */
	ecpt_entry_t * empty_slots[ECPT_TOTAL_WAY];
	ecpt_entry_t * evict_slots[ECPT_TOTAL_WAY];
	uint16_t empty_i = 0, evict_i = 0;
	if (gran == unknown) {
		return NULL;
	}

	select_way(
		vaddr, gran,		/* input */
		&way_start, &way_end, &vpn	/* output */
	);


	for (w = way_start; w < way_end; w++) {

		cr = ecpt->table[w];
		size = GET_HPT_SIZE(cr);

		if (size == 0) {
			/* way that has not been built becuase of lazy alloc of ECPT */
			continue;
		}

		hash = gen_hash_64(vpn, size, w);
		
		if (hash < rehash_ptr) {
            /* not supported for resizing now */
            /* rehash_ptr MBZ right now */
            panic("no rehash support!\n");
        } else {
			/* stay with current hash table */
            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);
            entry_ptr = &ecpt_base[hash];

		}
        entry = *entry_ptr;

		if (entry.VPN_tag == vpn) {
			
			return entry_ptr;
		} else if (entry.pte == 0){
			/* not found, but entry empty */
			empty_slots[empty_i++] = entry_ptr;
			entry_ptr = NULL;
		} else {
			evict_slots[evict_i++] = entry_ptr;	
			entry_ptr = NULL;
		}
	}

	if (empty_i > 0) {
		entry_ptr = empty_slots[get_rand_way(empty_i)];
		// pr_info_verbose("return ptr at %llx vaddr=%llx", (uint64_t) entry_ptr, vaddr);

		return entry_ptr;
	}

	if (evict_i > 0) {
		entry_ptr = evict_slots[get_rand_way(evict_i)];
		/* TODO: eviction */
		return NULL;
	}
	return entry_ptr;
}

int ecpt_insert(ECPT_desc_t * ecpt, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, Granularity gran) {
	
	uint64_t size, hash, vpn, cr, rehash_ptr = 0;

	uint32_t way_start = 0, way_end, n_way;
	static uint32_t way = 0;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr;
	ecpt_entry_t entry, temp;

	uint16_t tries = 0;

	// pr_info_verbose("ecpt at %llx vaddr=%llx paddr=%llx prot=%lx gran=%d\n", (uint64_t) ecpt ,vaddr, paddr, prot.pgprot, gran);


	if (gran == unknown) {
		WARN(1, KERN_WARNING "gran=%d\n", gran);
		return -1;
	}

	select_way(
		vaddr, gran,		/* input */
		&way_start, &way_end, &vpn	/* output */
	);
	n_way = way_end - way_start;
	
	/* calculate PPN */
	if (gran == page_4KB) 
	{
		entry.pte = ADDR_REMOVE_OFFSET_4KB(paddr);
	} 
	else if (gran == page_2MB) 
	{
		entry.pte = ADDR_REMOVE_OFFSET_2MB(paddr);
	} 
	else if (gran == page_1GB) 
	{
		entry.pte = ADDR_REMOVE_OFFSET_1GB(paddr);
	} 
	else 
	{
		/* invalid granularity */
		return -1;
	}

	if (n_way == 0) {

		/* invalid size */
		return -2;
	}

	entry.pte = entry.pte | ecpt_pgprot_val(prot);
	if (gran == page_2MB || gran == page_1GB) {
		entry.pte = entry.pte | _PAGE_PSE;
	}

	entry.VPN_tag = vpn;

	way = get_diff_rand(way, n_way);
	// DEBUG_VAR(vaddr);

	for (tries = 0; tries < ECPT_INSERT_MAX_TRIES; tries++) {
		// puthex_tabln(way);
		
		cr = ecpt->table[way_start + way];
		// DEBUG_VAR(cr);
		size = GET_HPT_SIZE(cr);
		if (size == 0) {
			fix_lazy_ECPT(ecpt, gran);
			
			cr = ecpt->table[way_start + way];
			size = GET_HPT_SIZE(cr);
			
			if (!size) {
				// pr_info_verbose("gran=%d way = %d\n", gran, way_start + way);
				BUG_ON(!size);
			}
		}

		hash = gen_hash_64(entry.VPN_tag, size, way_start + way);


		if (hash < rehash_ptr) {
            /* not supported for resizing now */
            /* rehash_ptr MBZ right now */
            panic("no rehash support!\n");
        } else {
			/* stay with current hash table */
            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);
			// DEBUG_VAR((uint64_t)ecpt_base);
            entry_ptr = &ecpt_base[hash];

		}
            
		
		if (!ecpt_entry_present(entry_ptr)) {
			/* can insert here */
			// pr_info_verbose("hash=%llx addr=%llx entry_ptr=%llx pte=%llx\n", 
					// hash, vaddr, (uint64_t) entry_ptr, entry.pte);
			set_ecpt_entry(entry_ptr, entry);
			if (tries > 0) {
				pr_info_verbose("set entry={.vpn=%llx .pte=%llx} at %llx\n", entry.VPN_tag, entry.pte, (uint64_t) entry_ptr);
			}
			ecpt->occupied[way_start + way] += 1;
			return 0;
		} else {
			/* swap and insert again */
			
			temp = *entry_ptr;
			if (temp.VPN_tag == entry.VPN_tag && temp.pte == entry.pte) {
				/* mapping already established, no need to kick it out */
				return 0;
			}
			pr_info_verbose("kick at %llx ={.vpn=%llx .pte=%llx} with entry={.vpn=%llx .pte=%llx} way=%d hash=%llx\n", 
				(uint64_t) entry_ptr, temp.VPN_tag, temp.pte, entry.VPN_tag, entry.pte, way_start + way, hash);
			set_ecpt_entry(entry_ptr, entry);
			entry = temp;
				
		}	
		
		way = get_diff_rand(way, n_way);

	}
	// pr_info_verbose("collision cannot be resolved.\n");
	// pr_info_verbose("collision cannot be resolved: ecpt at %llx vaddr=%llx paddr=%llx prot=%lx gran=%d\n", 
	// 		(uint64_t) ecpt ,vaddr, paddr, prot.pgprot, gran);
	// print_ecpt(ecpt);
	WARN(1, KERN_WARNING"Hash Collision unresolved:\n ecpt at %llx vaddr=%llx paddr=%llx prot=%lx gran=%d\n", 
			(uint64_t) ecpt ,vaddr, paddr, prot.pgprot, gran);
	print_ecpt(&ecpt_desc, 0 /* kernel */, 1 /* user */);
	/* exceed max number of tries */
	return -3;
}

int ecpt_mm_insert(struct mm_struct* mm, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, Granularity gran) {
	int res = 0;

	spin_lock(&mm->page_table_lock);

	res = ecpt_insert(
		(ECPT_desc_t *) mm->map_desc,
		vaddr,
		paddr,
		prot,
		gran
	);
	spin_unlock(&mm->page_table_lock);
	return res;
}

/**
 * @brief code borrowed from https://github.com/sgh185/nautilus/blob/carat-cake-artifact/src/aspace/paging/paging.c
 * 
 * @param mm 
 * @param vaddr 
 * @param vaddr_end 
 * @param paddr 
 * @param paddr_end 
 * @param prot 
 * @return int 
 */

int ecpt_mm_insert_range(
	struct mm_struct* mm, 
	uint64_t vaddr, 
	uint64_t vaddr_end,
	uint64_t paddr, 
	uint64_t paddr_end,
	ecpt_pgprot_t prot
) {
	int res = 0;

	Granularity gran = unknown;
	uint64_t remained = vaddr_end - vaddr;
	uint64_t page_granularity = 0;

	/**
	 * when condiction == T,
	 * 	cond should be the be bad case
	 */
	BUG_ON((vaddr_end - vaddr != paddr_end - paddr));

	while (vaddr < vaddr_end) {
        if (
            ECPT_1G_WAY && 
            vaddr % PAGE_SIZE_1GB == 0 && 
            paddr % PAGE_SIZE_1GB == 0 && 
            remained >= PAGE_SIZE_1GB
        ) {
            gran = page_1GB;
			page_granularity = PAGE_SIZE_1GB;
        } 
        else if (
            ECPT_2M_WAY && 
            vaddr % PAGE_SIZE_2MB == 0 && 
            paddr % PAGE_SIZE_2MB == 0 && 
            remained >= PAGE_SIZE_2MB 
        ) {
            gran = page_2MB;
			page_granularity = PAGE_SIZE_2MB;
        } 
        else if (
            vaddr % PAGE_SIZE_4KB == 0 && 
            paddr % PAGE_SIZE_4KB == 0 && 
            remained >= PAGE_SIZE_4KB 
        ) {
            // vaddr % PAGE_SIZE_4KB == 0
            // must be the case as we require 4KB alignment
            gran = page_4KB;
			page_granularity = PAGE_SIZE_4KB;
        } else {
            pr_err(" doesnot meet drill requirement at vaddr=0x%llx and paddr=0x%llx\n", vaddr, paddr);
            return -1;
        }

		spin_lock(&mm->page_table_lock);

        res = ecpt_insert(
			(ECPT_desc_t *) mm->map_desc,
			vaddr,
			paddr,
			prot,
			gran
		);

		spin_unlock(&mm->page_table_lock);

        if (res < 0) {
            pr_err("Failed to drill at virtual address=%llx"
                    " physical adress %llx"
                    " and ret code of %d"
                    " page_granularity = %llx\n",
                    vaddr, paddr, res, page_granularity
            );
            return res;
        }

        vaddr += page_granularity;
        paddr += page_granularity;
        remained -= page_granularity;
    }

	return res;
}


static bool update_stats = true;

uint32_t find_way_from_ptep(ECPT_desc_t * ecpt, pte_t *ptep) {
	uint32_t way = 0;
	uint64_t cr, size;
	uint64_t table_start, table_end;
	uint64_t ptep_ptr = (uint64_t) ptep;
	
	for (way = 0; way < ECPT_TOTAL_WAY; way++) {
		cr = ecpt->table[way];
		size = GET_HPT_SIZE(cr);

		table_start = GET_HPT_BASE_VIRT(cr);
		table_end = table_start + size * sizeof(ecpt_entry_t);

		if (table_start <= ptep_ptr && ptep_ptr <= table_end) {
			return way;
		}
	}

	return -1;
}

static int ecpt_set_pte(struct mm_struct *mm, pte_t *ptep, pte_t pte, unsigned long addr) {
	ecpt_entry_t * e;
	uint64_t * tag_ptr;
	ECPT_desc_t * ecpt = (ECPT_desc_t *) mm->map_desc;
	uint32_t way = 0;

	WRITE_ONCE(*ptep, pte);
	e = GET_ECPT_P_FROM_PTEP(ptep, addr);
	tag_ptr = (uint64_t *) &e->VPN_tag;
	WRITE_ONCE(*tag_ptr, ADDR_TO_PAGE_NUM_4KB(addr));

	if (update_stats) {
		way = find_way_from_ptep(ecpt, ptep);
		BUG_ON(way == -1);
		// pr_info_verbose("update way at %llx\n", ecpt->table[way]);
		ecpt->occupied[way] += 1;
	}

	pr_info_verbose("entry at %llx {.vpn=%llx .pte=%llx}\n", 
		(uint64_t) e, e->VPN_tag, e->pte);

	return -1;
}


int ecpt_set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte)
{
	int res = 0;

	if (ptep != NULL && ptep != (pte_t *) &pte_default.pte) {
		return ecpt_set_pte(mm, ptep, pte, addr);
	} 

	pr_info_verbose("  set_pte_at 4KB addr=%lx pte=%lx \n", addr, pte.pte);
	res = ecpt_insert(
		mm->map_desc,
		addr,
		ENTRY_TO_ADDR(pte.pte),
		__ecpt_pgprot(ENTRY_TO_PROT(pte.pte)),
		page_4KB
	);

	WARN(res, "Error when insert %lx as 4KB page\n", addr);
	return res;
}

int ptep_set_access_flags(struct vm_area_struct *vma,
			  unsigned long address, pte_t *ptep,
			  pte_t entry, int dirty)
{	
	int changed = 1;
	if (ptep != NULL && ptep != (pte_t *) &pte_default.pte) {
		pr_info_verbose("ptep_set_access_flags addr=%lx pte=%lx with ptep at %llx\n",
			address, entry.pte, (uint64_t) ptep);
		changed = !pte_same(*ptep, entry);

		if (changed && dirty)
			set_pte(ptep, entry);
		return changed;
	} 

	WARN(1, "Invalid set access addr=%lx ptep at %llx entry=%lx\n", address, (uint64_t) ptep, entry.pte );

	return 0;
}	

static pte_t __ecpt_native_ptep_get_and_clear(struct mm_struct *mm, pte_t *ptep, unsigned long addr) {
	ecpt_entry_t * e;
	uint64_t * tag_ptr;

	pte_t ret = READ_ONCE(*ptep);
	pte_t zero = {.pte = 0};
	
	ECPT_desc_t * ecpt = (ECPT_desc_t *) mm->map_desc;
	uint32_t way = 0;

	WRITE_ONCE(*ptep, zero);

	e = GET_ECPT_P_FROM_PTEP(ptep, addr);
	tag_ptr = (uint64_t *) &e->VPN_tag;
	
	WRITE_ONCE(*tag_ptr, 0);

	if (update_stats) {
		way = find_way_from_ptep(ecpt, ptep);
		BUG_ON(way == -1);
		// pr_info_verbose("update way at %llx\n", ecpt->table[way]);
		ecpt->occupied[way] -= 1;
	}

	pr_info_verbose("ptep_get_and_clear 4KB addr=%lx with entry at %llx\n",
			addr, (uint64_t) e);
	return ret;
}

pte_t ecpt_native_ptep_get_and_clear(struct mm_struct *mm,
					unsigned long addr, pte_t *ptep)
{
	pte_t ret;
	int res;
	if (ptep != NULL && ptep != &pte_default) {
		
		return __ecpt_native_ptep_get_and_clear(mm, ptep, addr);
	} 

	ret = READ_ONCE(*ptep);
	res = ecpt_invalidate(mm->map_desc, addr, page_4KB);
	pr_info("Invalidate 4KB addr=%lx\n", addr);
	WARN(res, "Fail to invalid 4KB page %lx \n", addr);
	return ret;
}

int ecpt_invalidate(ECPT_desc_t * ecpt_desc, uint64_t vaddr, Granularity g) {
	

	
	ecpt_entry_t * entry = NULL;
	uint32_t way;
	// DEBUG_VAR(vaddr);
	entry = get_hpt_entry(ecpt_desc, vaddr, &g, &way);
	
	if (entry == NULL) {
		/* no such entry */
		return -1;
	}
	
	entry->pte = 0;

	/**
	 * TODO: if PTE clustering is supported we don't clear VPN_tag
	 */
	entry->VPN_tag = 0;
	ecpt_desc->occupied[way] -= 1;

	// DEBUG_STR("\n");

	return 0;
}

int ecpt_mm_invalidate(struct mm_struct* mm, uint64_t vaddr, Granularity gran) {
	int res = 0;
	spin_lock(&mm->page_table_lock);

	res = ecpt_invalidate(
		(ECPT_desc_t *) mm->map_desc,
		vaddr,
		gran
	);
	spin_unlock(&mm->page_table_lock);
	
	return res;
}

ecpt_entry_t ecpt_peek(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity * gran) {
	ecpt_entry_t empty = {.VPN_tag = 0, .pte = 0};
	uint32_t way_temp;
	ecpt_entry_t * entry_p = get_hpt_entry(ecpt, vaddr, gran, &way_temp);

	if (entry_p == NULL) {
		// pr_warn("WARN: vaddr=%llx gran=%d doesn't exist", vaddr, *gran);
		*gran = unknown;
		return empty;
	}

	return *entry_p;
}

ecpt_entry_t ecpt_mm_peek(struct mm_struct* mm, uint64_t vaddr, Granularity * gran) {

	ecpt_entry_t entry;
	spin_lock(&mm->page_table_lock);

	entry = ecpt_peek(
		(ECPT_desc_t *) mm->map_desc,
		vaddr,
		gran
	);

	spin_unlock(&mm->page_table_lock);

	return entry;
}

int ecpt_update_prot(ECPT_desc_t * ecpt, uint64_t vaddr, ecpt_pgprot_t new_prot, Granularity gran) {

	uint64_t pte_val;
	ecpt_entry_t * entry_p;
	uint32_t way_temp;
	entry_p = get_hpt_entry(ecpt, vaddr, &gran, &way_temp);

	if (entry_p == NULL) {
		WARN(1, KERN_WARNING "entry_p == NULL\n");
		return -1;
	}

	if (!ecpt_entry_present(entry_p)) {
		pr_warn("Cannot update protection for entry that is not present\n");
		return -1;
	}

	pte_val = ENTRY_TO_ADDR(entry_p->pte) | new_prot.pgprot;

	entry_p->pte = pte_val;

	return 0;
}

int ecpt_mm_update_prot(struct mm_struct* mm, uint64_t vaddr, ecpt_pgprot_t new_prot, Granularity gran) {

	int res;
	spin_lock(&mm->page_table_lock);

	// cr3 = (uint64_t) mm->pgd;
	// /* hpt_base is pointer to ecpt_pmd_t, pointer arithmetic, by default, conside the size of the object*/
	res = ecpt_update_prot((ECPT_desc_t *) mm->map_desc, vaddr, new_prot, gran);

	spin_unlock(&mm->page_table_lock);
	// /* hpt_base is pointer to ecpt_pmd_t, pointer arithmetic, by default, conside the size of the object*/
	// return res;
	return 0;
}


/* Why memory clobber here */

/**
 * @brief  ## concatenates symbol together e.g. native_write_cr##N -> native_write_cr1
 * 			# turns input into string tokens e.g. "mov %0,%%cr"#N -> "mov %0,%%cr" "1" -> "mov %0,%%cr1"
 * 
 */
#define DEFINE_native_write_crN(N) \
static inline void native_write_cr##N(unsigned long val) {\
	asm volatile("mov %0,%%cr"#N: : "r" (val) : "memory"); \
}

DEFINE_native_write_crN(1)
DEFINE_native_write_crN(5)
DEFINE_native_write_crN(6)
DEFINE_native_write_crN(7)
DEFINE_native_write_crN(9)
DEFINE_native_write_crN(10)
DEFINE_native_write_crN(11)
DEFINE_native_write_crN(12)

#define DEFINE_load_crN(N) \
	static inline void load_cr##N(uint64_t cr) \
{ \
	native_write_cr##N(__sme_pa(cr)); \
}


DEFINE_load_crN(1)
DEFINE_load_crN(5)
DEFINE_load_crN(6)
DEFINE_load_crN(7)
DEFINE_load_crN(9)
DEFINE_load_crN(10)
DEFINE_load_crN(11)
DEFINE_load_crN(12)

static inline void load_cr3_ECPT(uint64_t cr)
{
	write_cr3(__sme_pa(cr) | CR3_TRANSITION_BIT);
}

typedef void(*load_cr_func)(uint64_t);

static load_cr_func load_funcs[9] = {
	&load_cr3_ECPT,
	&load_cr1,
	&load_cr5,
	&load_cr6,
	&load_cr7,
	&load_cr9,
	&load_cr10,
	&load_cr11,
	&load_cr12
};

/**
 * @brief load ECPT desc tables -> corresponding control registers
 * 
 * @param ecpt 
 */
void load_ECPT_desc(ECPT_desc_t * ecpt) {
	uint16_t i;
	load_cr_func f;
	BUG_ON(ECPT_TOTAL_WAY > ECPT_MAX_WAY);


	/* load ecpt table -> control registers */
	for (i = 1; i < ECPT_TOTAL_WAY; i++) {
		f = load_funcs[i];
		(*f)(ecpt->table[i]);
	}

	/* load cr3 in the end because it it will flush TLB */
	f = load_funcs[0];
	(*f)(ecpt->table[0]);
} 

static void print_ecpt_detail(ECPT_desc_t * ecpt, uint32_t way_start, uint32_t way_end) {
	uint64_t cr, size;
	uint32_t  i, j;
	ecpt_entry_t * ecpt_base, * entry_ptr; 


	for (i = way_start; i < way_end; i++) {
		pr_info("\t 0x%x/0x%llx %llx -> cr%d \n",
			ecpt->occupied[i], GET_HPT_SIZE(ecpt->table[i]), 
			ecpt->table[i], way_to_crN[i]);

		cr = ecpt->table[i];
		size = GET_HPT_SIZE(cr);

		ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);

		for (j = 0; j < size; j++) {
            entry_ptr = &ecpt_base[j];
			if (entry_ptr->VPN_tag != 0) {
				pr_info("\t\t entry at %llx {.vpn=%llx .pte=%llx}\n", 
					(uint64_t) entry_ptr, entry_ptr->VPN_tag, entry_ptr->pte);
			}
		}
	}
}

static inline void print_ecpt_user_detail(ECPT_desc_t * ecpt) {
	print_ecpt_detail(ecpt, ECPT_KERNEL_WAY, ECPT_TOTAL_WAY);
}

static inline void print_ecpt_kernel_detail(ECPT_desc_t * ecpt) {
	print_ecpt_detail(ecpt, 0, ECPT_KERNEL_WAY);
}


void print_ecpt(ECPT_desc_t * ecpt, bool kernel_table_detail, bool user_table_detail) {
	uint16_t i ;	

	if (ecpt == &ecpt_desc) 
		pr_info("show root ECPT ------------------\n");
	else
		pr_info("show ECPT at %llx ------------------\n", (uint64_t) ecpt);
	
	pr_info("Kernel tables: \n");
	for (i = 0; i < ECPT_KERNEL_WAY; i++) {
		pr_info("\t 0x%x/0x%llx %llx -> cr%d \n",
			ecpt->occupied[i], GET_HPT_SIZE(ecpt->table[i]), 
			ecpt->table[i], way_to_crN[i] );
	}

	pr_info("User tables: \n");
	for (i = ECPT_KERNEL_WAY; i < ECPT_TOTAL_WAY; i++) {
		pr_info("\t 0x%x/0x%llx %llx -> cr%d \n",
			ecpt->occupied[i], GET_HPT_SIZE(ecpt->table[i]), 
			ecpt->table[i], way_to_crN[i]);
	}
	
	pr_info("pte_default at %llx\n", (uint64_t) &pte_default);

	if (ecpt->mm == &init_mm)
		pr_info("\tmm = init_mm");
	else 
		pr_info("\tmm at %llx \n", (uint64_t) ecpt->mm);
	
	pr_info("\t ecpt->lru.next=%llx\n", (uint64_t)ecpt->lru.next);
	pr_info("\t ecpt->lru.prev=%llx\n", (uint64_t)ecpt->lru.prev);
	
	if (kernel_table_detail)
		print_ecpt_kernel_detail(ecpt);

	if (user_table_detail)
		print_ecpt_user_detail(ecpt);
	
	pr_info("End of ECPT at %llx ------------------\n", (uint64_t) ecpt);

}





