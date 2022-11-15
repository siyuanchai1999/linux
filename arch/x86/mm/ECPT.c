
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

#define ECPT_WARN(cond, fmt, ...) WARN(cond, fmt,  ##__VA_ARGS__)
#define ECPT_info_verbose(fmt, ...)
// #define ECPT_info_verbose(fmt, ...) printk(KERN_INFO "%s:%d %s " pr_fmt(fmt), __FILE__ , __LINE__ , __func__, ##__VA_ARGS__)

#define PRINT_ECPT_ENTRY_DEBUG(e) PRINT_ECPT_ENTRY_BASE(e, ECPT_info_verbose)
#define PRINT_ECPT_ENTRY_INFO(e) PRINT_ECPT_ENTRY_BASE(e, pr_info)

#define IS_KERNEL_MAP(vaddr) (vaddr >= __PAGE_OFFSET)

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
			// ECPT_info_verbose("call get random\n");
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


static inline uint16_t ecpt_entry_get_valid_pte_num(ecpt_entry_t * e) 
{
	return GET_VALID_PTE_COUNT(e->pte[PTE_IDX_FOR_COUNT]);
}

static inline void ecpt_entry_set_vpn(ecpt_entry_t * e, uint64_t VPN) 
{
	uint16_t i = 0;
	for (; i < ECPT_CLUSTER_FACTOR && i < PTE_IDX_FOR_COUNT; i++) {
		e->pte[i] = 
			PTE_WITH_VPN_CLEARED(e->pte[i]) | PARTIAL_VPN_IN_PTE(VPN, i);
	}
}

static inline void ecpt_entry_set_valid_pte_num(ecpt_entry_t * e, uint16_t num) 
{
	ECPT_WARN(num > ECPT_CLUSTER_FACTOR, "invalid num");
	e->pte[PTE_IDX_FOR_COUNT] = 
		PTE_WITH_VPN_CLEARED(e->pte[PTE_IDX_FOR_COUNT]) | VALID_NUM_IN_PTE(num);
}

static inline void ecpt_entry_inc_valid_pte_num(ecpt_entry_t * e) 
{
	ecpt_entry_set_valid_pte_num(e, ecpt_entry_get_valid_pte_num(e) + 1);
}

static inline void ecpt_entry_dec_valid_pte_num(ecpt_entry_t * e) 
{
	ecpt_entry_set_valid_pte_num(e, ecpt_entry_get_valid_pte_num(e) - 1);
}

static inline int ecpt_entry_match_vpn(ecpt_entry_t *entry, uint64_t vpn) {
	return ecpt_entry_get_vpn(entry) == vpn;
}

static inline int ecpt_entry_vpn_match(ecpt_entry_t * e1, ecpt_entry_t * e2) 
{
	return ecpt_entry_get_vpn(e1) == ecpt_entry_get_vpn(e2);
}

static inline int ecpt_entry_empty_vpn(ecpt_entry_t * e) 
{
	return ecpt_entry_get_valid_pte_num(e) == 0 && ecpt_entry_get_vpn(e) == 0;
}

static inline void ecpt_entry_clear_vpn(ecpt_entry_t * e)
{
	ecpt_entry_set_vpn(e, 0);
	ecpt_entry_set_valid_pte_num(e, 0);
}

static inline bool all_pte_empty_in_entry(ecpt_entry_t * e)
{	
	return ecpt_entry_get_valid_pte_num(e) == 0;
}

inline bool empty_entry(ecpt_entry_t * e) {	
	return ecpt_entry_get_vpn(e) == 0 && all_pte_empty_in_entry(e);
}

static inline void ecpt_entry_clear_ptep(ecpt_entry_t * e,  uint64_t *ptep) 
{
	
	pte_t pte = {.pte = *ptep};
	if (pte_present(pte)) {
		ecpt_entry_dec_valid_pte_num(e);
	}

	WRITE_ONCE(*ptep, CLEAR_PTE_BUT_NOT_VPN(*ptep));
	
	if (all_pte_empty_in_entry(e)) {
		ecpt_entry_clear_vpn(e);
	}	
}

static inline int ecpt_entry_can_merge(ecpt_entry_t * dest, ecpt_entry_t * src) 
{	
	return ecpt_entry_empty_vpn(dest) || ecpt_entry_vpn_match(dest, src);
}

/**
 * @brief merge two ECPT entries with same VPN. 
 * 	Only legal when ecpt_entry_can_merge(dest,src) == true
 * 
 * @param dest dest ecpt_entry_t
 * @param src  src ecpt_entry_t
 * @return int 
 */
static int ecpt_entry_do_merge(ecpt_entry_t * dest, ecpt_entry_t * src) 
{
	unsigned int idx = 0;
	pte_t dest_pte, src_pte;

	if (ecpt_entry_empty_vpn(dest)) {
		/**
		 * set destination vpn if empty
		 */
		ecpt_entry_set_vpn(dest, ecpt_entry_get_vpn(src));
	}

	for(; idx < ECPT_CLUSTER_FACTOR; idx++) {
		dest_pte.pte = dest->pte[idx];
		src_pte.pte = src->pte[idx];
		if (pte_present(src_pte)) {
			if (pte_present(dest_pte) && !pte_same(dest_pte, src_pte)) {
				WARN(1, "Potential PTE collision when merging dest_pte=%lx src_pte=%lx \n",
				 dest_pte.pte, src_pte.pte);
				return -EINVAL;
			}

			ecpt_entry_set_pte_helper(&dest->pte[idx], src_pte.pte);
			ecpt_entry_inc_valid_pte_num(dest);
		}
	}

	return 0;
}

static inline void ecpt_entry_overwrite(ecpt_entry_t * dest, ecpt_entry_t * src) 
{
	*dest = *src;
}

int ecpt_entry_present(ecpt_entry_t * entry, unsigned long addr, Granularity g)
{
	/*
	 * Checking for _PAGE_PSE is needed too because
	 * split_huge_page will temporarily clear the present bit (but
	 * the _PAGE_PSE flag will remain set at all times while the
	 * _PAGE_PRESENT bit is clear).
	 */
	uint64_t *pte;
	if (!(entry->pte)) {
		return 0;
	}
	pte = get_ptep_with_gran(entry, addr, g);
	return (*pte & _PAGE_PRESENT);
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
	pte_t pte;

	ECPT_desc_t * ecpt_fixed;
	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr;
	ecpt_entry_t * empty_slots[ECPT_2M_WAY];
	uint32_t empty_ways[ECPT_2M_WAY];

	ecpt_entry_t entry = {};
	// static uint16_t way = 0;
	uint16_t way = 0, w = 0, empty_i = 0;

	uint32_t way_start = ECPT_4K_WAY;
	uint32_t way_end = ECPT_4K_WAY + ECPT_2M_WAY;
	
	uint32_t i = 0;
	uint64_t * ptr;
	char tab[2] = "\t";
	char line_break[2] = "\n";
	char err[11] = "Error!!!!\n";
	char occupied_plus[11] = "occupied++";

	if (!ECPT_2M_WAY) return -1;
	ecpt_fixed = (ECPT_desc_t *) fixup_pointer(ecpt, kernel_start, physaddr);

	/* this function always run with two 2MB */
	// way += 1;
	// way = way % ECPT_2M_WAY;

	pte.pte = PADDR_TO_PTE_2MB(paddr) | ecpt_pgprot_val(prot);
	if (!(pte_present(pte))) {
		return 0;
	}

	vpn = VADDR_TO_PAGE_NUM_2MB(vaddr);
	ecpt_entry_set_vpn(&entry, vpn);
	ecpt_entry_set_pmd(&entry, pte, vaddr);

	puthexln(vaddr);

	for (w = way_start; w < way_end; w++) {
		cr = ecpt_fixed->table[w];
		cr = (uint64_t) fixup_pointer((void *) cr, kernel_start, physaddr);
		size = GET_HPT_SIZE(cr);

		if (size == 0) {
			/* early tables shoundn't hit here */
			BUG();
		}

		hash = early_gen_hash_64(ecpt_entry_get_vpn(&entry), size, w, kernel_start, physaddr);
		
		/* stay with current hash table */
		ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);
		entry_ptr = &ecpt_base[hash];

		if (ecpt_entry_match_vpn(entry_ptr, vpn)) {
			// DEBUG_VAR((uint64_t)entry_ptr);
			way = w;
			break;
		} else if (empty_entry(entry_ptr)){
			/* not found, but entry empty */
			empty_slots[empty_i] = entry_ptr;
			empty_ways[empty_i++] = w;
			entry_ptr = NULL;
		}
		else {
			/* not found move on */
			entry_ptr = NULL;
		}
	}

	if (entry_ptr) {
		/* valid nothing to do */
	} 
	else if (entry_ptr == NULL && empty_i > 0 ) 
	{
		entry_ptr = empty_slots[++round_robin_way % empty_i];
		way = empty_ways[round_robin_way % empty_i];
	} 
	else 
	{
		debug_putstr(err);
		/* should not be here early ecpt should not invoke kicking */
	}


	puthex_tabln((uint64_t) entry_ptr);
	puthex_tabln(way);
	if (ecpt_entry_empty_vpn(entry_ptr)) {
		debug_putstr(occupied_plus);
		ecpt_fixed->occupied[way]++;
	}
	ecpt_entry_do_merge(entry_ptr, &entry);

	ptr = (uint64_t *) entry_ptr;
	for (i = 0; i * sizeof(uint64_t) < sizeof(ecpt_entry_t); i++ ) {
		puthex_tabln(ptr[i]);
	}

	debug_putstr(line_break);

	return 0;
}

int early_ecpt_invalidate(ECPT_desc_t * ecpt, uint64_t vaddr) {
	uint32_t way_start = ECPT_4K_WAY;
	uint32_t way_end = ECPT_4K_WAY + ECPT_2M_WAY;
	uint32_t w, i;

	uint64_t cr, size, hash;
	uint64_t vpn = VADDR_TO_PAGE_NUM_2MB(vaddr);
	uint64_t * ptr;

	ecpt_entry_t *entry_ptr = NULL, *ecpt_base;
	DEBUG_VAR(vaddr);
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

		if (ecpt_entry_match_vpn(entry_ptr, vpn)) {
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
	ecpt_entry_clear_ptep(entry_ptr, (uint64_t *) pmd_offset_from_ecpt_entry(entry_ptr, vaddr));

	ptr = (uint64_t *) entry_ptr;
	for (i = 0; i * sizeof(uint64_t) < sizeof(ecpt_entry_t); i++ ) {
		DEBUG_VAR(ptr[i]);
	}

	DEBUG_STR("\n");
	if (ecpt_entry_empty_vpn(entry_ptr)) {
		DEBUG_STR("occupied--");
		ecpt->occupied[w] -= 1;
	}
	
	return 0;
}

static uint64_t way_to_vpn(uint32_t way, uint64_t vaddr) {
	if (way < ECPT_4K_WAY) {
		return VADDR_TO_PAGE_NUM_4KB(vaddr); 
	} 
	else if (way < ECPT_4K_WAY + ECPT_2M_WAY) {
		return VADDR_TO_PAGE_NUM_2MB(vaddr); 
	} 
	else if (way < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
		return VADDR_TO_PAGE_NUM_1GB(vaddr); 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {
		return VADDR_TO_PAGE_NUM_4KB(vaddr); 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
		return VADDR_TO_PAGE_NUM_2MB(vaddr); 
	} 
	else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY) {
		return VADDR_TO_PAGE_NUM_1GB(vaddr); 
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
	
	if ((nr_pages << PAGE_SHIFT) < n_entries * sizeof(ecpt_entry_t)) {
		nr_pages++;
		pr_notice("ECPT Allocation Notice: "
			"Increase number of pages by one to avoid truncation" 	
			"nr_pages=%llx n_entries=0x%x total size=0x%lx\n",
			nr_pages, n_entries, n_entries * sizeof(ecpt_entry_t));
	}

	if ((1 << order) < nr_pages) {
		order++;
		pr_notice("ECPT Allocation Notice: "
			"Increase order by one to avoid truncation order=%x nr_pages=0x%llx\n",
			order, nr_pages);
	}
	
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
	
	if ((nr_pages << PAGE_SHIFT) < n_entries * sizeof(ecpt_entry_t)) {
		nr_pages++;
		pr_notice("ECPT free way notice: "
			"Increase number of pages by one to avoid truncation" 	
			"nr_pages=%llx n_entries=0x%x total size=0x%lx\n",
			nr_pages, n_entries, n_entries * sizeof(ecpt_entry_t));
	}

	if ((1 << order) < nr_pages) {
		order++;
		pr_notice("ECPT free way notice: "
			"Increase order by one to avoid truncation order=%x nr_pages=0x%llx\n",
			order, nr_pages);
	}

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

	ECPT_info_verbose("Create ecpt at %llx for mm at %llx\n",
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
	ECPT_info_verbose("Destroy ecpt at %llx\n", (uint64_t) ecpt);
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
		
		*vpn = VADDR_TO_PAGE_NUM_4KB(vaddr); 
	} 
	else if (gran == page_2MB) {
		if (is_kernel_vaddr) {
			*way_start = ECPT_4K_WAY;
			*way_end = ECPT_4K_WAY + ECPT_2M_WAY;
		} else {
			*way_start = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY;
			*way_end = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY;
		}

		*vpn = VADDR_TO_PAGE_NUM_2MB(vaddr); 
	} 
	else if (gran == page_1GB) {
		if (is_kernel_vaddr) {
			*way_start = ECPT_4K_WAY + ECPT_2M_WAY;
			*way_end = ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY;
		} else {
			*way_start = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY;
			*way_end = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY;
		}

		*vpn = VADDR_TO_PAGE_NUM_1GB(vaddr); 
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

	ECPT_info_verbose("fixup for way_start=%x way_end=%x\n", way_start, way_end);
	for (way = way_start; way < way_end; way++) {
		ecpt->table[way] = way_allocator();
	}
	
}	

ecpt_entry_t * get_hpt_entry(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity * g, uint32_t * way) {

	uint64_t size, hash, vpn, cr, rehash_ptr = 0;

	uint32_t w = 0, way_start, way_end;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr = NULL;
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
		// ECPT_info_verbose("looking at entry_ptr at %llx {.vpn=%llx .pte=%llx} vpn=%llx\n", 
			// (uint64_t) entry_ptr, entry_ptr->VPN_tag, entry_ptr->pte, vpn);

		if (ecpt_entry_match_vpn(entry_ptr, vpn)) {
			// ECPT_info_verbose("found at %llx vaddr=%llx\n", (uint64_t) entry_ptr, vaddr);
			// DEBUG_VAR((uint64_t) entry_ptr);
			if (gran == unknown) *g = way_to_gran(w);
			*way = w;
			return entry_ptr;
		} else {
			/* not found move on */
			entry_ptr = NULL;
		}
	}
	// ECPT_info_verbose("Not Found! vaddr=%llx\n", vaddr);
	*g = unknown;
	*way = -1;
	return entry_ptr;
}

ecpt_entry_t * get_ecpt_entry_from_mm(struct mm_struct *mm, uint64_t vaddr, Granularity *g) 
{
	uint32_t way;
	return get_hpt_entry((ECPT_desc_t * ) mm->map_desc, vaddr, g, &way);
}


/**
 * @brief search for a entry that can fit for vaddr insertion with gran.
 * 
 * @param ecpt 
 * @param vaddr 
 * @param is_write 
 * @param gran  
 * 	When is_write = true, gran must be specified as  page_4KB, page_2MB or page_1GB
 * 		the entries are found in the corresponding ways. 
 * 		If no match is found, return an empty entry for insertion.
 * 		If no empty entry, return an entry to be evicted.
 * 	When is_write = false, gran can be unknown as welle the granularity above.
 * 		If gran == unknown is passed in, search all ways to find a potential match.
 * 		and assign gran to the correct granularity.
 * 		If gran ==  page_4KB, page_2MB or page_1GB, search only within corresponding
 * 		ways, and gran should not change value.
 *  @param status output parameter
 * @return ecpt_entry_t* 
 */
static ecpt_entry_t * ecpt_search_fit_entry(ECPT_desc_t * ecpt, uint64_t vaddr, bool is_insert,
	Granularity* gran, enum search_entry_status * status, uint32_t * way_found) 
{

	uint64_t size, hash, vpn, cr, rehash_ptr = 0;

	uint32_t w = 0, way_start, way_end;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr = NULL;
	// ecpt_entry_t entry;
	/* this m */
	ecpt_entry_t * empty_slots[ECPT_TOTAL_WAY];
	uint32_t empty_slots_ways[ECPT_TOTAL_WAY];
	ecpt_entry_t * evict_slots[ECPT_TOTAL_WAY];
	uint16_t empty_i = 0, evict_i = 0, pick_i = 0;

	if (gran == unknown && is_insert) {
		*status = ENTRY_NOT_FOUND;
		*way_found = -1;
		pr_err("Invalid arguments for ecpt_search_fit_entry. gran==unkown, is_insert=true");
		return NULL;
	}

	select_way(
		vaddr, *gran,		/* input */
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
		
		if (hash < rehash_ptr) {
            /* not supported for resizing now */
            /* rehash_ptr MBZ right now */
            panic("no rehash support!\n");
        } else {
			/* stay with current hash table */
            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);
            entry_ptr = &ecpt_base[hash];
		}
        // entry = *entry_ptr;

		if (ecpt_entry_match_vpn(entry_ptr, vpn)) {
			*status = ENTRY_MATCHED;
			if (*gran == unknown) *gran = way_to_gran(w);
			*way_found = w;
			return entry_ptr;
		} else if (empty_entry(entry_ptr)){
			/* not found, but entry empty */
			empty_slots[empty_i] = entry_ptr;
			empty_slots_ways[empty_i] = w;
			empty_i++;
			entry_ptr = NULL;
		} else {
			evict_slots[evict_i++] = entry_ptr;	
			entry_ptr = NULL;
		}
	}

	/**
	 *  keep gran unchanged after this.
	 * 	If gran == unknown, is_inserted must be false
	 * 		at this point, we cannot find any matched slots, so no point to update gran
	 * 	If gran == 4K, 2M, or 1G.
	 * 		is_insert == false, same as previous case
	 * 		is_insert == true, gran already been specified by the user
	 * */
	if (!is_insert) {
		/* not an insert but no matched entry found */
		*status = ENTRY_NOT_FOUND;
		*way_found = -1;
		return NULL;
	}

	if (empty_i > 0) {
		/* no matched entry found return a random empty entry */
		pick_i = get_rand_way(empty_i);
		entry_ptr = empty_slots[pick_i];
		*way_found = empty_slots_ways[pick_i];
		*status = ENTRY_EMPTY;
		return entry_ptr;
	}

	if (evict_i > 0) {
		/* no matched entry found return a random entry to evict*/
		// entry_ptr = evict_slots[get_rand_way(evict_i)];
		*status = ENTRY_OCCUPIED;
		*way_found = -1;
		/* TODO: eviction */
		return NULL;
	}
	/* nothing empty and no where to kick. Should not reach here */
	BUG();
	return entry_ptr;
}

ecpt_entry_t * ecpt_search_fit(ECPT_desc_t * ecpt, uint64_t vaddr, Granularity gran) {

	uint64_t size, hash, vpn, cr, rehash_ptr = 0;

	uint32_t w = 0, way_start, way_end;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr = NULL;
	// ecpt_entry_t entry;
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
        // entry = *entry_ptr;

		if (ecpt_entry_match_vpn(entry_ptr, vpn)) {
			
			return entry_ptr;
		} else if (empty_entry(entry_ptr)){
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
		// ECPT_info_verbose("return ptr at %llx vaddr=%llx", (uint64_t) entry_ptr, vaddr);

		return entry_ptr;
	}

	if (evict_i > 0) {
		entry_ptr = evict_slots[get_rand_way(evict_i)];
		/* TODO: eviction */
		return NULL;
	}
	return entry_ptr;
}


static int kick_to_insert(ECPT_desc_t * ecpt, ecpt_entry_t * to_insert, uint32_t way_start, uint32_t way_end) 
{		
	uint16_t tries = 0;
	uint64_t size, hash, cr, rehash_ptr = 0;
	uint32_t n_way = way_end - way_start;
	static uint32_t way = 0;

	ecpt_entry_t * ecpt_base;
	ecpt_entry_t * entry_ptr;
	ecpt_entry_t temp;

	way = get_diff_rand(way, n_way);
	for (tries = 0; tries < ECPT_INSERT_MAX_TRIES; tries++) {
		// puthex_tabln(way);
		
		cr = ecpt->table[way_start + way];
		// DEBUG_VAR(cr);
		size = GET_HPT_SIZE(cr);
		if (size == 0) {
			fix_lazy_ECPT(ecpt, way_to_gran(way_start + way));
			
			cr = ecpt->table[way_start + way];
			size = GET_HPT_SIZE(cr);
			
			if (!size) {
				// ECPT_info_verbose("gran=%d way = %d\n", gran, way_start + way);
				BUG_ON(!size);
			}
		}

		hash = gen_hash_64(ecpt_entry_get_vpn(to_insert), size, way_start + way);


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
            
		if (ecpt_entry_empty_vpn(entry_ptr)) {
			

			ecpt_entry_do_merge(entry_ptr, to_insert);
			ECPT_info_verbose("Set ");
			PRINT_ECPT_ENTRY_DEBUG(entry_ptr);

			ecpt->occupied[way_start + way]++;
			return 0;
		}
		else if (ecpt_entry_vpn_match(entry_ptr, to_insert)) {
			/* can insert here */
			ecpt_entry_do_merge(entry_ptr, to_insert);
			ECPT_info_verbose("Set ");
			PRINT_ECPT_ENTRY_DEBUG(entry_ptr);
				
			return 0;
		} else {
			/* swap and insert again */
			
			ecpt_entry_overwrite(&temp, entry_ptr);

			ECPT_info_verbose("Kick ");
			PRINT_ECPT_ENTRY_INFO(entry_ptr);
			ECPT_info_verbose("with ");
			PRINT_ECPT_ENTRY_INFO(to_insert);

			ecpt_entry_overwrite(entry_ptr, to_insert);
			to_insert = &temp;
		}	
		
		way = get_diff_rand(way, n_way);
	}

	/* exceed max number of tries */
	return -ENOMEM;
}

int ecpt_insert(ECPT_desc_t * ecpt, uint64_t vaddr, uint64_t paddr, ecpt_pgprot_t prot, Granularity gran) 
{

	uint64_t vpn;
	pte_t pte;

	uint32_t way_start = 0, way_end = 0, n_way, entry_way = -1;

	ecpt_entry_t * entry_ptr;
	ecpt_entry_t entry ={};
	enum search_entry_status status = ENTRY_NOT_FOUND;

	int ret = 0;

	ECPT_info_verbose("ecpt at %llx vaddr=%llx paddr=%llx prot=%lx gran=%d\n", (uint64_t) ecpt ,vaddr, paddr, prot.pgprot, gran);
	pte.pte = 0;

	/* calculate PPN */
	if (gran == page_4KB) 
	{
		pte.pte = PADDR_TO_PTE_4KB(paddr);
		pte.pte = pte.pte | ecpt_pgprot_val(prot);
		ecpt_entry_set_pte(&entry, pte, vaddr);	
	} 
	else if (gran == page_2MB) 
	{
		pte.pte = PADDR_TO_PTE_2MB(paddr);
		pte.pte = pte.pte | ecpt_pgprot_val(prot);
		pte.pte = pte.pte | _PAGE_PSE;
		ecpt_entry_set_pmd(&entry, pte, vaddr);	
	} 
	else if (gran == page_1GB) 
	{
		pte.pte = PADDR_TO_PTE_1GB(paddr);
		pte.pte = pte.pte | ecpt_pgprot_val(prot);
		pte.pte = pte.pte | _PAGE_PSE;
		ecpt_entry_set_pud(&entry, pte, vaddr);	
	} 
	else 
	{
		/* invalid granularity */
		return -EINVAL;
	}

	select_way(
		vaddr, gran,		/* input */
		&way_start, &way_end, &vpn	/* output */
	);

	n_way = way_end - way_start;
	if (n_way == 0) {
		/* invalid size */
		return -EINVAL;
	}
	ecpt_entry_set_vpn(&entry, vpn);

	entry_ptr = ecpt_search_fit_entry(ecpt, vaddr, 1 /* is_insert */,
		 								&gran, &status, &entry_way);

	// ECPT_info_verbose("Status=%d\n", status);
	if (entry_ptr == NULL || status == ENTRY_NOT_FOUND) 
	{
		pr_err("Cannot find any matched entry!");
		return -EINVAL;
	} 
	else if (status == ENTRY_EMPTY || status == ENTRY_MATCHED) 
	{
		/* match or empty entry we can just insert */
		WARN(entry_ptr == NULL, "Invalid entry_ptr=%llx returned from ecpt_search_fit_entry\n", (uint64_t) entry_ptr);
		ecpt_entry_do_merge(entry_ptr, &entry);
		PRINT_ECPT_ENTRY_DEBUG(entry_ptr);

		if (status == ENTRY_EMPTY) {
			ecpt->occupied[entry_way]++;
		}
	} 
	else if (status == ENTRY_OCCUPIED) 
	{
		ret = kick_to_insert(ecpt, &entry, way_start, way_end);
		if (ret) 
		{
			WARN(1, KERN_WARNING"Hash Collision unresolved:\n ecpt at %llx vaddr=%llx paddr=%llx prot=%lx gran=%d\n", 
			(uint64_t) ecpt ,vaddr, paddr, prot.pgprot, gran);
			print_ecpt(ecpt, 0 /* kernel */, 1 /* user */, 1 /* print_entry */);
			return ret;
		}
	} 
	else 
	{
		/* should not be here */
		BUG();
	}

	return 0;

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

/**
 * @brief Note: this function currently only supports set pte for 4KB pages
 * 		In particular, ecpt_entry_set_pte only supports 4KB pages
 * @param mm 
 * @param ptep 
 * @param pte 
 * @param addr 
 * @return int 
 */
static int ecpt_set_pte(struct mm_struct *mm, pte_t *ptep, pte_t pte, unsigned long addr) {
	ecpt_entry_t * e;
	// uint64_t * tag_ptr;
	ECPT_desc_t * ecpt = (ECPT_desc_t *) mm->map_desc;
	uint32_t way = 0;
	uint64_t vpn = VADDR_TO_PAGE_NUM_4KB(addr);

	e = get_ecpt_entry_from_ptep(ptep, addr);
	
	WARN(!(ecpt_entry_empty_vpn(e) || ecpt_entry_match_vpn(e, vpn)),
		"Cannot set pte=%lx at %llx", pte.pte, (uint64_t) e);
	
	WARN(!pte_present(pte), 
		"Set pte to be not present pte=%lx at %llx", pte.pte, (uint64_t) e);

	if (!pte_present(*ptep) && pte_present(pte)) {
		ecpt_entry_inc_valid_pte_num(e);

		if (update_stats && ecpt_entry_get_valid_pte_num(e) == 1) {	
			/* valid pte count increase from 0 -> 1 */
			way = find_way_from_ptep(ecpt, ptep);
			BUG_ON(way == -1);
			// ECPT_info_verbose("update way at %llx\n", ecpt->table[way]);
			ecpt->occupied[way] += 1;
		}
	}

	ecpt_entry_set_pte(e, pte, addr);
	ecpt_entry_set_vpn(e, vpn);

	PRINT_ECPT_ENTRY_DEBUG(e);

	return -1;
}


int ecpt_set_pte_at(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep, pte_t pte)
{
	int res = 0;

	if (ptep != NULL && ptep != (pte_t *) &pte_default.pte) {
		return ecpt_set_pte(mm, ptep, pte, addr);
	} 

	ECPT_info_verbose("  set_pte_at 4KB addr=%lx pte=%lx \n", addr, pte.pte);
	/* TODO: replace ecpt_insert with kick to insert */
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
		ECPT_info_verbose("ptep_set_access_flags addr=%lx pte=%lx with ptep at %llx\n",
			address, entry.pte, (uint64_t) ptep);
		changed = !pte_same(*ptep, entry);

		if (changed && dirty) {
			ecpt_set_pte(vma->vm_mm, ptep, entry, address);
		}
			// set_pte(ptep, entry);
		return changed;
	} 

	WARN(1, "Invalid set access addr=%lx ptep at %llx entry=%lx\n", address, (uint64_t) ptep, entry.pte );

	return 0;
}	

static pte_t __ecpt_native_ptep_get_and_clear(struct mm_struct *mm, pte_t *ptep, unsigned long addr) {
	ecpt_entry_t * e;

	pte_t ret = READ_ONCE(*ptep);
	
	ECPT_desc_t * ecpt = (ECPT_desc_t *) mm->map_desc;
	uint32_t way = 0;

	e = get_ecpt_entry_from_ptep(ptep, addr);
	ecpt_entry_clear_ptep(e, (uint64_t *) ptep);
	
	if (update_stats && ecpt_entry_get_valid_pte_num(e) == 0) {
		way = find_way_from_ptep(ecpt, ptep);
		BUG_ON(way == -1);
		// ECPT_info_verbose("update way at %llx\n", ecpt->table[way]);
		ecpt->occupied[way] -= 1;
	}

	ECPT_info_verbose("ptep_get_and_clear 4KB addr=%lx with entry at %llx\n",
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


uint64_t * get_ptep_with_gran(struct ecpt_entry *entry, unsigned long vaddr, Granularity g)
{		
	uint64_t * ptep = NULL;
	if (g == page_4KB) {
		ptep = (uint64_t *) pte_offset_from_ecpt_entry(entry, vaddr);
	} else if (g == page_2MB) {
		ptep = (uint64_t *) pmd_offset_from_ecpt_entry(entry, vaddr);
	} else if (g == page_1GB) {
		ptep = (uint64_t *) pud_offset_from_ecpt_entry(entry, vaddr);
	} else {
		BUG();
	}
	return ptep;
}

int ecpt_invalidate(ECPT_desc_t * ecpt_desc, uint64_t vaddr, Granularity g) {
	
	ecpt_entry_t * entry = NULL;
	uint64_t * ptep = NULL;
	uint32_t way;
	uint32_t prev_valid_cnt = 0;
	entry = get_hpt_entry(ecpt_desc, vaddr, &g, &way);
	
	if (entry == NULL) {
		/* no such entry */
		return -1;
	}

	prev_valid_cnt = ecpt_entry_get_valid_pte_num(entry);

	/* clear the ptep */
	ptep = get_ptep_with_gran(entry, vaddr, g);
	ecpt_entry_clear_ptep(entry, ptep);

	if (prev_valid_cnt> 0 && ecpt_entry_get_valid_pte_num(entry) == 0) {
		ecpt_desc->occupied[way] -= 1;
	}

	ECPT_info_verbose("ecpt_invalidate");
	PRINT_ECPT_ENTRY_DEBUG(entry);

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
	ecpt_entry_t empty;
	uint32_t way_temp;
	ecpt_entry_t * entry_p = get_hpt_entry(ecpt, vaddr, gran, &way_temp);

	if (entry_p == NULL) {
		// pr_warn("WARN: vaddr=%llx gran=%d doesn't exist", vaddr, *gran);
		memset(&empty, 0, sizeof(empty));
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

	pte_t pte_val;
	ecpt_entry_t * entry_p;
	uint32_t way_temp;
	uint64_t * ptep = NULL;
	entry_p = get_hpt_entry(ecpt, vaddr, &gran, &way_temp);

	if (entry_p == NULL) {
		WARN(1, KERN_WARNING "entry_p == NULL\n");
		return -1;
	}

	ptep = get_ptep_with_gran(entry_p, vaddr, gran);
	pte_val.pte = *ptep;
	if (!pte_present(pte_val)) {
		pr_warn("Cannot update protection for entry that is not present\n");
		return -1;
	}

	pte_val.pte = ENTRY_TO_ADDR(*ptep) | new_prot.pgprot;
	ecpt_entry_set_pte_with_pointer(entry_p, pte_val, ptep, vaddr);

	PRINT_ECPT_ENTRY_DEBUG(entry_p);
	return 0;
}

int ecpt_mm_update_prot(struct mm_struct* mm, uint64_t vaddr, ecpt_pgprot_t new_prot, Granularity gran) {

	int res;

	spin_lock(&mm->page_table_lock);
	res = ecpt_update_prot((ECPT_desc_t *) mm->map_desc, vaddr, new_prot, gran);
	spin_unlock(&mm->page_table_lock);

	return 0;
}

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

static void check_ecpt_detail(ECPT_desc_t * ecpt,
 		uint32_t way_start, uint32_t way_end, bool print_entry) {
	uint64_t cr, size;
	uint32_t  i, j;
	ecpt_entry_t * ecpt_base, * e; 
	uint32_t valid_entries_cnt = 0;

	for (i = way_start; i < way_end; i++) {
		valid_entries_cnt = 0;
		if (print_entry) {
			pr_info("\t 0x%x/0x%llx %llx -> cr%d \n",
				ecpt->occupied[i], GET_HPT_SIZE(ecpt->table[i]), 
				ecpt->table[i], way_to_crN[i]);
		}

		cr = ecpt->table[i];
		size = GET_HPT_SIZE(cr);

		ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE_VIRT(cr);

		for (j = 0; j < size; j++) {
            e = &ecpt_base[j];
			if (!ecpt_entry_empty_vpn(e)) {
				if (print_entry) {
					PRINT_ECPT_ENTRY_INFO(e);
				}
				valid_entries_cnt++;
			}
		}

		if (print_entry && valid_entries_cnt == ecpt->occupied[i] ) {
			pr_info("\t way %d passed check!\n", i);
		}

		WARN(valid_entries_cnt != ecpt->occupied[i], 
			"Inconsistent stats way=%d valid_entries_cnt=0x%x occupied=0x%x",
			i, valid_entries_cnt, ecpt->occupied[i]);
	}
}

inline void check_ecpt_user_detail(ECPT_desc_t * ecpt, bool print_entry) 
{
	check_ecpt_detail(ecpt, ECPT_KERNEL_WAY, ECPT_TOTAL_WAY, print_entry);
}

inline void check_ecpt_kernel_detail(ECPT_desc_t * ecpt, bool print_entry) 
{
	check_ecpt_detail(ecpt, 0, ECPT_KERNEL_WAY, print_entry);
}


void print_ecpt(ECPT_desc_t * ecpt, bool kernel_table_detail,
	 			bool user_table_detail, bool print_entry) {
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
		check_ecpt_kernel_detail(ecpt, print_entry);

	if (user_table_detail)
		check_ecpt_user_detail(ecpt, print_entry);
	
	pr_info("End of ECPT at %llx ------------------\n", (uint64_t) ecpt);
}
