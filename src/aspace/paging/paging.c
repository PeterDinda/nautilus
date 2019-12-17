#include <nautilus/nautilus.h>
#include <nautilus/spinlock.h>
#include <nautilus/paging.h>
#include <nautilus/thread.h>
#include <nautilus/shell.h>
#include <nautilus/cpu.h>

#include <nautilus/aspace.h>

#include "paging_helpers.h"

#ifndef NAUT_CONFIG_DEBUG_ASPACE_PAGING
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define ERROR(fmt, args...) ERROR_PRINT("aspace-paging: " fmt, ##args)
#define DEBUG(fmt, args...) DEBUG_PRINT("aspace-paging: " fmt, ##args)
#define INFO(fmt, args...)   INFO_PRINT("aspace-paging: " fmt, ##args)


typedef struct mmnode {
    nk_aspace_region_t region;
    struct list_head node;
} mm_node;


typedef struct nk_aspace_paging {
  nk_aspace_t *aspace;
    
  spinlock_t   lock;
  struct list_head region_list;
    
  nk_aspace_characteristics_t chars;

  ph_cr3e_t     cr3;

#define CR4_MASK 0xb0ULL // bits 4,5,7
  uint64_t      cr4;
} nk_aspace_paging_t;

#if 0
// This table defines the kernel's mappings
static struct kmap {
  uint64_t virt;
  uint64_t phys_start;
  uint64_t phys_end;
  int  flags;
} kmap[] = {
 // addr_t kern_start     = (addr_t)&_loadStart;
 // addr_t kern_end       = multiboot_get_modules_end(mbd);
 // not sure about the boundary of each region
 { (void*)va_kern_start, kern_start, kern_end, 0},     // kern text+rodata+normaldata+memory 
};


static void setup_paging(void *state){
  // since we are still using direct mapping, all these codes should be able to execute
  nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
  // first, map only the kernel code, data
  struct kmap *k;
  uint64_t va_addr, pa_addr;
  int nele = (sizeof(kmaps)) / sizeof(struct kmap) ; 
  for(k = kmap; k < &kmap[nele]; k++){
    for(va_addr = k->virt, pa_addr = k->phys_start; pa_addr < k->phys_end; va_addr += PAGE_SIZE_4KB, pa_addr += PAGE_SIZE_4KB){
      nk_map_page(va_addr, pa_addr, k->flags, PAGE_SIZE_4KB)
      // I can't use paging_helper_drill(), since it will allocate a new physical page. I just need to map
    }
  }
  // second, write the physical address of pml4e into cr3 
  write_cr3((p->cr3).pml4_base); 
  // third, set up the most significant bit in cr0
  ulong_t cr0 = read_cr0(); 
  cr0 = cr0 | (1 << 63);
  write_cr0(cr0);
  // now we start using paging, if page fault happens, process can use the mapped kernel code to handle it, thus avoiding triple fault
}

#endif

static  int destroy(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // free regions in list
    struct list_head *pos = &(p->region_list);
    list_for_each(pos, &p->region_list){
      mm_node *node = (mm_node *)(pos - sizeof(nk_aspace_region_t));
      free(node);
    }

/* don't worry about it now
    STATE_LOCK_CONF;
    
    STATE_LOCK();
    list_del(&p->aspace->aspace_list_node); 
    STATE_UNLOCK();
//  ....
*/
    // free paging table
    paging_helper_free(p->cr3, 1);
    // free aspace struct
    free(p); 
    return 0;
}


static int add_thread(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    thread->aspace = p->aspace;
    DEBUG("Add thread %p to base address\n");    
    return 0;
}
    
    
static int remove_thread(void *state)
{
    nk_vc_printf("In remove thread function\n");
    struct nk_thread *thread = get_cur_thread();
    thread->aspace = 0;
    return 0;
}


static int add_region(void *state, nk_aspace_region_t *region)
{

    // add the new node into region_list
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("adding region %p (va=%016lx pa=%016lx len=%lx)\n", region, region->va_start, region->pa_start, region->len_bytes);
    
    mm_node* new_node = (mm_node*)malloc(sizeof(mm_node));

    if (!new_node) { 
	ERROR("failed to allocate new mm_node\n");
	return -1;
    }
    
    new_node->region = *region;

    DEBUG("survived region set\n");
    
    list_add(&(new_node->node), &(p->region_list));

    DEBUG("survived list add\n");
    
    //    if (region->protect.flags & NK_ASPACE_EAGER) { 
    
    // edit page tables to match
    // easiest way: delete all page tables and start from scratch
    // assume the va and pa in region may not be page aligned
  if(region->protect.flags & NK_ASPACE_EAGER){
    addr_t cur_page, phy_page;
    ph_pf_access_t access_type = {
	.present = 0,
	.write = 1, 
	.user = 0,
	.ifetch = 1,
    };
    DEBUG("starting to drill from %016lx to %016lx\n",region->va_start,region->va_start+region->len_bytes);
    phy_page = (addr_t) region->pa_start; 
    for (cur_page = (addr_t) region->va_start;
	 cur_page < (addr_t) (region->va_start + region->len_bytes);
	 cur_page += PAGE_SIZE_4KB, phy_page += PAGE_SIZE_4KB ) {
	
	//DEBUG("invoking drill on %016lx\n",cur_addr);
	// here how should i pick up a physical address? use the pa provied in region?
	// looks like I map them to continuous physical memory, but it shouldn't
	
	if (paging_helper_drill(p->cr3, cur_page, phy_page, access_type) != 0) {
	    ERROR("Could not map page at vaddr %p paddr %p\n", cur_page, cur_page);
	}
    }

    DEBUG("Finished drill\n");
  }
	
    // if we are editing the current address space then... 
    //    write_cr3((p->cr3).pml4_base);

    
    return 0;
}

static int remove_region(void *state, nk_aspace_region_t *region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // assume the region we need to remove exists in the current linked list
    struct list_head *pos = &(p->region_list);
    nk_aspace_region_t *current = 0;
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)(pos - sizeof(nk_aspace_region_t));
      if(current->va_start == region->va_start && current->pa_start == region->pa_start &&
                 current->len_bytes == region->len_bytes){
        break;
      }
    }

    if (!current) {
	ERROR("failed to find region\n");
	return -1;
    }
    mm_node *current_mmnode = (mm_node *)current;
    list_del(&(current_mmnode->node));
    free(current_mmnode);

    // edit page tables to match
    ulong_t base_addr = (ulong_t)region->va_start;    
    ulong_t end_addr = base_addr + region->len_bytes;
    base_addr = ROUND_DOWN_TO_PAGE(base_addr);
    end_addr = ROUND_DOWN_TO_PAGE(end_addr + PAGE_SIZE_4KB - 1);
    pte_t *pte;
    ph_pf_access_t access_type = {0, 1, 1, 0, 0, 0} ;
    for(; base_addr < end_addr; ){
      // I need to add a function to get the pte, walk_page_table()
      // in walk_page_table, it doesn't allocate pte, drill will allocate
      // walk function only get the existing pte
      if(paging_helper_walk(p->cr3, base_addr, access_type, &pte) != 0){
        panic("Cannot find the page at addr 0x%x\n", base_addr);
      }
      *pte &= ~PTE_PRESENT_BIT;
      base_addr += PAGE_SIZE_4KB;
    } 
    write_cr3((p->cr3).pml4_base); 
    return 0;
}
   
static int protect_region(void *state, nk_aspace_region_t *region, nk_aspace_protection_t *prot)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // now need to edit page tables to match
    ulong_t base_addr = (ulong_t)region->va_start;    
    ulong_t end_addr = base_addr + region->len_bytes;
    base_addr = ROUND_DOWN_TO_PAGE(base_addr);
    end_addr = ROUND_DOWN_TO_PAGE(end_addr + PAGE_SIZE_4KB - 1);
    pte_t* pte;
    ph_pf_access_t access_type = {0, 1, 1, 0, 0, 0};
    for(; base_addr < end_addr; ){
      if(paging_helper_walk(p->cr3, base_addr, access_type, &pte) != 0){
        panic("Cannot find the page at addr 0x%x\n", base_addr);
      }
      *pte &= ~(prot->flags); // nk_aspace_protection_t in aspace.h does not match with the pte protection bit pattern in paging.h
      base_addr += PAGE_SIZE_4KB;
    }
    write_cr3((p->cr3).pml4_base); 
    return 0;
}

static int move_region(void *state, nk_aspace_region_t *cur_region, nk_aspace_region_t *new_region)
{
    if(cur_region->len_bytes != new_region->len_bytes)
      ERROR("Cannot move two regions that have different length\n");
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    memcpy(new_region->va_start, cur_region->va_start, new_region->len_bytes);
    // now need to edit page tables to match
    remove_region(state, cur_region);
    add_region(state, new_region);
    return 0;
}



static int switch_from(void *state)
{
  struct nk_aspace_paging *p = (struct nk_aspace_paging *)state;
  struct nk_thread *thread = get_cur_thread();
  
  DEBUG("Switching out address space %s from thread %d\n",p->aspace->name, thread->tid);
  
  return 0;
}

static int switch_to(void *state)
{
  nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
  struct nk_thread *thread = get_cur_thread();
  DEBUG("Switching in address space %p %s from thread %d\n",p, p->aspace->name,thread->tid);
  DEBUG("pas->as=%p pas->lock=%d, pas->cr3=%016x, pas->cr4=%016x &pas->cr3=%p\n", p->aspace, p->lock, p->cr3, p->cr4,&p->cr3);
  DEBUG("will write cr3=%016lx\n", p->cr3.val);
  write_cr3(p->cr3.val);
  uint64_t cr4 = read_cr4();
  cr4 &= ~CR4_MASK;
  cr4 |= p->cr4;
  DEBUG("will write cr4=%016lx\n", cr4);
  write_cr4(cr4);
  return 0;
}

static int exception(void *state, excp_entry_t *exp, excp_vec_t vec)
{
  nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
  struct nk_thread *thread = get_cur_thread();

  uint64_t va = read_cr2();
  //DEBUG("Exception 0x%x on thread %d, virtual address 0x%x\n", vec, thread->tid, va);

  // FIX ME - I NOW NEED TO DRILL A PTE IF THIS IS A VALID PAGE FAULT
  // if PF
  //   - if fault address (CR2) is in a valid *region*
  //     and access permissions are OK
  //     then drill the PTE for the address
  // if GPF
  //   - BAD - PANIC
  // Is this the way I know if this exception is a GPF?SPACE_EAGER  
  if(vec == NK_ASPACE_HOOK_GPF){
    panic("General protection fault on address 0x%x, on thread %d\n", va, thread->tid);
  }
  uint64_t *pte;
  ph_pf_access_t access_type = {
        .present = 0,
        .write = 1,
        .user = 0,
        .ifetch = 1,
  };
  int walk_res = 0;
  if((walk_res = paging_helper_walk(p->cr3, va, access_type, &pte)) != 0){
     //panic("Cannot find the page table entry of virtual addr 0x%x, error code %d\n", va, walk_res);
     if(paging_helper_drill(p->cr3, va, ((addr_t)va - 0xffff800000000000UL), access_type) != 0){
       panic("Could not map page at vaddr %p paddr %p\n", (void*)va, (void*)(va - 0xffff800000000000UL));
     }
     return 0;
  }
  /*uint64_t pa = PAGE_NUM_TO_ADDR_4KB(*pte); // (((addr_t)x) << 12)
  if(!(*pte & PTE_PRESENT_BIT)){
    panic("Virtual address 0x%x not present, on thread %d\n", va, thread->tid);
    return -1;
  }
  if(!(*pte & PTE_WRITABLE_BIT)){
    panic("Virtual address 0x%x not writable, on thread %d\n", va, thread->tid);
    return -1;
  }
  DEBUG("Exception 0x%x on thread physical address 0x%x\n", vec, pa);

  // not sure about the ifetch bit
  // access_type = { 0, 1, 1, 0, 0, 0};
  if(paging_helper_drill(p->cr3, va, pa, access_type) != 0){
    panic("Could not map page at vaddr %p paddr %p\n", (void*)va, (void*)pa);
  }*/
  //write_cr3((p->cr3).pml4_base); 
  return 0;
}
    
static int print(void *state, int detailed)
{
  nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
  struct nk_thread *thread = get_cur_thread();

  // print the data about the regions
  // print the PTs
  // etc.

  // basic info
  nk_vc_printf("%s Paging Address Space [granularity 0x%lx alignment 0x%lx]\n"
   	       "   CR3:    %016lx  CR4m: %016lx\n",
   	       p->aspace->name, p->chars.granularity, p->chars.alignment, p->cr3.val, p->cr4);
  // regions info
  struct list_head *pos = &(p->region_list);
  list_for_each(pos, &p->region_list){
      mm_node *node = list_entry(pos,mm_node,node);
      nk_aspace_region_t *region = &node->region;
      nk_vc_printf("   Region: %016lx - %016lx => %016lx\n",
		   (uint64_t) region->va_start,
		   (uint64_t) region->va_start + region->len_bytes, 
		   (uint64_t) region->pa_start);
  }
  
  if (!detailed) {
      return 0;
  }
  // page info
  ph_cr3e_t cr3 = p->cr3;
  ph_pml4e_t *pml4e = (ph_pml4e_t *)PAGE_NUM_TO_ADDR_4KB(cr3.pml4_base);

  uint64_t i, j, k, m;
  for (i = 0; i < NUM_PML4_ENTRIES; i++) {
    if(pml4e[i].present){
	nk_vc_printf("pml4e[%d]=%016lx\n",i,pml4e[i].val);
      ph_pdpe_t *pdpe = (ph_pdpe_t *)PAGE_NUM_TO_ADDR_4KB(pml4e[i].pdp_base);
      for (j = 0; j < NUM_PDPT_ENTRIES; j++) {
        if(pdpe[j].present){
	    nk_vc_printf("pdpe[%d]=%016lx\n",j,pdpe[j].val);
          ph_pde_t * pde = (ph_pde_t *)PAGE_NUM_TO_ADDR_4KB(pdpe[j].pd_base);          
          for (k = 0; k < NUM_PD_ENTRIES; k++) {
            if(pde[k].present){
	    nk_vc_printf("pde[%d]=%016lx\n",k,pde[k].val);
              ph_pte_t * pte = (ph_pte_t *)PAGE_NUM_TO_ADDR_4KB(pde[k].pt_base);
              for (m = 0; m < NUM_PT_ENTRIES; m++) {
                if(pte[m].present){
	    nk_vc_printf("pte[%d]=%016lx\n",m,pte[m].val);
                  uint64_t va = (i << PML4_SHIFT) | (j << PDPT_SHIFT) | (k << PD_SHIFT) | (m << PT_SHIFT) ;
                  uint64_t pa = PAGE_NUM_TO_ADDR_4KB(pte[m].page_base);
                  nk_vc_printf("   Page: va 0x%x -> pa 0x%x\n", va, pa);
                }
              }
            }
          }
        }
      }
    }
  }
  return 0;
}    


static nk_aspace_interface_t paging_interface = {
    .destroy = destroy,
    .add_thread = add_thread,
    .remove_thread = remove_thread,
    .add_region = add_region,
    .remove_region = remove_region,
    .protect_region = protect_region,
    .move_region = move_region,
    .switch_from = switch_from,
    .switch_to = switch_to,
    .exception = exception,
    .print = print
};



static int   get_characteristics(nk_aspace_characteristics_t *c)
{
  c->granularity = c->alignment = PAGE_SIZE_4KB;
  
  return 0;
}



static struct nk_aspace * create(char *name, nk_aspace_characteristics_t *c)
{
  struct naut_info *info = nk_get_nautilus_info();
  nk_aspace_paging_t *p;

  p = malloc(sizeof(*p));
  
  if (!p) {
    ERROR("cannot allocate paging aspace %s\n",name);
    return 0;
  }
  
  memset(p,0,sizeof(*p));

  spinlock_init(&p->lock);
  
  //p->mm_rb = RB_ROOT;
  INIT_LIST_HEAD(&(p->region_list));

  p->chars.granularity = p->chars.alignment = PAGE_SIZE_4KB;

  /*void *pml4 = malloc(PAGE_SIZE_4KB);

  if (!pml4) {
    ERROR("Failed to allocate PML4\n");
    free(p);
    return 0;
  }

  memset(pml4,0,PAGE_SIZE_4KB);*/

  if(paging_helper_create(&(p->cr3)) == -1){
    ERROR("Unable create aspace cr3 in address space %s\n", name);
  }

  p->cr4 = nk_paging_default_cr4() & CR4_MASK;
  
  // EFER

  p->aspace = nk_aspace_register(name,
				 NK_ASPACE_HOOK_PF | NK_ASPACE_HOOK_GPF,
				 &paging_interface,
				 p);

  if (!p->aspace) {
    ERROR("Unable to register paging address space %s\n",name);
    return 0;
  }
  // start using paging table
  // setup_paging(p);

  DEBUG("Paging address space %s configured and initialized (returning %p)\n", name, p->aspace);
    
  return p->aspace; 
}

static nk_aspace_impl_t paging = {
				.impl_name = "paging",
				.get_characteristics = get_characteristics,
				.create = create,
};


nk_aspace_register_impl(paging);


