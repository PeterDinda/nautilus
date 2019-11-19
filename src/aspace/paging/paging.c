#include <nautilus/nautilus.h>
#include <nautilus/spinlock.h>
#include <nautilus/paging.h>
#include <nautilus/thread.h>
#include <nautilus/shell.h>
#include <nautilus/cpu.h>

#include <nautilus/aspace.h>

#ifndef NAUT_CONFIG_DEBUG_ASPACE_PAGING
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define ERROR(fmt, args...) ERROR_PRINT("aspace-paging: ERROR %s(%d): " fmt, __FILE__, __LINE__, ##args)
#define DEBUG(fmt, args...) DEBUG_PRINT("aspace-paging: DEBUG: " fmt, ##args)
#define INFO(fmt, args...)   INFO_PRINT("aspace-paging: " fmt, ##args)


struct mm_node {
    nk_aspace_region_t region;
    mm_node *next;
};


typedef struct nk_aspace_paging {
  nk_aspace_t *aspace;

  spinlock_t   lock;
  struct mm_node *mmap;  // vm region sorted list
  //struct rb_root mm_rb;  // contains regions
  nk_aspace_characteristics_t chars;

  uint64_t     cr3; 
#define CR4_MASK 0xb0ULL // bits 4,5,7
  uint64_t     cr4;
} nk_aspace_paging_t;



static  int destroy(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
// free region information
    struct mm_node *r = p->mmap;
    struct mm_node *r_next = r;
    while(r != NULL){
      r_next = r->next;
      free(r);
      r = r_next;
    }

// why don't we use a global lock to remove aspace from aspace list
    STATE_LOCK_CONF;
    
    STATE_LOCK();
    list_del(&p->aspace->aspace_list_node); 
    STATE_UNLOCK();
//  ....

    free(p->aspace);
    free(p); 
    return 0;
}


static int add_thread(void *state)
{
    nk_aspace_paging_t *as = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    thread->aspace = as->aspace;
    DEBUG("Add thread %p to base address\n");
    
    return 0;
}
    
    
static int remove_thread(void *state)
{
    struct nk_thread *thread = get_cur_thread();
    thread->aspace = 0;
    return 0;
    
}


static int add_region(void *state, nk_aspace_region_t *region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct mm_node* new_node = (struct mm_node*)malloc(sizeof(struct mm_node));   
    new_node->region = region;
    new_node->next = NULL;

    if (p->mmap == NULL || p->mmap->region.va >= region->va){  
        new_node->next = p->mmap;  
        p->mmap = new_node;  
    }  
    else{  
        /* Locate the node before the point of insertion */
        struct mm_node* current = p->mmap;  
        while (current->next != NULL &&  
            current->next->region.va < region->va)
        {  
            current = current->next;  
        }  
        new_node->next = current->next;  
        current->next = new_node;  
    }  

    // now you need to edit page tables to match
    // easiest way: delete all page tables and start from scratch
    // assume the va and pa in region may not be page aligned
    ulong_t base_addr = (ulong_t)region->va;    
    ulong_t end_addr = base_addr + region->len_bytes;
    base_addr = ROUND_DOWN_TO_PAGE(base_addr);
    end_addr = ROUND_DOWN_TO_PAGE(end_addr + PAGE_SIZE_4KB - 1);
    ulong_t pa_base_addr = ROUND_DOWN_TO_PAGE(region->pa);
    for(; base_addr < end_addr; ){
      // here how should i pick up a physical address? use the pa provied in region?
      // looks like I map them to continuous physical memory, but it shouldn't
      if(nk_map_page(base_addr, pa_base_addr, 0, PAGE_SIZE_4KB) != 0){
        ERROR_PRINT("Could not map page at vaddr %p paddr %p\n", (void*)vaddr, (void*)paddr);
      }
      base_addr += PAGE_SIZE_4KB;
      pa_base_addr += PAGE_SIZE_4KB;
    } 
    write_cr3(p->cr3); 
    return 0;
}

static int remove_region(void *state, nk_aspace_region_t *region)
{
    nk_aspace_paging_t *as = (nk_aspace_paging_t *)state;
    struct mm_node* current = p->mmap;
    if(current == NULL) panic("Remove region from an empty linked list\n");
    uint64_t end_addr = (uint64_t)region->va_start + region->len_bytes;
    // assume we can only remove a region that is exist in the current linked list
    // the region that will be removed will have an identical copy in the list    
    if (p->mmap != NULL && p->mmap->region.va_start == region->va_start && 
           p->mmap->region.pa_start == region->pa_start && 
           p->mmap->region.len_bytes == region->len_bytes){  
        p->mmap = p->mmap->next;  
    }  
    else{  
        struct mm_node* current = p->mmap;  
        while (current->next != NULL) 
        {  
            if(current->next->region.va_start == region->va_start &&
                 current->next->region.pa_start == region->pa_start &&
                 current->next->region.len_bytes == region->len_bytes){
               current->next = current->next->next;
               break;
            }
            else current = current->next;  
        }  
    } 

    // now need to edit page tables to match
    ulong_t base_addr = (ulong_t)region->va;    
    ulong_t end_addr = base_addr + region->len_bytes;
    base_addr = ROUND_DOWN_TO_PAGE(base_addr);
    end_addr = ROUND_DOWN_TO_PAGE(end_addr + PAGE_SIZE_4KB - 1);
    for(; base_addr < end_addr; ){
      // I need to add a function to get the pte, walk_page_table()
      pte_t* pte = walk_page_table(base_addr);
      *pte &= ~PTE_PRESENT_BIT;
      base_addr += PAGE_SIZE_4KB;
    } 
    write_cr3(p->cr3); 
    return 0;
}
   
static int protect_region(void *state, nk_aspace_region_t *region, nk_aspace_protection_t *prot)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // now need to edit page tables to match
    ulong_t base_addr = (ulong_t)region->va;    
    ulong_t end_addr = base_addr + region->len_bytes;
    base_addr = ROUND_DOWN_TO_PAGE(base_addr);
    end_addr = ROUND_DOWN_TO_PAGE(end_addr + PAGE_SIZE_4KB - 1);
    for(; base_addr < end_addr; ){
      pte_t* pte = walk_page_table(base_addr);
      *pte &= ~(*prot); // nk_aspace_protection_t in aspace.h does not match with the pte protection bit pattern in paging.h
      base_addr += PAGE_SIZE_4KB;
    }
    write_cr3(p->cr3); 
    return 0;
}

static int move_region(void *state, nk_aspace_region_t *cur_region, nk_aspace_region_t *new_region)
{
    if(cur_region->len_bytes != new_region->len_bytes)
      ERROR("Cannot move two regions that have different length\n");
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // now need to edit page tables to match
    // should I do copy work?? move the content in pa of cur_region to pa of new_region
    remove_region(state, cur_region);
    add_region(state, new_region);
    return 0;
}



static int switch_from(void *state)
{
  struct nk_aspace_paging *as = (struct nk_aspace_paging *)state;
  struct nk_thread *thread = get_cur_thread();
  
  DEBUG("Switching out base address space from thread %d\n",thread->tid);
  
  return 0;
}

static int switch_to(void *state)
{
  nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
  struct nk_thread *thread = get_cur_thread();
  DEBUG("Switching in address space %s from thread %d\n",p->aspace->name,thread->tid);
  write_cr3(a->cr3);
  cr4 = read_cr4();
  cr4 &= ~CR4_MASK;
  cr4 |= a->cr4;
  write_cr4(cr4);
  return 0;
}

static int exception(void *state, excp_entry_t *exp, excp_vec_t vec)
{
  nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
  struct nk_thread *thread = get_cur_thread();

  DEBUG("Exception 0x%x on thread %d\n",vec,thread->tid);

  // FIX ME - I NOW NEED TO DRILL A PTE IF THIS IS A VALID PAGE FAULT
  // if PF
  //   - if fault address (CR2) is in a valid *region*
  //     and access permissions are OK
  //     then drill the PTE for the address
  // if GPF
  //   - BAD - PANIC
  // Is this the way I know if this exception is a GPF?
  if(vec == NK_ASPACE_HOOK_GPF){
    panic("General protection fault on address 0x%x, on thread %d\n", va, thread->tid);
  }
  uint64_t va = read_cr2();
  pte_t* pte = walk_page_table(base_addr); 
  if(pte == 0){
    DEBUG("Invalid virtual address 0x%x, on thread %d\n", va, thread->tid);
    return -1;
  }
  if(!(*pte & PTE_KERNEL_ONLY_BIT)){
    DEBUG("Illegal kernal only virtual address 0x%x, on thread %d\n", va, thread->tid);
    return -1;
  }
  if(!(*pte & PTE_PRESENT_BIT)){
    DEBUG("Virtual address 0x%x not present, on thread %d\n", va, thread->tid);
    return -1;
  }
  if(!(*pte & PTE_KERNEL_WRITABLE_BIT)){
    DEBUG("Virtual address 0x%x not writable, on thread %d\n", va, thread->tid);
    return -1;
  }
  // what access permissions should it meet, PRESENT_BIT, WRITABLE_BIT
  
  if(drill_page_tables(va, PTE_ADDR(pte),0) != 0){
    DEBUG("Drill page table error on thread %d\n", thread->tid\);
    return -1;
  }
  write_cr3(p->cr3); 
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
   	       p->aspace->name, p->chars.granularity, p->chars.alignment, p->cr3, p->cr4);
  // regions info
  struct mm_node* current = p->mmap;
  while(current != NULL){
    nk_vc_printf("   Region: %016lx - %016lx => %016lx\n",
   	       (uint64_t) as->theregion.va_start, 
   		 (uint64_t) as->theregion.va_start + as->theregion.len_bytes);
    current = current->next;
  }
  // page info
  int i, j, k, m;
  for (i = 0; i < NUM_PML4_ENTRIES; i++) {
    if(pml[i] != 0){
      pdpte_t * pdpt = (pdpte_t*)PTE_ADDR(pml[i]);
      for (j = 0; j < NUM_PDPT_ENTRIES; j++) {
        if(pdpt[j] != 0){
          pde_t * pd = (pde_t*)PTE_ADDR(pdpt[j]);          
          for (k = 0; k < NUM_PD_ENTRIES; k++) {
            if(pd[k] != 0){
              pte_t * pt = (pte_t*)PTE_ADDR(pd[k]);
              for (m = 0; m < NUM_PT_ENTRIES; m++) {
                if(pt[m] != 0){
                  uint64_t va = (i << PML4_SHIFT) | (j << PDPT_SHIFT) | (k << PD_SHIFT) | (m << PT_SHIFT) ;
                  nk_vc_printf("   Page: va 0x%x -> pa 0x%x, protection bits 0x%x\n",
   	              va, PTE_ADDR(pte), (pte & ((1<<12)-1)));
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
  nk_paging_aspace_t *p;
  
  p = malloc(sizeof(*p));
  
  if (!p) {
    ERROR("cannot allocate paging aspace %s\n",name);
    return 0;
  }
  
  memset(p,0,sizeof(*p));

  spinlock_init(&p->lock);
  
  //p->mm_rb = RB_ROOT;
  p->mmap = NULL; 

  p->chars.granularity = paging_state.chars.alignment = PAGE_SIZE_4KB;

  void *pml4 = malloc(PAGE_SIZE_4KB);

  if (!pml4) {
    ERROR("Failed to allocate PML4\n");
    free(p);
    return 0;
  }

  memset(pml4,0,PAGE_SIZE_4KB);
  // not sure about the construct pt
  //__construct_tables_4k(pml4, PAGE_SIZE_4KB*PAGE_SIZE_4KB); //  malloc init 16MB for this address space

  // need to actually drill page tables for basic parts of NK
  // ???
  p->cr3 = pml4;
  p->cr4 = nk_paging_default_cr4() & CR4_MASK;
  // EFER

  p->aspace = nk_aspace_register(name,
				 NK_ASPACE_HOOK_PF | NK_ASPACE_HOOK_GPF,
    struct mm_node* cur_node = p->mmap;
				 &paging_interface,
				 p);

  if (!p->aspace) {
    ERROR("Unable to register paging address space %s\n",name);
    return 0;
  }

  DEBUG("Paging address space %s configured and initialized\n", name);
    
  return p->aspace; 
}

static nk_aspace_impl_t paging = {
				.impl_name = "paging",
				.get_characteristics = get_characteristics,
				.create = create,
};


nk_aspace_register_impl(paging);


