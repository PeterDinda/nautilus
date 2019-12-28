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

// Some macros to hide the details of doing locking for
// a paging address space
#define ASPACE_LOCK_CONF uint8_t _aspace_lock_flags
#define ASPACE_LOCK(a) _aspace_lock_flags = spin_lock_irq_save(&(a)->lock)
#define ASPACE_TRY_LOCK(a) spin_try_lock_irq_save(&(a)->lock,&_aspace_lock_flags)
#define ASPACE_UNLOCK(a) spin_unlock_irq_restore(&(a)->lock, _aspace_lock_flags);
#define ASPACE_UNIRQ(a) irq_enable_restore(_aspace_lock_flags);


// graceful printouts of names
#define ASPACE_NAME(a) ((a)?(a)->aspace->name : "default")
#define THREAD_NAME(t) ((!(t)) ? "(none)" : (t)->is_idle ? "(idle)" : (t)->name[0] ? (t)->name : "(noname)")


static int print(void *state, int detailed);

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


static void pagewalk_analysis(uint64_t va, int level, uint64_t *entry, ph_pf_access_t access_type){
    DEBUG("Vaddr %016lx page walk function failed in %dth level\n", va, level);
    ph_pte_t *pte = (ph_pte_t*)entry;
    if(!pte->present){
        DEBUG("page walk function failed due to vaddr %016lx page is not present\n", va);    
    }
    else if(pte->writable < access_type.write){
        DEBUG("page walk function failed due to vaddr %016lx page's write protection \n", va);    
    }
    else if(pte->user < access_type.user){
        DEBUG("page walk function failed due to vaddr %016lx page's kernel only protection \n", va);    
    }
    else if(pte->no_exec >= access_type.ifetch){
        DEBUG("page walk function failed due to vaddr %016lx page's not executable protection \n", va);    
    }
}


static int destroy(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // free regions in list
    struct list_head *pos = &(p->region_list);
    list_for_each(pos, &p->region_list){
      mm_node *node = (mm_node *)(pos - sizeof(nk_aspace_region_t));
      free(node);
    }

    ASPACE_LOCK_CONF;
    // lets do that with a lock, perhaps? 
    ASPACE_LOCK(p);

    // free paging table
    paging_helper_free(p->cr3, 1);
    // free aspace struct
    free(p); 
    ASPACE_UNLOCK(p);
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
    DEBUG("in add resion region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)new_node->region.va_start, (void*)new_node->region.pa_start, new_node->region.len_bytes);      

    DEBUG("survived region set\n");

    // haven't write the sanity check
    
    list_add(&(new_node->node), &(p->region_list));

    nk_aspace_region_t *current = 0;
    struct list_head *pos = &(p->region_list);
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      DEBUG("!!!!!!!!! region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)current->va_start, (void*)current->pa_start, current->len_bytes);      
    }
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
	    ERROR("Could not map page at vaddr %p paddr %p\n", cur_page, phy_page);
	}
    }
    DEBUG("Finished drill\n");
  }
	
    // if we are editing the current address space of this cpu, then we
    // might need to flush the TLB here.   We can do that with a cr3 write
    // like: write_cr3(p->cr3.val);

    // if this aspace is active on a different cpu, we might need to do
    // a TLB shootdown here (out of scope of class)
    // a TLB shootdown is an interrupt to a remote CPU whose handler
    // flushes the TLB
    
    return 0;
}

static int remove_region(void *state, nk_aspace_region_t *region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    // assume the region we need to remove exists in the current linked list
    struct list_head *pos = &(p->region_list);
    nk_aspace_region_t *current = 0;
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      if(current->va_start == region->va_start && current->pa_start == region->pa_start &&
                 current->len_bytes == region->len_bytes){
        break;
      }
      current = 0;
    }

    if (!current) {
	ERROR("failed to find region\n");
	return -1;
    }
    mm_node *current_mmnode = (mm_node *)current;
    list_del(&(current_mmnode->node));
    free(current_mmnode);

    pos = &(p->region_list);
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      DEBUG("!!!!!!!!! region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)current->va_start, (void*)current->pa_start, current->len_bytes);      
    }
    DEBUG("survived list remove\n");
    

    // edit page tables to match
    pte_t *pte;
    ph_pf_access_t access_type = {
        .present = 0,
        .write = 1,
        .user = 0,
        .ifetch = 1,
    };
    addr_t cur_page;
    ph_pte_t *p_pte;
    int walk_res = 0;
    for (cur_page = (addr_t) region->va_start;
	 cur_page < (addr_t) (region->va_start + region->len_bytes);
	 cur_page += PAGE_SIZE_4KB){

      //DEBUG("remove page on %016lx\n",cur_page);
      if((walk_res = paging_helper_walk(p->cr3, cur_page, access_type, &pte)) != 0){
        //panic("Cannot find the page at addr 0x%x\n", cur_page);
        pagewalk_analysis(cur_page, walk_res, pte, access_type);
        continue;
      }
      p_pte = (ph_pte_t*)pte;
      p_pte->present = 0;
      //*pte &= ~PTE_PRESENT_BIT;
    } 
    // write_cr3((p->cr3).pml4_base); 
    return 0;
}
   
static int protect_region(void *state, nk_aspace_region_t *region, nk_aspace_protection_t *prot)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct list_head *pos = &(p->region_list);
    nk_aspace_region_t *current = 0;
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      //if(current->va_start == region->va_start && current->pa_start == region->pa_start &&
      //           current->len_bytes == region->len_bytes){
      if(current->va_start == region->va_start && current->pa_start == region->pa_start){                 
        break;
      }
      current = 0;
    }

    if (!current) {
	ERROR("failed to find region\n");
	return -1;
    }
    DEBUG("Original region flag 0x%x\n", current->protect.flags); 
    current->protect.flags &= (prot->flags);
    DEBUG("Protect flag 0x%x, New region flag is 0x%x\n", (prot->flags), current->protect.flags); 
    // now need to edit page tables to match
    pte_t* pte;
    ph_pf_access_t access_type = {
        .present = 0,
        .write = 1,
        .user = 0,
        .ifetch = 1,
    };
    addr_t cur_page;
    ph_pte_t *p_pte;

    DEBUG("Protect region start from va 0x%lx to va 0x%lx\n", region->va_start, region->va_start + region->len_bytes);
    int walk_res = 0;
    for (cur_page = (addr_t) region->va_start;
	 cur_page < (addr_t) (region->va_start + region->len_bytes);
	 cur_page += PAGE_SIZE_4KB){
      if((walk_res = paging_helper_walk(p->cr3, cur_page, access_type, &pte)) != 0){
        //DEBUG("Cannot find the page at addr 0x%lx\n", cur_page);
        pagewalk_analysis(cur_page, walk_res, pte, access_type);
        continue;
      }
      p_pte = (ph_pte_t*)pte;
      // FIX ME
      // means it is a write protection
      // so we need to make the writable flag in pte zero
      DEBUG("Original pte is 0x%lx\n", *pte);
      if(!((prot->flags) & NK_ASPACE_WRITE)){
        p_pte->writable = 0; 
        DEBUG("Cannot write the page at addr 0x%lx\n", cur_page);
      }
 
      DEBUG("New pte is 0x%lx\n", *pte);
      print((void*)p, 1);
      invlpg(cur_page);
    }
    
    write_cr3(p->cr3.val); 
    return 0;
}

static int move_region(void *state, nk_aspace_region_t *cur_region, nk_aspace_region_t *new_region)
{
    if(cur_region->len_bytes != new_region->len_bytes)
      ERROR("Cannot move two regions that have different length\n");
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    uint64_t va_start = (uint64_t)cur_region->va_start;
    uint64_t va_end = (uint64_t)cur_region->va_start + cur_region->len_bytes;

    // first, find the region in your data structure
    // it had better exist and be identical except for the physical addresses
    struct list_head *pos = &(p->region_list);
    nk_aspace_region_t *current = 0;
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      if(va_start >= (addr_t)current->va_start && va_end <= (addr_t)(current->va_start + current->len_bytes)){
        break;
      }
      current = 0;
    }
    if (!current) {
        // kernel thread panic
	panic("failed to find region\n");
        // kill user thread(how to know it is a user thread)
        // thread->status = NK_THR_SUSPENDED;
	return -1;
    }

    // next, update the region in your data structure
    // ADVANCED VERSION: allow for splitting the region - if cur_region
    // is a subset of some region, then split that region, and only move
    // the affected addresses.   The granularity of this is that reported
    // in the aspace characteristics (i.e., page granularity here).
    //remove_region(state, cur_region);
    //add_region(state, new_region);
    mm_node *current_mmnode = (mm_node *)current;
    list_del(&(current_mmnode->node));
    // identical region
    if(va_start == (addr_t)current->va_start && va_end == (addr_t)(current->va_start + current->len_bytes)){
      mm_node *current_mmnode = (mm_node *)current;
      list_del(&(current_mmnode->node));
      free(current_mmnode);     
    }
    // subset of the region
    else{
        if(va_start > (addr_t)current->va_start){
            mm_node* new_node = (mm_node*)malloc(sizeof(mm_node));
            if (!new_node) { 
	        ERROR("failed to allocate new mm_node\n");
	        return -1;
            }    
            nk_aspace_region_t r;
            r.va_start = current->va_start;
	    r.pa_start = current->pa_start;
	    r.len_bytes = va_start - (addr_t)current->va_start;
            r.protect.flags = current->protect.flags;
            new_node->region = r;
            DEBUG("in add region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)new_node->region.va_start, (void*)new_node->region.pa_start, new_node->region.len_bytes);      
            list_add(&(new_node->node), &(p->region_list));
        }
        if(va_end < (addr_t)(current->va_start + current->len_bytes)){
            mm_node* new_node = (mm_node*)malloc(sizeof(mm_node));
            if (!new_node) { 
	        ERROR("failed to allocate new mm_node\n");
	        return -1;
            }    
            nk_aspace_region_t r;
            r.va_start = (void*)va_end;
	    r.pa_start = (void*)(current->pa_start + (va_end - (addr_t)current->va_start));
	    r.len_bytes = (addr_t)(current->va_start + current->len_bytes) - va_end;
            r.protect.flags = current->protect.flags;
            new_node->region = r;
            DEBUG("in add region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)new_node->region.va_start, (void*)new_node->region.pa_start, new_node->region.len_bytes);      
            list_add(&(new_node->node), &(p->region_list));
        }
    }
    free(current_mmnode);

    // add new_region into list
    mm_node* new_node = (mm_node*)malloc(sizeof(mm_node));
    if (!new_node) { 
	ERROR("failed to allocate new mm_node\n");
	return -1;
    }
    new_node->region = *new_region;
    DEBUG("in add resion region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)new_node->region.va_start, (void*)new_node->region.pa_start, new_node->region.len_bytes);      
    list_add(&(new_node->node), &(p->region_list));


    current = 0;
    pos = &(p->region_list);
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      DEBUG("!!!!!!!!! region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)current->va_start, (void*)current->pa_start, current->len_bytes);      
    }
    DEBUG("survived list add\n");


    //uint64_t pa = (addr_t)current->pa_start + (va - (addr_t)current->va_start);




    // next, update all corresponding page table entries that exist
    // drill page table if NK_ASPACE_EAGER
    if(new_region->protect.flags & NK_ASPACE_EAGER){
        addr_t cur_page, phy_page;
        ph_pf_access_t access_type = {
	    .present = 0,
	    .write = 1, 
	    .user = 0,
	    .ifetch = 1,
        };
        DEBUG("starting to drill from %016lx to %016lx\n", new_region->va_start, new_region->va_start + new_region->len_bytes);
        phy_page = (addr_t) new_region->pa_start; 
        for (cur_page = (addr_t) new_region->va_start;
	    cur_page < (addr_t) (new_region->va_start + new_region->len_bytes);
	    cur_page += PAGE_SIZE_4KB, phy_page += PAGE_SIZE_4KB ) {	
	    if (paging_helper_drill(p->cr3, cur_page, phy_page, access_type) != 0) {
	        ERROR("Could not map page at vaddr %p paddr %p\n", cur_page, phy_page);
	    }
        }
        DEBUG("Finished drill\n");
    }
    // clear the page table entries of cur_region
    pte_t *pte;
    ph_pf_access_t access_type = {
        .present = 0,
        .write = 1,
        .user = 0,
        .ifetch = 1,
    };
    addr_t cur_page;
    ph_pte_t *p_pte;
    int walk_res = 0;
    for (cur_page = (addr_t) cur_region->va_start;
	 cur_page < (addr_t) (cur_region->va_start + cur_region->len_bytes);
	 cur_page += PAGE_SIZE_4KB){
      if((walk_res = paging_helper_walk(p->cr3, cur_page, access_type, &pte)) != 0){
        pagewalk_analysis(cur_page, walk_res, pte, access_type);
        continue;
        //panic("Cannot find the page at addr 0x%x\n", cur_page);
      }
      p_pte = (ph_pte_t*)pte;
      p_pte->present = 0;
    }    
    write_cr3(p->cr3.val);
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
    //DEBUG("exception 0x%x on thread %d\n", vec, thread->tid);

    if (vec==GP_EXCP) {
      ERROR("general protection fault encountered.... uh...\n");
      ERROR("i have seen things that you people would not believe.\n");
      panic("general protection fault delivered to paging subsystem\n");
      return -1; // will never happen
    }

    if (vec!=PF_EXCP) {
      ERROR("Unknown exception %d delivered to paging subsystem\n",vec);
      panic("Unknown exception delivered to paging subsystem\n");
      return -1; // will never happen
    }

    uint64_t va = read_cr2();
    ph_pf_error_t  error; // change ph_pf_error_t from struct to union
    // FIX ME 
    error.val = exp->error_code;
    //DEBUG("error code 0x%x on thread %d\n", error.val, thread->tid);
    
    //ASPACE_LOCK_CONF;
    
    //ASPACE_LOCK(p)

    struct list_head *pos = &(p->region_list);
    nk_aspace_region_t *current = 0;
    
    list_for_each(pos, &p->region_list){
      current = (nk_aspace_region_t *)((void*)pos - sizeof(nk_aspace_region_t));
      if(va >= (addr_t)current->va_start && va < (addr_t)(current->va_start + current->len_bytes)){
        //DEBUG("In exception we find region va start 0x%016lx pa start 0x%016lx, len %lx!!!!!!!\n", (void*)current->va_start, (void*)current->pa_start, current->len_bytes);      
        break;
      }
      current = 0;
    }
    if (!current) {
        // FIX ME
        // kernel thread panic
	panic("failed to find region\n");
        // kill user thread(how to know it is a user thread)
        // thread->status = NK_THR_SUSPENDED;
	return -1;
    }
    uint64_t pa = (addr_t)current->pa_start + (va - (addr_t)current->va_start);
    
    //DEBUG("Some Error of page 0x%lx\n", (void*)va);
    if(!error.present){
      //DEBUG("Error Error of page 0x%lx is not present\n", (void*)va);
      uint64_t *pte;
      ph_pf_access_t access_type = {
        .present = 0,
        .write = 1,
        .user = 0,
        .ifetch = 1,
      };
      int walk_res = 0;
      // page not present
      if((walk_res = paging_helper_walk(p->cr3, va, access_type, &pte)) != 0){
        pagewalk_analysis(va, walk_res, pte, access_type);
        //DEBUG("we cannot find the page 0x%lx\n", (void*)va);
        if(paging_helper_drill(p->cr3, va, pa, access_type) != 0){
          panic("Could not map page at vaddr %p paddr %p\n", (void*)va, (void*)pa);
        }
      }
      return 0;
    }
    //DEBUG("Some Error Error of page 0x%lx\n", (void*)va);
    if(error.write){
      panic("Virtual address 0x%x not writable, on thread %d\n", va, thread->tid);
      return -1;
    }
    if(error.user){
      panic("Virtual address 0x%x cannot be accessed by user thread %d\n", va, thread->tid);
      return -1;
    }
    if(error.rsvd_access){
      panic("Virtual address 0x%x reads a 1 from a reserved field, on thread %d\n", va, thread->tid);
      return -1;
    }
    if(error.ifetch){
      panic("Virtual address 0x%x access was an instr fetch (only with NX), on thread %d\n", va, thread->tid);
      return -1;
    }
    //DEBUG("Some Error Error Error of page 0x%lx\n", (void*)va);
    //ASPACE_UNLOCK(p);
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
      nk_vc_printf("   Region: %016lx - %016lx => %016lx - %016lx\n",
		   (uint64_t) region->va_start,
		   (uint64_t) region->va_start + region->len_bytes, 
		   (uint64_t) region->pa_start,
                   (uint64_t) region->pa_start + region->len_bytes);
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
      //nk_vc_printf("pml4e[%d]=%016lx\n",i,pml4e[i].val);
      ph_pdpe_t *pdpe = (ph_pdpe_t *)PAGE_NUM_TO_ADDR_4KB(pml4e[i].pdp_base);
      for (j = 0; j < NUM_PDPT_ENTRIES; j++) {
        if(pdpe[j].present){
	  //nk_vc_printf("pdpe[%d]=%016lx\n",j,pdpe[j].val);
          ph_pde_t * pde = (ph_pde_t *)PAGE_NUM_TO_ADDR_4KB(pdpe[j].pd_base);          
          for (k = 0; k < NUM_PD_ENTRIES; k++) {
            if(pde[k].present){
	      //nk_vc_printf("pde[%d]=%016lx\n",k,pde[k].val);
              ph_pte_t * pte = (ph_pte_t *)PAGE_NUM_TO_ADDR_4KB(pde[k].pt_base);
              for (m = 0; m < NUM_PT_ENTRIES; m++) {
                if(pte[m].present){
                  uint64_t va = (i << PML4_SHIFT) | (j << PDPT_SHIFT) | (k << PD_SHIFT) | (m << PT_SHIFT) ;
                  uint64_t pa = PAGE_NUM_TO_ADDR_4KB(pte[m].page_base);
                  if(va >= 0x100000000){
	            nk_vc_printf("pte[%d]=%016lx\n", m, pte[m].val);
                    nk_vc_printf("   Page: va %016lx -> pa %016lx\n", va, pa);
                  } 
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


