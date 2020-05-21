/*
 * Automatically generated C config: don't edit
 * Nautilus version: 
 * Thu May 21 11:22:53 2020
 */
#define AUTOCONF_INCLUDED

/*
 * Platform
 */
#undef NAUT_CONFIG_X86_64_HOST
#define NAUT_CONFIG_X86_32_HOST 1
#undef NAUT_CONFIG_XEON_PHI
#undef NAUT_CONFIG_HVM_HRT
#undef NAUT_CONFIG_GEM5
#define NAUT_CONFIG_MAX_CPUS 256
#define NAUT_CONFIG_MAX_IOAPICS 16

/*
 * Build
 */
#define NAUT_CONFIG_USE_NAUT_BUILTINS 1
#define NAUT_CONFIG_CXX_SUPPORT 1
#undef NAUT_CONFIG_RUST_SUPPORT
#define NAUT_CONFIG_USE_GCC 1
#undef NAUT_CONFIG_USE_CLANG
#undef NAUT_CONFIG_USE_WLLVM
#define NAUT_CONFIG_COMPILER_PREFIX ""
#define NAUT_CONFIG_COMPILER_SUFFIX ""
#define NAUT_CONFIG_TOOLCHAIN_ROOT ""

/*
 * Configuration
 */
#define NAUT_CONFIG_MAX_THREADS 1024
#undef NAUT_CONFIG_RUN_TESTS_AT_BOOT
#define NAUT_CONFIG_THREAD_EXIT_KEYCODE 196
#undef NAUT_CONFIG_USE_TICKETLOCKS
#undef NAUT_CONFIG_PARTITION_SUPPORT
#define NAUT_CONFIG_VIRTUAL_CONSOLE_DISPLAY_NAME 1
#undef NAUT_CONFIG_VIRTUAL_CONSOLE_CHARDEV_CONSOLE
#define NAUT_CONFIG_VIRTUAL_CONSOLE_SERIAL_MIRROR 1
#define NAUT_CONFIG_VIRTUAL_CONSOLE_SERIAL_MIRROR_ALL 1

/*
 * Scheduler Options
 */
#define NAUT_CONFIG_UTILIZATION_LIMIT 99
#define NAUT_CONFIG_SPORADIC_RESERVATION 10
#define NAUT_CONFIG_APERIODIC_RESERVATION 10
#define NAUT_CONFIG_HZ 10
#define NAUT_CONFIG_INTERRUPT_REINJECTION_DELAY_NS 10000
#undef NAUT_CONFIG_AUTO_REAP
#undef NAUT_CONFIG_WORK_STEALING
#undef NAUT_CONFIG_TASK_IN_SCHED
#undef NAUT_CONFIG_TASK_THREAD
#undef NAUT_CONFIG_TASK_IN_IDLE
#undef NAUT_CONFIG_INTERRUPT_THREAD
#undef NAUT_CONFIG_APERIODIC_DYNAMIC_QUANTUM
#undef NAUT_CONFIG_APERIODIC_DYNAMIC_LIFETIME
#undef NAUT_CONFIG_APERIODIC_LOTTERY
#define NAUT_CONFIG_APERIODIC_ROUND_ROBIN 1

/*
 * Fiber Options
 */
#undef NAUT_CONFIG_FIBER_ENABLE
#undef NAUT_CONFIG_REAL_MODE_INTERFACE

/*
 * Watchdog Options
 */
#define NAUT_CONFIG_WATCHDOG 1
#define NAUT_CONFIG_WATCHDOG_DEFAULT_TIME_MS 1000
#undef NAUT_CONFIG_DEBUG_WATCHDOG
#undef NAUT_CONFIG_ISOCORE

/*
 * Garbage Collection Options
 */
#undef NAUT_CONFIG_GARBAGE_COLLECTION

/*
 * FPU Options
 */
#undef NAUT_CONFIG_XSAVE_SUPPORT

/*
 * Optimizations
 */
#define NAUT_CONFIG_FPU_SAVE 1
#define NAUT_CONFIG_KICK_SCHEDULE 1
#define NAUT_CONFIG_HALT_WHILE_IDLE 1
#undef NAUT_CONFIG_THREAD_OPTIMIZE

/*
 * Debugging
 */
#define NAUT_CONFIG_DEBUG_INFO 1
#define NAUT_CONFIG_DEBUG_PRINTS 1
#define NAUT_CONFIG_ENABLE_ASSERTS 1
#undef NAUT_CONFIG_PROFILE
#undef NAUT_CONFIG_SILENCE_UNDEF_ERR
#undef NAUT_CONFIG_ENABLE_STACK_CHECK
#undef NAUT_CONFIG_ENABLE_REMOTE_DEBUGGING
#define NAUT_CONFIG_ENABLE_MONITOR 1
#undef NAUT_CONFIG_DEBUG_PAGING
#undef NAUT_CONFIG_DEBUG_BOOTMEM
#undef NAUT_CONFIG_DEBUG_CMDLINE
#undef NAUT_CONFIG_DEBUG_TESTS
#undef NAUT_CONFIG_DEBUG_BUDDY
#undef NAUT_CONFIG_DEBUG_KMEM
#undef NAUT_CONFIG_DEBUG_FPU
#undef NAUT_CONFIG_DEBUG_SMP
#undef NAUT_CONFIG_DEBUG_SHELL
#undef NAUT_CONFIG_DEBUG_SFI
#undef NAUT_CONFIG_DEBUG_CXX
#undef NAUT_CONFIG_DEBUG_THREADS
#undef NAUT_CONFIG_DEBUG_TASKS
#undef NAUT_CONFIG_DEBUG_WAITQUEUES
#undef NAUT_CONFIG_DEBUG_FUTURES
#undef NAUT_CONFIG_DEBUG_GROUP
#undef NAUT_CONFIG_DEBUG_SCHED
#undef NAUT_CONFIG_DEBUG_GROUP_SCHED
#undef NAUT_CONFIG_DEBUG_TIMERS
#undef NAUT_CONFIG_DEBUG_SEMAPHORES
#undef NAUT_CONFIG_DEBUG_MSG_QUEUES
#undef NAUT_CONFIG_DEBUG_SYNCH
#undef NAUT_CONFIG_DEBUG_BARRIER
#undef NAUT_CONFIG_DEBUG_NUMA
#undef NAUT_CONFIG_DEBUG_VIRTUAL_CONSOLE
#undef NAUT_CONFIG_DEBUG_DEV
#undef NAUT_CONFIG_DEBUG_FILESYSTEM
#undef NAUT_CONFIG_DEBUG_LOADER
#undef NAUT_CONFIG_DEBUG_LINKER
#undef NAUT_CONFIG_DEBUG_PMC

/*
 * Address Spaces
 */

/*
 * Runtimes
 */
#undef NAUT_CONFIG_LEGION_RT
#undef NAUT_CONFIG_NDPC_RT
#undef NAUT_CONFIG_NESL_RT
#undef NAUT_CONFIG_OPENMP_RT
#define NAUT_CONFIG_RACKET_RT 1

/*
 * Devices
 */

/*
 * Serial Options
 */
#define NAUT_CONFIG_SERIAL_REDIRECT 1
#define NAUT_CONFIG_SERIAL_REDIRECT_PORT 1
#undef NAUT_CONFIG_APIC_FORCE_XAPIC_MODE
#undef NAUT_CONFIG_APIC_TIMER_CALIBRATE_INDEPENDENTLY
#undef NAUT_CONFIG_DEBUG_APIC
#undef NAUT_CONFIG_DEBUG_IOAPIC
#undef NAUT_CONFIG_DEBUG_PCI
#define NAUT_CONFIG_DISABLE_PS2_MOUSE 1
#undef NAUT_CONFIG_DEBUG_PS2
#undef NAUT_CONFIG_GPIO
#undef NAUT_CONFIG_DEBUG_PIT
#undef NAUT_CONFIG_RAMDISK
#define NAUT_CONFIG_ATA 1
#define NAUT_CONFIG_DEBUG_ATA 1

/*
 * Filesystems
 */
#undef NAUT_CONFIG_EXT2_FILESYSTEM_DRIVER
#undef NAUT_CONFIG_FAT32_FILESYSTEM_DRIVER

/*
 * Networking
 */
#define NAUT_CONFIG_NET_ETHERNET 1
#define NAUT_CONFIG_DEBUG_NET_ETHERNET_PACKET 1
#define NAUT_CONFIG_DEBUG_NET_ETHERNET_AGENT 1
#define NAUT_CONFIG_DEBUG_NET_ETHERNET_ARP 1
#undef NAUT_CONFIG_NET_COLLECTIVE
#undef NAUT_CONFIG_NET_LWIP

/*
 * Languages
 */
#undef NAUT_CONFIG_LOAD_LUA
