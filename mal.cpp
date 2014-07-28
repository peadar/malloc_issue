/*
 * Show potential post-fork COW problems with a heap with many cached freed blocks.
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

/*
 * We will allocate this many small blocks, and free them, to create the initial
 * conditions.
 */

static const int blockCount = 65536;

// remember system page size for later.
static const int pagesize = getpagesize();

/*
 * HeapGuard write-protects a range of pages such that write access will produce a SIGSEGV.
 * When the SIGSEGV Is received, we increment the write fault count, and
 * unprotect the page.
 */
struct HeapGuard {
    unsigned writeFaults;
    unsigned readFaults;
    const char *msg; // used for formatting messages from the heap guard.
    // The range of memory protected.
    char *low;
    char *high;
    struct sigaction restoreAction; // The original fault handler, for restoring at destrution time.

    HeapGuard(const char *msg, char *low_, char *high_);
    ~HeapGuard();
    static HeapGuard *current; // accessable from non-member sigsegv handler.
};

// Information about allocated block. (currently, just a pointer to it)
struct BlockInfo {
    char *ptr;
};

/*
 * Heap Guard implementation
 */

// SEGV signal handling.  Only one heap guard can be active at a time.
HeapGuard *HeapGuard::current = 0;
extern "C" {
static void
sigsegv(int signo, siginfo_t *sa, void *)
{

    HeapGuard::current->writeFaults++;
    char *addr = (char *)sa->si_addr;
    addr -= (intptr_t)addr % pagesize;
    if (mprotect(addr, pagesize, PROT_READ|PROT_WRITE) != 0)
        abort();
}
}

/*
 * Create heap guard:
 *   Align start and end on page boundary,
 *   Protect as many pages as we can in the range
 *   Install signal handler for SIGSEGV, and save old status.
 *   Report on how many pages we could protect
 */
HeapGuard::HeapGuard(const char *msg_, char *low_, char *high_)
    : writeFaults(0)
    , readFaults(0)
    , msg(msg_)
    , low(low_)
    , high(high_)
{
    assert(current == 0);
    current = this;
    low -= (intptr_t)low % pagesize;
    high += pagesize - 1;
    high -= (intptr_t)high % pagesize;

    unsigned goodPages = 0;

    for (char *cur = low; cur < high; cur += pagesize)
        if (mprotect(cur, pagesize, PROT_READ) == 0)
            goodPages++;

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigsegv;

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, &restoreAction) == -1)
        err(2, "can't install SIGSSEGV handler");
    fprintf(stderr, "%s: watching %u of %lu pages\n", msg, goodPages, (high - low) / pagesize);
}

/*
 * Tear down heap guard:
 *   attempt to mark all pages in the range READ|WRITE
 *   reinstall old SIGSEGV handler
 *   report on faults, and the number of pages we successfully restored (this
 *   may differ from the number we protected if the malloc implementation
 *   returned anything back to the OS in the meantime)
 */
HeapGuard::~HeapGuard()
{
    assert(current == this);
    current = 0;

    unsigned goodPages = 0;
    for (char *cur = low; cur < high; cur += pagesize)
        if (mprotect(cur, pagesize, PROT_READ|PROT_WRITE) == 0)
            goodPages++;
    if (sigaction(SIGSEGV, &restoreAction, 0) == -1)
        err(2, "can't restore SIGSSEGV handler");
    fprintf(stderr, "%s: write faults: %d, stopped watching %u of %lu pages\n",
            msg, writeFaults, goodPages, (high - low) / pagesize);
}


/*
 * Look at the pathology in question:
 *    Allocate a large number of small memory blocks.
 *    Free them (monitoring write access to pages)
 *    just for completeness, fork and wait for a child that:
 *         allocates one large(ish) block of memory, while monitoring page
 *         writes.
 */
int
main(int argc, char *argv[])
{
    int c;

    unsigned long bigSize = 1024;
    unsigned long smallSize = 4;
    bool preforkAlloc = false;

    while ((c = getopt(argc, argv, "pl:s:")) != -1) {
        switch (c) {
            case 'p':
                preforkAlloc = true;
                break;
            case 'l':
                bigSize = strtoul(optarg, 0, 0);
                break;
            case 's':
                smallSize = strtoul(optarg, 0, 0);
                break;
            default:
                fprintf(stderr, "usage: mal [-p] [-b size] [-s size]\n");
                fprintf(stderr, "\t[-p] : apply-prefork alloc to work around pathology\n");
                fprintf(stderr, "\t[-s size] : make 'small' allocs be size bytes\n");
                fprintf(stderr, "\t[-l size] : make 'large' alloc be size bytes\n");
                exit(255);
                break;
        }
    }

    fprintf(stderr,
        "settings: small alloc size=%lu, "
        "big alloc size=%lu, alloc before fork?  %s\n",
        smallSize, bigSize, preforkAlloc ? "yes" : "no");

    BlockInfo blocks[blockCount]; // on stack
    BlockInfo *last = blocks + blockCount;

    char *low = 0, *high = 0;

    for (BlockInfo *block = blocks; block != last; ++block) {
        block->ptr = (char *)malloc(smallSize);
        if (high == 0 || high < block->ptr)
            high = block->ptr;
        if (low == 0 || low > block->ptr)
            low = block->ptr;
    }

    for (BlockInfo *block = blocks; block != last; ++block)
        free(block->ptr);

    if (preforkAlloc)
        free(malloc(bigSize));

    pid_t pid;
    switch (pid = fork()) {
        case 0: { // child
            HeapGuard guard("allocating large buffer", low, high);
            malloc(bigSize);
            break;
        }
        default: { // parent
            int status;
            if (waitpid(pid, &status, 0) == -1)
                err(4, "waitpid failed");
            break;
        }
        case -1: {
            err(3, "fork failed");
            break;
        }
    }
    return 0;
}
