#pragma once

#include "propagate.h"

#include <stdbool.h>

#include "regs.h"
#include "riscv.h"
#include "params.h"
#include "logging.h"


static target_ulong propagate_taint_op__lazy(target_ulong t1, target_ulong t2)
{
    /*
     * "Lazy" as defined in Valgrind's memcheck:
     *
     * > Lazy. The V bits of all inputs to the operation are pessimistically
     * > summarised into a single bit, using chains of UifU and/or PCastX0
     * > operations. The resulting bit will indicate ``undefined'' if any part
     * > of any input is undefined. This bit is duplicated (using PCast0X) so as
     * > to give suitable shadow output word(s) for the operation.
     *
     *      https://www.usenix.org/legacy/publications/library/proceedings/usenix05/tech/general/full_papers/seward/seward_html/usenix2005.html
     *
     * In essence: reduce each operands taint to a single taint bit, then the output
     * it the AND of these bits, extended to the size of the output.
     *
     * NOTE: assumes that the operation writes to all the bits of rd.
     */

    // if any bit tainted in any of the operands, the output is completely tainted
    bool is_out_tainted = (t1 || t2);

    target_ulong tout = is_out_tainted ? -1ULL : 0;

    return tout;
}
