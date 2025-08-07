/*
 * QEMU RISC-V VSPMP (Virtual S-mode Physical Memory Protection)
 *
 * Author: Luís Cunha luisccunha8@gmail.com
 *
 * This provides a RISC-V Virtual S-mode Physical Memory Protection interface
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "trace.h"
#include "exec/exec-all.h"

/*
 * Check whether mstatus.sum is set.
 */
static inline bool sum_is_set(CPURISCVState *env)
{
    if (env->vsstatus & MSTATUS_SUM) {
        return true;
    }

    return false;
}

/*
 * Count the number of active rules.
 */
static inline uint32_t vspmp_get_num_rules(CPURISCVState *env)
{
     return env->vspmp_state.num_rules;
}

static void vspmp_update_rule_addr(CPURISCVState *env, uint32_t vspmp_index)
{
    uint8_t this_cfg = env->vspmp_state.spmp[vspmp_index].cfg_reg;
    target_ulong this_addr = env->vspmp_state.spmp[vspmp_index].addr_reg;
    target_ulong prev_addr = 0u;
    target_ulong sa = 0u;
    target_ulong ea = 0u;

    if (vspmp_index >= 1u) {
        prev_addr = env->vspmp_state.spmp[vspmp_index - 1].addr_reg;
    }

    switch (spmp_get_a_field(this_cfg)) {
    case SPMP_AMATCH_OFF:
        sa = 0u;
        ea = -1;
        break;

    case SPMP_AMATCH_TOR:
        sa = prev_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (this_addr << 2) - 1u;
        break;

    case SPMP_AMATCH_NA4:
        sa = this_addr << 2; /* shift up from [xx:0] to [xx+2:2] */
        ea = (sa + 4u) - 1u;
        break;

    case SPMP_AMATCH_NAPOT:
        spmp_decode_napot(this_addr, &sa, &ea);
        break;

    default:
        sa = 0u;
        ea = 0u;
        break;
    }

    env->vspmp_state.addr[vspmp_index].sa = sa;
    env->vspmp_state.addr[vspmp_index].ea = ea;
    qemu_log_mask(CPU_LOG_SPMP,
                      "%s: Entry %d - start_addr: " HWADDR_FMT_plx ", end_addr: " HWADDR_FMT_plx "\n", __func__, vspmp_index, sa, ea);
}

static void vspmp_update_rule_nums(CPURISCVState *env)
{
    int i;

    env->vspmp_state.num_rules = 0;
    for (i = 0; i < MAX_RISCV_SPMPS; i++) {
        const uint8_t a_field =
            spmp_get_a_field(env->vspmp_state.spmp[i].cfg_reg);
        if (SPMP_AMATCH_OFF != a_field) {
            env->vspmp_state.num_rules++;
        }
    }
}

/* Convert cfg/addr reg values here into simple 'sa' --> start address and 'ea'
 *   end address values.
 *   This function is called relatively infrequently whereas the check that
 *   an address is within a spmp rule is called often, so optimise that one
 */
static void vspmp_update_rule(CPURISCVState *env, uint32_t vspmp_index)
{
    vspmp_update_rule_addr(env, vspmp_index);
    vspmp_update_rule_nums(env);
}

static uint8_t vspmp_is_in_range(CPURISCVState *env, int vspmp_index, target_ulong addr)
{
    if ((addr >= env->vspmp_state.addr[vspmp_index].sa)
        && (addr <= env->vspmp_state.addr[vspmp_index].ea)) {
        return 1;
    }

    return 0;
}

static bool vspmp_get_vspmpswitch_bit(CPURISCVState *env, int vspmp_index)
{
    return (env->vspmpswitch >> vspmp_index) & 0x1;
}

/*
 * Check if the address has required RWX privs when no SPMP entry is matched.
 */
static bool vspmp_hart_has_privs_default(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode)
{
    bool ret;

    if ((!riscv_cpu_cfg(env)->vspmp) || mode != PRV_U) {
        /*
         * The SPMP proposal states three circumstances that the access is allowed:
         * 1. The HW does not implement any SPMP entry.
         * 2. If the effective privilege mode of the access is S and no SPMP entry matches
         * 3. The access mode is M.
         */
        ret = true;
        *allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
    } else {
        /*
         * U-mode is not allowed to succeed if they don't match a rule,
         * but there are rules. We've checked for those rules earlier in this
         * function.
         */
        ret = false;
        *allowed_privs = 0;
    }

    return ret;
}


/*
 * Public Interface
 */

/*
 * Check if the address has required RWX privs to complete desired operation
 */
bool vspmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode)
{
    int i = 0;
    int ret = -1;
    int vspmp_size = 0;
    uint8_t s = 0, e = 0;
    bool vspmpswitch_en = false;

	/* Short cut for non-virtual accesses*/
    bool virt = env->virt_enabled;
    if (!virt) {
		*allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
		return true;
	}

    /* Short cut if no rules */
    if (0 == vspmp_get_num_rules(env)) {
        return vspmp_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    if (size == 0) {
        if (riscv_cpu_cfg(env)->mmu) {
            /*
             * If size is unknown (0), assume that all bytes
             * from addr to the end of the page will be accessed.
             */
            vspmp_size = -(addr | TARGET_PAGE_MASK);
        } else {
            vspmp_size = sizeof(target_ulong);
        }
    } else {
        vspmp_size = size;
    }

    for (i = 0; i < MAX_RISCV_VSPMPS; i++) {
        s = vspmp_is_in_range(env, i, addr);
        e = vspmp_is_in_range(env, i, addr + vspmp_size - 1);
        vspmpswitch_en = vspmp_get_vspmpswitch_bit(env, i);

        /* partially inside */
        if ((s + e) == 1) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: vspmp violation - access is partially inside\n", __func__);
            ret = 0;
            break;
        }

        /* fully inside */
        const uint8_t a_field =
            spmp_get_a_field(env->vspmp_state.spmp[i].cfg_reg);

        /*
         * Convert the VSPMP permissions to match the truth table in the SPMP spec.
         * 
         */
        const uint8_t vspmp_operation = (env->vspmp_state.spmp[i].cfg_reg & SPMP_EXEC)
                                       | (env->vspmp_state.spmp[i].cfg_reg & SPMP_WRITE)
                                       | (env->vspmp_state.spmp[i].cfg_reg & SPMP_READ);

        if (((s + e) == 2) && (SPMP_AMATCH_OFF != a_field) && vspmpswitch_en) {
            /*
             * If the SPMP entry is not off, spmpswitch bit is set, and the address is in range,
             * do the priv check
             */
            if(!(env->vspmp_state.spmp[i].cfg_reg & SPMP_SHARED)) {
                /*  
                *   Deny if:
                *   S mode access, with SUM not set, and UMODE set.
                *   U mode access, with UMODE not set.
                */
                if((mode == PRV_S && !sum_is_set(env) && (env->vspmp_state.spmp[i].cfg_reg & SPMP_UMODE)) ||
                  (mode == PRV_U && !(env->vspmp_state.spmp[i].cfg_reg & SPMP_UMODE))) {
                    *allowed_privs = 0;
                }
                else if (mode == PRV_S && sum_is_set(env) && (env->vspmp_state.spmp[i].cfg_reg & SPMP_UMODE)){
                    switch (vspmp_operation) {
                        case 0:
                        case 2:
                        case 4:
                        case 6:
                            *allowed_privs = 0;
                            break;
                        case 1:
                        case 5:
                            *allowed_privs = SPMP_READ;
                            break;
                        case 3:
                        case 7:
                            *allowed_privs = SPMP_READ | SPMP_WRITE;
                            break;
                        default:
                            g_assert_not_reached();
                    }
                }
                else {
                    // Check for reserved configs
                    if(vspmp_operation == 2 || vspmp_operation == 6)
                        *allowed_privs = 0;
                    else
                        *allowed_privs = vspmp_operation & 0x7;
                }
            }
            else {
                if(mode == PRV_S){
                    // Check for reserved configs
                    if(vspmp_operation == 2 || vspmp_operation == 6)
                        *allowed_privs = 0;
                    else
                        *allowed_privs = vspmp_operation & 0x7;
                }
                else {
                    switch (vspmp_operation) {
                        case 0:
                        case 2:
                        case 6:
                            *allowed_privs = 0;
                            break;
                        case 1:
                        case 3:
                            *allowed_privs = SPMP_READ;
                            break;
                        case 4:
                        case 7:
                            *allowed_privs = SPMP_EXEC;
                            break;
                        case 5:
                            *allowed_privs = SPMP_READ | SPMP_EXEC;
                            break;
                        default:
                            g_assert_not_reached();
                    }
                }
            }
            
            ret = ((privs & *allowed_privs) == privs);
            break;
        }
    }

    /* No rule matched */
    if (ret == -1) {
        return vspmp_hart_has_privs_default(env, addr, size, privs,
                                          allowed_privs, mode);
    }

    return ret == 1 ? true : false;
}

/*
 * Accessor to set the cfg reg for a specific SPMP/HART
 * Bounds checks.
 */
void vspmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val, bool s_mode_access)
{
    // S mode bypasses the lock
    bool locked = s_mode_access ? 0 :
                    (env->vspmp_state.spmp[reg_index].cfg_reg & SPMP_LOCK) >> 7;

    // If within bounds and not locked
    if (reg_index < MAX_RISCV_VSPMPS && !locked) {
    
        env->vspmp_state.spmp[reg_index].cfg_reg = val;
        vspmp_update_rule(env, reg_index);
        qemu_log_mask(CPU_LOG_SPMP,
                      "%s: new config: " HWADDR_FMT_plx " in entry: %d\n", __func__, val, reg_index);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: ignoring vspmpcfg write - out of bounds\n", __func__);
    }
}

/*
 * Handle a read from a spmpcfg CSR
 */
target_ulong vspmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index)
{
    if (reg_index < MAX_RISCV_VSPMPS) {
        return env->vspmp_state.spmp[reg_index].cfg_reg;
    }

    return 0;
}

/*
 * Handle a write to a spmpaddr CSR
 */
void vspmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val, bool s_mode_access)
{
    // M mode bypasses the lock
    bool locked = s_mode_access ? 0 : 
                    (env->vspmp_state.spmp[addr_index].cfg_reg & SPMP_LOCK) >> 7;

    // If within bounds and not locked
    if (addr_index < MAX_RISCV_SPMPS && !locked) {

        env->vspmp_state.spmp[addr_index].addr_reg = val;
        vspmp_update_rule(env, addr_index);
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: ignoring spmpaddr write - out of bounds\n", __func__);
    }
}

/*
 * Handle a read from a spmpaddr CSR
 */
target_ulong vspmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index)
{
    target_ulong val = 0;

    if (addr_index < MAX_RISCV_SPMPS) {
        val = env->vspmp_state.spmp[addr_index].addr_reg;
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: ignoring spmpaddr read - out of bounds\n", __func__);
    }

    return val;
}

void vspmp_unlock_entries(CPURISCVState *env)
{
    // Reset everything
    for (int i = 0; i < MAX_RISCV_VSPMPS; i++) {
        env->vspmp_state.spmp[i].cfg_reg &= ~(SPMP_LOCK | SPMP_AMATCH);
    }
}