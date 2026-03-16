/*
 * QEMU RISC-V SPMP (S-mode Physical Memory Protection)
 *
 * Author: Bicheng Yang, SuperYbc@outlook.com
 *         Dong Du,      Ddnirvana1@gmail.com
 *
 * This provides a RISC-V S-mode Physical Memory Protection interface
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

/*
 * Heavily modified to adhere to new versions of the specification
 *      Author: Luís Cunha, luisccunha8@gmail.com
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "cpu_bits.h"
#include "trace.h"
#include "exec/exec-all.h"

typedef struct {
    spmp_table_t *table;
    bool mstatus;
    uint64_t spmpswitch;
} spmp_op_t;

/*
 * Accessor method to extract address matching type 'a field' from cfg reg
 */
static uint8_t spmp_get_a_field(uint8_t cfg)
{
    uint8_t a = cfg >> 3;
    return a & 0x3;
}

static void spmp_decode_napot(target_ulong a, target_ulong *sa, target_ulong *ea)
{
    /*
       aaaa...aaa0   8-byte NAPOT range
       aaaa...aa01   16-byte NAPOT range
       aaaa...a011   32-byte NAPOT range
       ...
       aa01...1111   2^XLEN-byte NAPOT range
       a011...1111   2^(XLEN+1)-byte NAPOT range
       0111...1111   2^(XLEN+2)-byte NAPOT range
       1111...1111   Reserved
    */
    a = (a << 2) | 0x3;
    *sa = a & (a + 1);
    *ea = a | (a + 1);
}

static void spmp_update_rule_addr(spmp_table_t *instance, uint32_t spmp_index)
{
    uint8_t this_cfg = instance->spmp[spmp_index].cfg_reg;
    target_ulong this_addr = instance->spmp[spmp_index].addr_reg;
    target_ulong prev_addr = 0u;
    target_ulong sa = 0u;
    target_ulong ea = 0u;

    if (spmp_index >= 1u) {
        prev_addr = instance->spmp[spmp_index - 1].addr_reg;
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

    instance->addr[spmp_index].sa = sa;
    instance->addr[spmp_index].ea = ea;
    qemu_log_mask(CPU_LOG_SPMP,
                      "%s: Entry %d - start_addr: " HWADDR_FMT_plx ", end_addr: " HWADDR_FMT_plx "\n", __func__, spmp_index, sa, ea);
}

static void spmp_update_rule_nums(spmp_table_t *instance)
{
    int i;

    instance->num_active_rules = 0;
    for (i = 0; i < MAX_RISCV_SPMPS; i++) {
        const uint8_t a_field =
            spmp_get_a_field(instance->spmp[i].cfg_reg);
        if (SPMP_AMATCH_OFF != a_field) {
            instance->num_active_rules++;
        }
    }
}

/* Convert cfg/addr reg values here into simple 'sa' --> start address and 'ea'
 *   end address values.
 *   This function is called relatively infrequently whereas the check that
 *   an address is within a spmp rule is called often, so optimise that one
 */
static void spmp_update_rule(spmp_table_t *instance, uint32_t spmp_index)
{
    spmp_update_rule_addr(instance, spmp_index);
    spmp_update_rule_nums(instance);
}

static uint8_t spmp_is_in_range(spmp_table_t *instance, int spmp_index, target_ulong addr)
{
    if ((addr >= instance->addr[spmp_index].sa)
        && (addr <= instance->addr[spmp_index].ea)) {
        return 1;
    }

    return 0;
}

static bool is_entry_switch_enabled(uint64_t spmpswitch, int index)
{
    return (spmpswitch >> index) & 0x1;
}

static uint64_t spmp_get_spmpswitch(CPURISCVState *env)
{
    if(!riscv_cpu_cfg(env)->ext_sspmpsw) {
        return ~0ULL;
    }

    // If it is virtualized, read from hspmpswitch
    return env->virt_enabled? env->hspmpswitch : env->spmp_state.spmpswitch;
}

static uint64_t vspmp_get_spmpswitch(CPURISCVState *env)
{
    if(!riscv_cpu_cfg(env)->ext_sspmpsw) {
        return ~0ULL;
    }

    return env->vspmp_state.spmpswitch;
}

/*
 * Check if the address has required RWX privs when no SPMP entry is matched.
 */
static bool spmp_hart_has_privs_default(bool extension_present, spmp_priv_t *allowed_privs, target_ulong mode)
{
    bool ret;
    
    if ((!extension_present) || !(mode == PRV_U)) {
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

static int spmp_evaluate_entries(spmp_op_t* op, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs, target_ulong mode)
{ 
    bool spmpswitch_en;
    uint8_t s, e;
    int i;

    /* It depends on mpmpdeleg */
    for (i = 0; i < op->table->num_deleg_rules; i++) {
        s = spmp_is_in_range(op->table, i, addr);
        e = spmp_is_in_range(op->table, i, addr + size - 1);
        spmpswitch_en = is_entry_switch_enabled(op->spmpswitch, i);

        /* partially inside */
        if ((s + e) == 1) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: spmp violation - access is partially inside\n", __func__);
            return false;
        }

        /* may be fully inside */
        const uint8_t a_field =
            spmp_get_a_field(op->table->spmp[i].cfg_reg);

        /*
         * Convert the SPMP permissions to match the truth table in the SPMP spec.
         */
        const uint8_t spmp_operation = (op->table->spmp[i].cfg_reg & SPMP_EXEC)
                                       | (op->table->spmp[i].cfg_reg & SPMP_WRITE)
                                       | (op->table->spmp[i].cfg_reg & SPMP_READ);

        if (((s + e) == 2) && (SPMP_AMATCH_OFF != a_field) && spmpswitch_en) {
            /*
             * If the SPMP entry is not off, spmpswitch bit is set, and the address is in range,
             * do the priv check
             */
            // Shared not set 
            if(!(op->table->spmp[i].cfg_reg & SPMP_SHARED)) {
                /*  
                *   Deny if:
                *   S mode access, with SUM not set, and UMODE set.
                *   U mode access, with UMODE not set.
                */
                if((mode == PRV_S && !op->mstatus && (op->table->spmp[i].cfg_reg & SPMP_UMODE)) ||
                  (mode == PRV_U && !(op->table->spmp[i].cfg_reg & SPMP_UMODE))) {
                    *allowed_privs = 0;
                }
                /*  
                *   EnforceNoX if:
                *   S mode access, with SUM set, and UMODE set.
                * 
                *   Note: The specification has the table in RWX, the oposite of the order in the cfg reg.
                */
                else if (mode == PRV_S && op->mstatus && (op->table->spmp[i].cfg_reg & SPMP_UMODE)){
                    switch (spmp_operation) {
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
                    if(spmp_operation == 2 || spmp_operation == 6)
                        *allowed_privs = 0;
                    else // U mode falls here - Enforce
                        *allowed_privs = spmp_operation & 0x7;
                }
            }
            // Set Shared bit
            else {
                if(mode == PRV_S){
                    // Check for reserved configs
                    if(spmp_operation == 2 || spmp_operation == 6)
                        *allowed_privs = 0;
                    else
                        *allowed_privs = spmp_operation & 0x7;
                }
                else {
                    switch (spmp_operation) {
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
            
            return ((privs & *allowed_privs) == privs);
        }
    }

    return -1; // No entry matched
}


static bool is_entry_locked(spmp_table_t *instance, int index){
    uint8_t next_a_field = SPMP_AMATCH_TOR;

    /*
    *  Verify if it is the last entry. 
    *  If not, check if the next entry is TOR type. 
    *  If it is TOR, check if either this or next entry is locked.
    */
    if (index < instance->num_deleg_rules - 1){
        next_a_field = spmp_get_a_field(instance->spmp[index + 1].cfg_reg);

        if(next_a_field == SPMP_AMATCH_TOR){
            return (instance->locked_rules >> index) & 0x1
                    || (instance->locked_rules >> (index + 1)) & 0x1;
        }
    }

    // Otherwise, just check this entry
    return (instance->locked_rules >> index) & 0x1;
}

static void spmpcfg_csr_write_common(spmp_table_t *instance, uint32_t reg_index,
    target_ulong val, bool priv_access)
{
    bool locked = priv_access ? false : is_entry_locked(instance, reg_index);

    // If within bounds and not locked
    if (reg_index < instance->num_deleg_rules && !locked) {
    
        instance->spmp[reg_index].cfg_reg = val;
        // Storing this allows for faster switching with the sspmpsw extension
        instance->locked_rules |= ((val & SPMP_LOCK) >> 7 & 0x1) << reg_index;

        if((val & SPMP_LOCK) && instance->last_locked_rule < (signed int)reg_index /*can make signed as the spec only goes up to 64*/) {
            instance->last_locked_rule = reg_index;
        }

        spmp_update_rule(instance, reg_index);
        qemu_log_mask(CPU_LOG_SPMP,
                      "%s: new config: " HWADDR_FMT_plx " in entry: %d\n", __func__, val, reg_index);
    } else {
        if (locked){
            qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: ignoring spmpcfg write - locked entry \n", __func__);
        }
        else {
            qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: ignoring spmpcfg write - out of bounds\n", __func__);
        }
    }
}

static void spmpaddr_csr_write_common(spmp_table_t *instance, uint32_t addr_index,
    target_ulong val, bool priv_access)
{
    bool locked = priv_access ? false : is_entry_locked(instance, addr_index);

    // If within bounds and not locked
    if (addr_index < instance->num_deleg_rules && !locked) {

        instance->spmp[addr_index].addr_reg = val;
        spmp_update_rule(instance, addr_index);
    } else {
        if (locked){
            qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: ignoring spmpaddr write - locked entry \n", __func__);
        }
        else {
            qemu_log_mask(LOG_GUEST_ERROR,
                    "%s: ignoring spmpaddr write - out of bounds\n", __func__);
        }
    }
}

static void spmp_unlock_entries_common(spmp_table_t *instance)
{
    // Reset everything
    for (int i = 0; i < MAX_RISCV_SPMPS; i++) {
        instance->spmp[i].cfg_reg &= ~(SPMP_LOCK | SPMP_AMATCH);
    }

    instance->locked_rules = 0;
    instance->num_active_rules = 0;
    instance->last_locked_rule = -1;
}

static void spmpswitch_csr_write_common(spmp_table_t *instance, uint64_t new_val)
{
    uint64_t mask = (instance->num_deleg_rules == MAX_RISCV_SPMPS) ? ~0ULL : ((1ULL << instance->num_deleg_rules) - 1);
    
    // If the rule is locked, the bit cannot be changed
    instance->spmpswitch = (instance->spmpswitch & instance->locked_rules) | (new_val & ~instance->locked_rules);
    instance->spmpswitch &= mask;
}

/*
 * Public Interface
 */

bool vspmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode)
{
    int ret;
    spmp_op_t op = {&(env->vspmp_state), env->vsstatus & MSTATUS_SUM, vspmp_get_spmpswitch(env)};

    /* Short cut for M-mode and HS access*/
    if (mode == PRV_M || (mode == PRV_S && !env->virt_enabled)) {
		*allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
		return true;
	}

    /* Short cut if no rules */
    if (env->vspmp_state.num_active_rules == 0) {
        return spmp_hart_has_privs_default(riscv_cpu_cfg(env)->ext_ssvspmp, allowed_privs, mode);
    }

    ret = spmp_evaluate_entries(&op, addr, size, privs, allowed_privs, mode);

    // No entry matched
    if(ret == -1)
        return spmp_hart_has_privs_default(riscv_cpu_cfg(env)->ext_ssvspmp, allowed_privs, mode);

    return ret;
}

bool spmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode)
{
    int ret;
    spmp_op_t op = {&(env->spmp_state), (env->mstatus & MSTATUS_SUM), spmp_get_spmpswitch(env)};

    /* Short cut for M-mode access*/
    if (mode == PRV_M) {
		*allowed_privs = SPMP_READ | SPMP_WRITE | SPMP_EXEC;
		return true;
	}

    /* Short cut if no rules */
    if (env->spmp_state.num_active_rules == 0) {
        return spmp_hart_has_privs_default(riscv_cpu_cfg(env)->spmp, allowed_privs, mode);
    }

    ret = spmp_evaluate_entries(&op, addr, size, privs, allowed_privs, mode);

    // No entry matched
    if(ret == -1)
        return spmp_hart_has_privs_default(riscv_cpu_cfg(env)->spmp, allowed_privs, mode);

    return ret;
}

/*
 * Accessor to set the cfg reg for a specific SPMP/HART
 * Bounds checks.
 */
void spmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val, bool priv_access)
{
    spmpcfg_csr_write_common(&env->spmp_state, reg_index, val, priv_access);
}

void vspmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val, bool priv_access)
{
    spmpcfg_csr_write_common(&env->vspmp_state, reg_index, val, priv_access);
}


/*
 * Handle a read from a spmpcfg CSR
 */
target_ulong spmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index)
{
    if (reg_index < env->spmp_state.num_deleg_rules) {
        return env->spmp_state.spmp[reg_index].cfg_reg;
    }

    return 0;
}

target_ulong vspmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index)
{
    if (reg_index < env->vspmp_state.num_deleg_rules) {
        return env->vspmp_state.spmp[reg_index].cfg_reg;
    }

    return 0;
}

/*
 * Handle a write to a spmpaddr CSR
 */
void spmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val, bool priv_access)
{
    spmpaddr_csr_write_common(&env->spmp_state, addr_index, val, priv_access);
}

void vspmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val, bool priv_access)
{
    spmpaddr_csr_write_common(&env->vspmp_state, addr_index, val, priv_access);
}

/*
 * Handle a read from a spmpaddr CSR
 */
target_ulong spmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index)
{
    target_ulong val = 0;

    if (addr_index < env->spmp_state.num_deleg_rules) {
        val = env->spmp_state.spmp[addr_index].addr_reg;
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: ignoring spmpaddr read - out of bounds\n", __func__);
    }

    return val;
}

target_ulong vspmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index)
{
    target_ulong val = 0;

    if (addr_index < env->vspmp_state.num_deleg_rules) {
        val = env->vspmp_state.spmp[addr_index].addr_reg;
    } else {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: ignoring spmpaddr read - out of bounds\n", __func__);
    }

    return val;
}

/*
 * Handle a write to the sspmpswitch CSR
 */
void sspmpswitch_csr_write(CPURISCVState *env, uint64_t new_val)
{
    spmpswitch_csr_write_common(&env->spmp_state, new_val);
}

void vspmpswitch_csr_write(CPURISCVState *env, uint64_t new_val)
{
    spmpswitch_csr_write_common(&env->vspmp_state, new_val);
}

/*
 * Handle a write to the hspmpswitch CSR
 */
void hspmpswitch_csr_write(CPURISCVState *env, uint64_t new_val)
{
    uint64_t mask = (env->spmp_state.num_deleg_rules == MAX_RISCV_SPMPS) ? ~0ULL : ((1ULL << env->spmp_state.num_deleg_rules) - 1);

    // If the rule is locked, the bit cannot be changed
    env->hspmpswitch = (env->hspmpswitch & env->spmp_state.locked_rules) | (new_val & ~env->spmp_state.locked_rules);
    env->hspmpswitch &= mask;
}

/*
 * Convert SPMP privilege to TLB page privilege.
 */
int spmp_priv_to_page_prot(spmp_priv_t spmp_priv)
{
    int prot = 0;

    if (spmp_priv & SPMP_READ) {
        prot |= PAGE_READ;
    }
    if (spmp_priv & SPMP_WRITE) {
        prot |= PAGE_WRITE;
    }
    if (spmp_priv & SPMP_EXEC) {
        prot |= PAGE_EXEC;
    }

    return prot;
}

void spmp_unlock_entries(CPURISCVState *env)
{
    spmp_unlock_entries_common(&env->spmp_state);
}

void vspmp_unlock_entries(CPURISCVState *env)
{
    spmp_unlock_entries_common(&env->vspmp_state);
}