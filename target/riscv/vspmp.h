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

#ifndef RISCV_VSPMP_H
#define RISCV_VSPMP_H


void vspmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val, bool s_mode_access);
target_ulong vspmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index);

target_ulong vspmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index);
void vspmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val, bool s_mode_access);

bool vspmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, spmp_priv_t privs, spmp_priv_t *allowed_privs,
    target_ulong mode);

void vspmp_unlock_entries(CPURISCVState *env);

#endif
