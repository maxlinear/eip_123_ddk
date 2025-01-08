/* cs_umdevxs_sim.h
 *
 * Configuration Switches for UMDevXS Kernel driver
 *  for Simulation device only (for testing without hardware).
 */

/*****************************************************************************
* Copyright (c) 2009-2013 INSIDE Secure B.V. All Rights Reserved.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*****************************************************************************/

// logging level (choose one)
//#define LOG_SEVERITY_MAX LOG_SEVERITY_CRIT
#define LOG_SEVERITY_MAX LOG_SEVERITY_WARN
//#define LOG_SEVERITY_MAX LOG_SEVERITY_INFO

// uncomment to enable device logging when an error occurs
//#define UMDEVXS_CHRDEV_LOG_ERRORS
// uncomment to enable Pre- and Post-DMA logging
//#define HWPAL_TRACE_DMARESOURCE_PREPOSTDMA

#define UMDEVXS_LOG_PREFIX "UMDevXS_Sim: "

#define UMDEVXS_MODULENAME "umdevxs"

// uncomment to remove selected functionality
//#define UMDEVXS_REMOVE_DEVICE
//#define UMDEVXS_REMOVE_SMBUF
#define UMDEVXS_REMOVE_PCI
//#define UMDEVXS_REMOVE_SIMULATION
#define UMDEVXS_REMOVE_INTERRUPT
#define UMDEVXS_REMOVE_DEVICE_PCICFG
#define UMDEVXS_REMOVE_DEVICE_OF

// Definition of device resources
// UMDEVXS_DEVICE_ADD      Name               Start  Last
// UMDEVXS_DEVICE_ADD_PCI  Name               Bar    Start       Size
// UMDEVXS_DEVICE_ADD_SIM  Name               Size
#define UMDEVXS_DEVICES \
    UMDEVXS_DEVICE_ADD_SIM("EIP150",          0x10000), \
    UMDEVXS_DEVICE_ADD_SIM("EIP123_HOST0",    0x04000), \
    UMDEVXS_DEVICE_ADD_SIM("EIP123_FPGA",     0x01000)

/* end of file cs_umdevxs_sim.h */
