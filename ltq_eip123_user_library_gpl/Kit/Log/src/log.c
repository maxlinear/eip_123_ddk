/* log.c
 *
 * Log implementation for specific environment
 */

/*****************************************************************************
* Copyright (c) 2008-2013 INSIDE Secure B.V. All Rights Reserved.
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

#define LOG_SEVERITY_MAX  LOG_SEVERITY_NO_OUTPUT

#include "log.h"            // the API to implement


/*----------------------------------------------------------------------------
 * Log_HexDump
 *
 * This function logs Hex Dump of a Buffer
 *
 * szPrefix
 *     Prefix to be printed on every row.
 *
 * PrintOffset
 *     Offset value that is printed at the start of every row. Can be used
 *     when the byte printed are located at some offset in another buffer.
 *
 * Buffer_p
 *     Pointer to the start of the array of bytes to hex dump.
 *
 * ByteCount
 *     Number of bytes to include in the hex dump from Buffer_p.
 *
 * Return Value
 *     None.
 */
void
Log_HexDump(
        const char * szPrefix_p,
        const unsigned int PrintOffset,
        const uint8_t * Buffer_p,
        const unsigned int ByteCount)
{
    unsigned int i;
    char Format[] =
                "%s %08d:"
                " %02X %02X %02X %02X %02X %02X %02X %02X"
                " %02X %02X %02X %02X %02X %02X %02X %02X\n";

    for(i = 0; i < ByteCount; i += 16)
    {
        // if we do not have enough data for a full line
        // then modify the line to cut off the printout
        if (i + 16 > ByteCount)
        {
            int j = ByteCount - i;
            j = j * 5;
            Format[8 + j] = '\n';
            Format[9 + j] = 0;
        }

        Log_FormattedMessage(
                Format,
                szPrefix_p,
                PrintOffset + i,
                Buffer_p[i+0],  Buffer_p[i+1],  Buffer_p[i+2],  Buffer_p[i+3],
                Buffer_p[i+4],  Buffer_p[i+5],  Buffer_p[i+6],  Buffer_p[i+7],
                Buffer_p[i+8],  Buffer_p[i+9],  Buffer_p[i+10], Buffer_p[i+11],
                Buffer_p[i+12], Buffer_p[i+13], Buffer_p[i+14], Buffer_p[i+15]);
    } // for
}


/* end of file log.c */
