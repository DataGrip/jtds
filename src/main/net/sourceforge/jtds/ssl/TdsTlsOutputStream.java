// jTDS JDBC Driver for Microsoft SQL Server and Sybase
// Copyright (C) 2004 The jTDS Project
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

package net.sourceforge.jtds.ssl;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import net.sourceforge.jtds.jdbc.TdsCore;

/**
 * <p> An output stream that mediates between JSSE and the DB server. </p>
 *
 * <p> SQL Server 2000 has the following requirements:
 * <ul>
 *   <li>All handshake records are delivered in TDS packets.</li>
 *   <li>The "Client Key Exchange" (CKE), "Change Cipher Spec" (CCS) and
 *       "Finished" (FIN) messages are to be submitted in both, the same TDS
 *       packet and the same TCP packet.</li>
 *   <li>From then on TLS/SSL records should be transmitted as normal -- the TDS
 *       packet is part of the encrypted application data.</li>
 * </ul> </p>
 *
 * @author
 *    Rob Worsnop, Mike Hutchinson, Holger Rehn
 */
class TdsTlsOutputStream extends FilterOutputStream
{

   /**
    * used for holding back CKE, CCS and FIN records
    */
   final private List<byte[]> _BufferedRecords = new ArrayList<>();

   /**
    * total size of all deferred records in {@link #_BufferedRecords}
    */
   private int                _TotalSize;

   /**
    * <p> Constructs a {@link TdsTlsOutputStream} based on an underlying output
    * stream. </p>
    *
    * @param out
    *    the underlying output stream
    */
   TdsTlsOutputStream( OutputStream out )
   {
      super( out );
   }

   /**
    * <p> Holds back a record for batched transmission. </p>
    *
    * @param record
    *    the TLS record to buffer
    *
    * @param off
    *    offset of the TLS record within the provided byte array
    *
    * @param len
    *    the length of the TLS record to buffer
    */
   private void deferRecord( byte record[], int off, int len )
   {
      byte tmp[] = new byte[len];
      System.arraycopy( record, off, tmp, 0, len );
      _BufferedRecords.add( tmp );
      _TotalSize += len;
   }

   /**
    * <p> Transmits the buffered batch of TSL records. </p>
    */
   private void flushBufferedRecords()
      throws IOException
   {
      byte tmp[] = new byte[_TotalSize];
      int  off   = 0;

      // concatenate all buffered records
      for( byte[] x : _BufferedRecords )
      {
         System.arraycopy( x, 0, tmp, off, x.length );
         off += x.length;
      }

      putTdsPacket( tmp, 0, off );
      _BufferedRecords.clear();
      _TotalSize = 0;
   }

   /**
    * <p> Writes TSL record to the underlying stream. </p>
    *
    * @param b
    *    the TLS record to write
    *
    * @param off
    *    offset of the TLS record within the provided byte array
    *
    * @param len
    *    length of the TLS record
    */
   public void write( byte[] b, int off, int len )
      throws IOException
   {
      if( len < Ssl.TLS_HEADER_SIZE )
      {
         // too short for a TLS packet just write it
         out.write( b, off, len );
         return;
      }

      // extract relevant TLS header fields
      int contentType = b[off] & 0xFF;
      int length = ( ( b[off + 3] & 0xFF ) << 8 ) | ( b[off + 4] & 0xFF );

      // check to see if probably a SSL client hello
      if( contentType < Ssl.TYPE_CHANGECIPHERSPEC || contentType > Ssl.TYPE_APPLICATIONDATA || length != len - Ssl.TLS_HEADER_SIZE )
      {
         // assume SSLv2 client hello
         putTdsPacket( b, off, len );
         return;
      }

      // process TLS record
      switch( contentType )
      {
         case Ssl.TYPE_APPLICATIONDATA:
            // application data, just copy to output
            out.write( b, off, len );
            break;

         case Ssl.TYPE_CHANGECIPHERSPEC:
            // cipher spec change has to be buffered
            deferRecord( b, off, len );
            break;

         case Ssl.TYPE_ALERT:
            // alert record, ignore
            break;

         case Ssl.TYPE_HANDSHAKE:
            // TLS handshake record
            if( len >= (Ssl.TLS_HEADER_SIZE + Ssl.HS_HEADER_SIZE) )
            {
               // long enough for a handshake subheader
               int hsType = b[off + 5];
               int hsLen = ( b[off + 6] & 0xFF ) << 16 | ( b[off + 7] & 0xFF ) << 8 | ( b[off + 8] & 0xFF );

               // client hello has to go in its own TDS packet
               if( hsLen == len - ( Ssl.TLS_HEADER_SIZE + Ssl.HS_HEADER_SIZE ) && hsType == Ssl.TYPE_CLIENTHELLO )
               {
                  putTdsPacket( b, off, len );
                  break;
               }

               // all others have to be deferred and sent as a block
               deferRecord( b, off, len );

               // now see if we have a finish record which will flush the buffered records
               if( hsLen != len - ( Ssl.TLS_HEADER_SIZE + Ssl.HS_HEADER_SIZE ) || hsType != Ssl.TYPE_CLIENTKEYEXCHANGE )
               {
                  // this is probably a finish record
                  flushBufferedRecords();
               }
               break;
            }

         default:
            // short or unknown record, output it anyway
            out.write( b, off, len );
            break;
      }
   }

   /**
    * <p> Write a TDS packet containing the TLS record(s). </p>
    *
    * @param b
    *    the TLS record
    *
    * @param off
    *    offset of the TLS record(s) within the provided byte array
    *
    * @param len
    *    the length of the TLS record(s)
    */
   void putTdsPacket( byte[] b, int off, int len )
      throws IOException
   {
      byte tdsHdr[] = new byte[TdsCore.PKT_HDR_LEN];
      tdsHdr[0] = TdsCore.PRELOGIN_PKT;
      tdsHdr[1] = 0x01;
      tdsHdr[2] = (byte) ( ( len + TdsCore.PKT_HDR_LEN ) >> 8 );
      tdsHdr[3] = (byte) ( len + TdsCore.PKT_HDR_LEN );
      out.write( tdsHdr, 0, tdsHdr.length );
      out.write( b, off, len );
   }

}