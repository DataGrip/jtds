// jTDS JDBC Driver for Microsoft SQL Server
// Copyright (C) 2004 The jTDS Project
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
package net.sourceforge.jtds.jdbc;

import java.io.*;
import java.sql.*;

import net.sourceforge.jtds.util.Logger;
import net.sourceforge.jtds.util.ReaderInputStream;
import net.sourceforge.jtds.util.WriterOutputStream;

/**
 * An in-memory, disk or database representation of character data.
 * <p>
 * Implementation note:
 * <ol>
 * <li> Mostly Brian's original code but modified to include the
 *      ability to convert a stream into a String when required.
 * <li> SQLException messages loaded from properties file.
 * </ol>
 *
 * @author Brian Heineman
 * @author Mike Hutchinson
 * @version $Id: ClobImpl.java,v 1.15 2004-07-22 17:09:57 bheineman Exp $
 */
public class ClobImpl implements Clob {
	private static final String EMPTY_CLOB = "";
	
    private final ConnectionJDBC2 _connection;
    private String _clob;
    private File _clobFile;
    private JtdsReader _jtdsReader;

    /**
     * Constructs a new Clob instance.
     * 
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     */
    ClobImpl(Object callerReference) {
        this(callerReference, EMPTY_CLOB);
    }
    
    /**
     * Constructs a new Clob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @param clob The clob object to encapsulate
     */
    ClobImpl(Object callerReference, String clob) {
        if (clob == null) {
            throw new IllegalArgumentException("clob cannot be null.");
        }

        _clob = (String) clob;
        _connection = getConnection(callerReference);
    }

    /**
     * Constructs a new Clob instance.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @param clob The clob object to encapsulate
     */
    ClobImpl(Object callerReference, ResponseStream in, boolean ntext, boolean readTextMode) throws IOException {
        if (in == null) {
            throw new IllegalArgumentException("in cannot be null.");
        }
        
        _connection = getConnection(callerReference);
        
        TextPtr tp = new TextPtr();
        
        in.read(tp.ptr);
        in.read(tp.ts);
        tp.len = in.readInt();

        readTextMode = false;
        
        if (readTextMode) {
	        if (ntext) {
                char[] buf = new char[tp.len / 2];

                in.read(buf);
                tp.value = buf;
                
                // FIXME - Create a JtdsReader instead
	        	_clob = new String((char[]) tp.value);
	        } else {
                byte[] bytes = new byte[tp.len];
                
                in.read(bytes);
                tp.value = bytes;
                
                // FIXME - Create a JtdsReader instead
	        	_clob = new String((byte[]) tp.value);
	        }
        } else {
            try {
                if (tp.len < _connection.getLobBuffer()) {
                	if (ntext) {
                		_clob = in.readString(tp.len / 2);
                	} else {
                		_clob = in.readAsciiString(tp.len);
                	}
                } else {
                	_clob = EMPTY_CLOB;
            	
	            	Writer writer = setCharacterStream(1);
	            	long length = tp.len;

    	        	while (length > 0) {
    	        		int results = (int) Math.min(1024, length);
    	        		String data; 
    	        		
		    	        if (ntext) {
	    	        		data = in.readString(results / 2); 
		    	        } else {
			                data = in.readAsciiString(results);
		    	        }
    	        		
		    	        length -= results;
    	        		writer.write(data);
    	        	}
    	        	
    	        	writer.close();
            	}
                
                if (in.getTdsVersion() < TdsCore.TDS70
                        && length() == 1
                        && getSubString(1, 1).equals(" ")) {
                        // In TDS 4/5 zero length strings are stored as a single space
                        // to distinguish them from nulls.
                        truncate(0);
                }                
            } catch (SQLException e) {
                // Should never happen...
            }
        }
        
        if (ntext && (tp.len & 0x01) != 0) {
            // If text size is set to an odd number e.g. 1
            // Then only part of a char is available.
            in.read(); // Discard!
        }
        
/*
        if (statement != null && statement.getMaxFieldSize() == 1) {
            // Try to build a CLOB built over a Reader stream.
            ColData data = getColumn(columnIndex);
            ColInfo ci = columns[columnIndex - 1];

            if (data.getTextPtr() != null && ci.jdbcType == java.sql.Types.LONGVARCHAR) {
                return new ClobImpl(new JtdsReader((ConnectionJDBC2) statement.getConnection(),
                                      ci,
                                      data,
                                      ((ConnectionJDBC2) statement.getConnection()).
                                            getCharSet()));
            }
        }
*/        
    }
    
    /**
     * Returns a new ascii stream for the CLOB data.
     */
    public InputStream getAsciiStream() throws SQLException {
        return new ReaderInputStream(getCharacterStream(), "ASCII");
    }

    /**
     * Returns a new reader for the CLOB data.
     */
    public synchronized Reader getCharacterStream() throws SQLException {
        try {
            if (_clob != null) {
                return new StringReader(_clob);
            } else if (_clobFile != null) {
                return new BufferedReader(new FileReader(_clobFile));
            }
            
            _jtdsReader.reset();
            
            return _jtdsReader;
        } catch (IOException e) {
            throw new SQLException(Support.getMessage("error.generic.ioerror", e.getMessage()),
                                   "HY000");
        }
    }
    
    public String getSubString(long pos, int length) throws SQLException {
        if (pos < 1) {
            throw new SQLException(Support.getMessage("error.blobclob.badpos"), "HY090");
        } else if (length < 0) {
            throw new SQLException(Support.getMessage("error.blobclob.badlen"), "HY090");
        } else if (pos - 1 + length > length()) {
            throw new SQLException(Support.getMessage("error.blobclob.lentoolong"), "HY090");
        }

        Reader reader = getCharacterStream();

        skip(reader, pos - 1);
        
        try {
            char[] buffer = new char[length];
            
            if (reader.read(buffer) != length) {
                throw new SQLException(Support.getMessage("error.blobclob.readlen"), "HY000");
            }
            
            return new String(buffer);
        } catch (IOException ioe) {
            throw new SQLException(
                 Support.getMessage("error.generic.ioread", "String", ioe.getMessage()),
                                    "HY000");
        }
    }

    /**
     * Returns the length of the value.
     */
    public synchronized long length() throws SQLException {
    	if (_clob != null) {
            return _clob.length();
    	} else if (_clobFile != null) {
    		return _clobFile.length();
        }

        return _jtdsReader.getLength();
    }

    public long position(String searchStr, long start) throws SQLException {
        return position(new ClobImpl(_connection, searchStr), start);
    }
    
    public long position(Clob searchStr, long start) throws SQLException {
        if (searchStr == null) {
            throw new SQLException(Support.getMessage("error.clob.searchnull"), "HY024");
        }

        try {
            Reader reader = getCharacterStream();
            long length = length() - searchStr.length();
            boolean reset = true;
            
            for (long i = start; i < length; i++) {
                boolean found = true;
                int value;
                
                if (reset) {
                    reader = getCharacterStream();
                    skip(reader, i);
                    reset = false;
                }
            
                value = reader.read();
                
                Reader searchReader = searchStr.getCharacterStream();
                int searchValue;
                
                while ((searchValue = searchReader.read()) != -1) {
                    if (value != searchValue) {
                        found = false;
                        break;
                    }
                    
                    reset = true;
                }

                if (found) {
                    return i;
                }
            }
        } catch (IOException e) {
            throw new SQLException(
                Support.getMessage("error.generic.ioread", "String", e.getMessage()),
                                   "HY000");
        }

        return -1;
    }

    public OutputStream setAsciiStream(final long pos) throws SQLException {
        return new WriterOutputStream(setCharacterStream(pos), "ASCII");
    }

    public synchronized Writer setCharacterStream(final long pos) throws SQLException {
        final long length = length();
        
        if (pos < 1) {
            throw new SQLException(Support.getMessage("error.blobclob.badpos"), "HY024");
        } else if (pos > length && pos != 1) {
            throw new SQLException(Support.getMessage("error.blobclob.badposlen"), "HY024");
        }

        return new Writer() {
            Writer writer;
            long curPos = pos - 1;
            boolean securityFailure = false;

            {
                try {
                    if (length > _connection.getLobBuffer()) {
                        if (_clobFile == null) {
                            writeToDisk(getCharacterStream());
                        }
                    } else if (_jtdsReader != null) {
                        StringWriter sw  = new StringWriter((int) length);

                        char[] buffer = new char[1024];
                        int result = -1;

                        while ((_jtdsReader.read(buffer)) != -1) {
                            sw.write(buffer, 0, result);
                        }

                        _clob = sw.toString();
                        _jtdsReader = null;
                    }

                    updateWriter();
                } catch (IOException e) {
                    throw new SQLException(Support.getMessage("error.generic.ioerror", e.getMessage()),
                                           "HY000");
                }
            }

            public void write(int c) throws IOException {
                synchronized (ClobImpl.this) {
                    checkSize(1);
                    writer.write(c);
                    curPos++;
                }
            }

            public void write(char[] cbuf, int off, int len) throws IOException {
                synchronized (ClobImpl.this) {
                    checkSize(len);
                    writer.write(cbuf, off, len);
                    curPos += len;
                }
            }

            /**
             * Checks the size of the in-memory buffer; if a write will
             * cause the size to exceed <code>MAXIMUM_SIZE</code> than
             * the data will be removed from memory and written to disk.
             *
             * @param length the length of data to be written
             */
            private void checkSize(long length) throws IOException {
                // Return if the data has already exceeded the maximum size
                if (curPos > _connection.getLobBuffer()) {
                    return;
                }

                // Return if a file is already being used to store the data
                if (_clobFile != null) {
                    return;
                }

                // Return if there was a security failure attempting to
                // create a buffer file
                if (securityFailure) {
                    return;
                }

                // Return if the length will not exceed the maximum in-memory
                // value
                if (curPos + length <= _connection.getLobBuffer()) {
                    return;
                }

                if (_clob != null) {
                    writeToDisk(new StringReader(_clob));
                    updateWriter();
                }
            }

            void writeToDisk(Reader reader) throws IOException {
                Writer wtr = null;

                try {
                    _clobFile = File.createTempFile("jtds", ".tmp");
                    _clobFile.deleteOnExit();

                    wtr = new BufferedWriter(new FileWriter(_clobFile));
                } catch (SecurityException e) {
                    // Unable to write to disk
                    securityFailure = true;

                    wtr = new StringWriter();

                    if (Logger.isActive()) {
                        Logger.println("Clob: Unable to buffer data to disk: " + e.getMessage());
                    }
                }

                try {
                    char[] buffer = new char[1024];
                    int result = -1;

                    while ((result = reader.read(buffer)) != -1) {
                        wtr.write(buffer, 0, result);
                    }
                } finally {
                    wtr.flush();

                    if (wtr instanceof StringWriter) {
                    	if (_clobFile != null) {
                    		_clobFile.delete();
                    		_clobFile = null;
                    	}
                    	
                        _clob = ((StringWriter) wtr).toString();
                    } else {
                        _clob = null;
                    }

                    wtr.close();
                }
            }

            /**
             * Updates the <code>outputStream</code> member by creating the
             * approperiate type of output stream based upon the current
             * storage mechanism.
             *
             * @throws IOException if any failure occure while creating the
             *         output stream
             */
            void updateWriter() throws IOException {
                if (_clob != null) {
                    final long startPos = curPos;

                    writer = new Writer() {
                        int curPos = (int) startPos;
                        boolean closed = false;
                        char[] singleChar = new char[1];

                        public void write(int c) throws IOException {
                            singleChar[0] = (char) c;
                            write(singleChar, 0, 1);
                        }

                        public void write(char[] cbuf, int off, int len) throws IOException {
                            if (closed) {
                                throw new IOException("stream closed");
                            } else if (cbuf == null) {
                                throw new NullPointerException();
                            } else if (off < 0
                                       || len < 0
                                       || off > cbuf.length
                                       || off + len > cbuf.length) {
                                throw new ArrayIndexOutOfBoundsException();
                            } else if (len == 0) {
                                return;
                            }
                            
                            // FIXME - Optimize writes; reduce memory allocation
                            // by creating fewer objects.
                            if (curPos + 1 > _clob.length()) {
                                _clob += new String(cbuf, off, len);
                            } else {
                                String tmpClob = _clob;
                                
                                _clob = tmpClob.substring(0, curPos) + new String(cbuf, off, len);
                                
                                if (_clob.length() < tmpClob.length()) {
                                    _clob += tmpClob.substring(curPos + len);
                                }
                            }
                            
                            curPos += len;
                        }
                        
                        public void flush() throws IOException {
                        }
                        
                        public void close() throws IOException {
                            closed = true;
                        }
                    };
                } else {
                    writer = new Writer() {
                        RandomAccessFile raf = new RandomAccessFile(_clobFile, "rw");
                        char[] singleChar = new char[1];

                        {
                            raf.seek(curPos);
                        }

                        public void write(int c) throws IOException {
                            singleChar[0] = (char) c;
                            write(singleChar, 0, 1);
                        }

                        public void write(char cbuf[], int off, int len) throws IOException {
                            if (raf == null) {
                                throw new IOException("stream closed");
                            }
                            
                            if (cbuf == null) {
                                throw new NullPointerException();
                            } else if (off < 0
                                       || len < 0
                                       || off > cbuf.length
                                       || off + len > cbuf.length) {
                                throw new ArrayIndexOutOfBoundsException();
                            } else if (len == 0) {
                                return;
                            }
                            
                            byte[] data = new String(cbuf, off, len).getBytes();
                            
                            raf.write(data, 0, data.length);
                        }

                        public void flush() throws IOException {
                        }
                        
                        public void close() throws IOException {
                            raf.close();
                            raf = null;
                        }
                    };
                }
            }

            public void flush() throws IOException {
                writer.flush();
            }

            public void close() throws IOException {
                writer.close();
            }
        };
    }

    public int setString(long pos, String str) throws SQLException {
        if (str == null) {
            throw new SQLException(Support.getMessage("error.clob.strnull"), "HY090");
        }

        return setString(pos, str, 0, str.length());
    }

    public int setString(long pos, String str, int offset, int len)
    throws SQLException {
        Writer writer = setCharacterStream(pos);

        try {
            writer.write(str, offset, len);
            writer.close();
        } catch (IOException e) {
            throw new SQLException(
                Support.getMessage("error.generic.iowrite", "String", e.getMessage()),
                            "HY000");
        }

        return len;
    }

    /**
     * Truncates the value to the length specified.
     *
     * @param len the length to truncate the value to
     */
    public synchronized void truncate(long len) throws SQLException {
        long currentLength = length();
        
        if (len < 0) {
            throw new SQLException(Support.getMessage("error.blobclob.badlen"), "HY090");
        } else if (len > currentLength) {
            throw new SQLException(Support.getMessage("error.blobclob.lentoolong"), "HY090");
        }

        if (len == currentLength) {
            return;
        } else if (len <= _connection.getLobBuffer()) {
        	_clob = getSubString(1, (int) len);
            
            if (_clobFile != null) {
                _clobFile.delete();
                _clobFile = null;
            }
            
        	_jtdsReader = null;
        } else {
	        try {
	        	Reader reader = getCharacterStream();
                File tmpFile = _clobFile;

                _clob = "";
                _clobFile = null;
                _jtdsReader = null;
                
	        	Writer writer = setCharacterStream(1);
                char[] buffer = new char[1024];
                int result = -1;
                
                while ((result = reader.read(buffer, 0, (int) Math.min(buffer.length, len))) > 0) {
                    len -= result;
                    writer.write(buffer, 0, result);
                }
	        	
	        	writer.close();
                
                // If the data came from a file; delete the original file to 
                // free disk space
                if (tmpFile != null) {
                    tmpFile.delete();
                }
	        } catch (IOException e) {
	            throw new SQLException(Support.getMessage("error.generic.iowrite",
	            		                                  "String",
														  e.getMessage()),
	                                   "HY000");
	        }
        }
    }

    private void skip(Reader reader, long skip) throws SQLException {
        try {
            long skipped = reader.skip(skip);

            if (skipped != skip) {
                throw new SQLException(Support.getMessage("error.blobclob.badposlen"), "HY090");
            }
        } catch (IOException e) {
            throw new SQLException(Support.getMessage("error.generic.ioerror", e.getMessage()),
                                   "HY000");
        }
    }

    /**
     * Returns a connection for a given caller reference.
     *
     * @param callerReference an object reference to the caller of this method;
     *        must be a <code>Connection</code>, <code>Statement</code> or
     *        <code>ResultSet</code>
     * @return a connection
     */
    private ConnectionJDBC2 getConnection(Object callerReference) {
        if (callerReference == null) {
            throw new IllegalArgumentException("callerReference cannot be null.");
        }

        Connection connection;
        
        try {
            if (callerReference instanceof Connection) {
                connection = (Connection) callerReference;
            } else if (callerReference instanceof Statement) {
                connection = ((Statement) callerReference).getConnection();
            } else if (callerReference instanceof ResultSet) {
                connection = ((ResultSet) callerReference).getStatement().getConnection();
            } else {
                throw new IllegalArgumentException("callerReference is invalid.");
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e.getMessage());
        }
        
        return (ConnectionJDBC2) connection;
    }
    
    protected void finalize() {
    	if (_clobFile != null) {
    		_clobFile.delete();
    	}
    }
}
