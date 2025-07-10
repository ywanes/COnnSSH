class Buf{
    public java.security.SecureRandom random = new java.security.SecureRandom();
    public byte[] buffer;
    public int i_put;
    public int i_get;
    public Buf() {
        this(new byte[1024 * 10 * 2]);
    }
    public Buf(byte[] buffer) {
        this.buffer = buffer;
        i_put = 0;
        i_get = 0;
    }
    public void putInt(int val) {
        buffer[i_put++] = (byte)(val >> 24);
        buffer[i_put++] = (byte)(val >> 16);
        buffer[i_put++] = (byte)(val >> 8);
        buffer[i_put++] = (byte)val;
    }
    public void putByte(byte a) {
        buffer[i_put++] = a;
    }
    public void putBytes(byte[] a) {
        for ( int i=0;i<a.length;i++ )
            buffer[i_put++] = a[i];
    }
    public void putValue(byte[] a) {
        putInt(a.length);
        putBytes(a);
    }
    public byte getByte() {
        return buffer[i_get++];
    }
    public int getInt(){
        return (getByte() & 0xff) << 24 | (getByte() & 0xff) << 16 | (getByte() & 0xff) << 8 | (getByte() & 0xff); 
    }
    public byte[] getValue() {
        byte[] a = new byte[getInt()];
        System.arraycopy(buffer, i_get, a, 0, a.length);
        i_get+=a.length;
        return a;
    }
    public byte[] getValueAllLen(){
        byte[] a = new byte[i_put - i_get];
        System.arraycopy(buffer, i_get, a, 0, a.length);
        i_get+=a.length;
        return a;
    }
    public void reset_command(int command){
        i_put=5;
        putByte((byte) command);
    }
    public int getCommand(){
        return buffer[5] & 0xff;
    }
    public void padding(int bsize) {
        int len = i_put;
        int pad = (-len) & (bsize - 1);
        if (pad < bsize)
            pad += bsize;
        len = len + pad - 4;
        byte[] ba4 = new byte[4];
        ba4[0] = (byte)(len >> 24);
        ba4[1] = (byte)(len >> 16);
        ba4[2] = (byte)(len >> 8);
        ba4[3] = (byte)(len);
        System.arraycopy(ba4, 0, buffer, 0, 4);
        buffer[4] = (byte) pad;
        byte[] tmp_fill = new byte[16];
        if (pad > tmp_fill.length)
            tmp_fill = new byte[pad];
        random.nextBytes(tmp_fill);
        System.arraycopy(tmp_fill, 0, buffer, i_put, pad);
        i_put+=pad;
    }    
}
