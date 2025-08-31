class Buf{
    byte[] buffer;
    int i_put, i_get;
    public Buf() {
        this(new byte[1024 * 10 * 2]);
    }
    public Buf(byte[] buffer) {
        this.buffer = buffer;
        i_put = i_get = 0;
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
}
