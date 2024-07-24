class Buffer {    
    public static java.security.SecureRandom random = new java.security.SecureRandom();
    public byte[] buffer;
    private int i_put;
    private int i_get;
    public Buffer() {
        this(new byte[1024 * 10 * 2]);
    }
    public Buffer(byte[] buffer) {
        this.buffer = buffer;
        i_put = 0;
        i_get = 0;
    }
    public void putInt(int val) {
        buffer[i_put++] = (byte)(val >>> 24);
        buffer[i_put++] = (byte)(val >>> 16);
        buffer[i_put++] = (byte)(val >>> 8);
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
    void skip_put(int n) {
        i_put += n;
    }   
    public void set_get(int s) {
        i_get = s;
    }
    public int get_get() {
        return i_get;
    }
    public void set_put(int s) {
        i_put = s;
    }
    public int get_put() {
        return i_put;
    }
    public byte getByte() {
        return buffer[i_get++];
    }
    private int getB() {
        return getByte() & 0xff;
    }
    public int getShort() {
        return getB() << 8 | getB();        
    }
    public int getInt(){
        return getB() << 24 | getB() << 16 | getB() << 8 | getB(); 
    }
    public byte[] getValue() {
        int len = getInt();
        byte[] a = new byte[len];
        for ( int i=0;i<len;i++ )
            a[i] = buffer[i_get++];
        return a;
    }
    public byte[] getValueAllLen(){
        int len = getLength();
        byte[] a = new byte[len];
        for ( int i=0;i<len;i++ )
            a[i] = buffer[i_get++];
        return a;
    }
    public int getLength(){
        return i_put - i_get;
    }    
    public void reset(){
        i_put = 0;
        i_get = 0;
    }
    public void reset_packet(){
        set_put(5);
    }
    void reset_get(){
        i_get = 0;
    }
    byte getCommand(){
        return buffer[5];
    }
    void padding(int bsize) {
        int len = get_put();
        int pad = (-len) & (bsize - 1);
        if (pad < bsize)
            pad += bsize;
        len = len + pad - 4;
        byte[] ba4 = new byte[4];
        ba4[0] = (byte)(len >>> 24);
        ba4[1] = (byte)(len >>> 16);
        ba4[2] = (byte)(len >>> 8);
        ba4[3] = (byte)(len);
        System.arraycopy(ba4, 0, buffer, 0, 4);
        buffer[4] = (byte) pad;
        int start_fill = get_put();
        byte[] tmp_fill = new byte[16];
        if (pad > tmp_fill.length)
            tmp_fill = new byte[pad];
        random.nextBytes(tmp_fill);
        System.arraycopy(tmp_fill, 0, buffer, start_fill, pad);
        skip_put(pad);
    }    
}

