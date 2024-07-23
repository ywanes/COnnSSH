class Buffer {    
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
    public void putByte(byte foo) {
        buffer[i_put++] = foo;
    }
    public void putBytes(byte[] a) {
        for ( int i=0;i<a.length;i++ )
            buffer[i_put++] = a[i];
    }
    public void putValue(byte[] foo) {
        putInt(foo.length);
        putBytes(foo);
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
    void reset_get(){
        i_get = 0;
    }
    byte getCommand(){
        return buffer[5];
    }
}

