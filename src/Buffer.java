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
    public void putByte(byte foo) {
        buffer[i_put++] = foo;
    }
    public void putBytes(byte[] foo, int begin, int len) {
        System.arraycopy(foo, begin, buffer, i_put, len);
        i_put += len;
    }
    public void putString(byte[] foo) {
        putInt(foo.length);
        putBytes(foo, 0, foo.length);
    }
    public void putInt(int val) {
        final byte[] foo = new byte[4];
        foo[0] = (byte)(val >>> 24);
        foo[1] = (byte)(val >>> 16);
        foo[2] = (byte)(val >>> 8);
        foo[3] = (byte)(val);
        System.arraycopy(foo, 0, buffer, i_put, 4);
        i_put += 4;
    }
    void skip_put(int n) {
        i_put += n;
    }   
    public void putMPInt(byte[] foo) {
        if ((foo[0] & 0x80) == 0) {
            putInt(foo.length);
        } else {
            putInt(foo.length + 2);
            putByte((byte) 0);
        }
        putBytes(foo, 0, foo.length);
    }
    public int getLength(){
        return i_put - i_get;
    }
    public int get_get() {
        return i_get;
    }
    public void set_get(int s) {
        i_get = s;
    }
    public int get_put() {
        return i_put;
    }
    public void set_put(int s) {
        i_put = s;
    }
    public void add_put(int s){
        i_put += s;
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
    public byte[] getBytes() {
        int len = getInt();
        byte[] foo = new byte[len];
        System.arraycopy(buffer, i_get, foo, 0, len);
        i_get += len;
        return foo;        
    }
    public byte[] getBytesAll(){
        int len = getLength(); // getLength
        byte[] foo = new byte[len];
        System.arraycopy(buffer, i_get, foo, 0, len);
        i_get += len;
        return foo;        
    }
    public void reset() {
        i_put = 0;
        i_get = 0;
    }
    void reset_get() {
        i_get = 0;
    }
    byte getCommand() {
        return buffer[5];
    }
    void resize_buffer(int n) {
        int i = i_put + n + ECDH.nn;
        if ( buffer.length <  i){
            byte[] foo = new byte[i];
            System.arraycopy(buffer, 0, foo, 0, i_put);
            buffer = foo;
        }
    }
}

