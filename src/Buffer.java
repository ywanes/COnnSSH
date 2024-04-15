class Buffer {
    final byte[] tmp_putInt = new byte[4];
    byte[] buffer;
    int i_put;
    int i_get;
    public Buffer() {
        this(new byte[1024 * 10 * 2]);
    }
    public Buffer(int size) {
        this(new byte[size]);
    }
    public Buffer(byte[] buffer) {
        this.buffer = buffer;
        i_put = 0;
        i_get = 0;
    }
    public void putByte(byte foo) {
        buffer[i_put++] = foo;
    }
    public void putByte(byte[] foo) {
        putByte(foo, 0, foo.length);
    }
    public void putByte(byte[] foo, int begin, int len) {
        System.arraycopy(foo, begin, buffer, i_put, len);
        i_put += len;
    }
    public void putString(byte[] foo) {
        putString(foo, 0, foo.length);
    }
    public void putString(byte[] foo, int begin, int len) {
        putInt(len);
        putByte(foo, begin, len);
    }
    public void putInt(int val) {
        tmp_putInt[0] = (byte)(val >>> 24);
        tmp_putInt[1] = (byte)(val >>> 16);
        tmp_putInt[2] = (byte)(val >>> 8);
        tmp_putInt[3] = (byte)(val);
        System.arraycopy(tmp_putInt, 0, buffer, i_put, 4);
        i_put += 4;
    }
    void skip_put(int n) {
        i_put += n;
    }   
    public void putMPInt(byte[] foo) {
        int i = foo.length;
        if ((foo[0] & 0x80) != 0) {
            i++;
            putInt(i + 1);
            putByte((byte) 0);
        } else {
            putInt(i);
        }
        putByte(foo);
    }
    public int getLength() {
        return i_put - i_get;
    }
    public int get_get() {
        return i_get;
    }
    public void set_get(int s) {
        this.i_get = s;
    }
    public int getInt(){
        return ((getShort() << 16) & 0xffff0000) | (getShort() & 0xffff);
    }
    int getShort() {
        return ((getByte() << 8) & 0xff00) | (getByte() & 0xff);
    }
    public byte getByte() {
        return buffer[i_get++];
    }
    public byte[] getBytes(int len) {
        byte[] foo = new byte[len];
        System.arraycopy(buffer, i_get, foo, 0, len);
        i_get += len;
        return foo;
    }
    public byte[] getBytes() {
        return getBytes(getInt());
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
    void fixSize(int n) {
        int i = i_put + n + (32 + 64 + 32);
        if ( buffer.length <  i){
            byte[] tmp = new byte[i];
            System.arraycopy(buffer, 0, tmp, 0, i_put);
            buffer = tmp;
        }
    }

}

