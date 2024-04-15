class Buffer {
    final byte[] tmp = new byte[4];
    byte[] buffer;
    int i_put;
    int i_get;
    public Buffer(int size) {
        buffer = new byte[size];
        i_put = 0;
        i_get = 0;
    }
    public Buffer(byte[] buffer) {
        this.buffer = buffer;
        i_put = 0;
        i_get = 0;
    }
    public Buffer() {
        this(1024 * 10 * 2);
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
    public void putString(byte[] foo, int begin, int length) {
        putInt(length);
        putByte(foo, begin, length);
    }
    public void putInt(int val) {
        tmp[0] = (byte)(val >>> 24);
        tmp[1] = (byte)(val >>> 16);
        tmp[2] = (byte)(val >>> 8);
        tmp[3] = (byte)(val);
        System.arraycopy(tmp, 0, buffer, i_put, 4);
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
    public int getByte() {
        return (int)buffer[i_get++];
    }
    void getByte(byte[] foo, int start, int len) {
        System.arraycopy(buffer, i_get, foo, start, len);
        i_get += len;
    }
    public int getByte2(int len) { // ?
        int foo = i_get;
        i_get += len;
        return foo;
    }
    public byte[] getMPInt() {
        int i = getInt();
        if (i < 0 || i > 8 * 1024)
            i = 8 * 1024;
        byte[] foo = new byte[i];
        getByte(foo, 0, i);
        return foo;
    }
    public byte[] getMPIntBits() {
        int bits = getInt();
        int bytes = (bits + 7) / 8;
        byte[] foo = new byte[bytes];
        getByte(foo, 0, bytes);
        if ((foo[0] & 0x80) != 0) {
            byte[] bar = new byte[foo.length + 1];
            bar[0] = 0;
            System.arraycopy(foo, 0, bar, 1, foo.length);
            foo = bar;
        }
        return foo;
    }
    public byte[] getString() {
        int i = getInt();
        byte[] foo = new byte[i];
        getByte(foo, 0, i);
        return foo;
    }
    public void reset() {
        i_put = 0;
        i_get = 0;
    }
    public void shift() {
        if (i_get == 0) return;
        System.arraycopy(buffer, i_get, buffer, 0, i_put - i_get);
        i_put = i_put - i_get;
        i_get = 0;
    }
    void rewind() {
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

