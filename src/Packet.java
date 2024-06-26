class Packet{
    private static java.security.SecureRandom random = null;
    static void setRandom(java.security.SecureRandom foo) {
        random = foo;
    }
    Buffer buffer;
    byte[] ba4 = new byte[4];

    public Packet(Buffer buffer) {
        this.buffer = buffer;
    }
    public void reset() {
        buffer.i_put = 5;
    }
    void padding(int bsize) {
        int len = buffer.i_put;
        int pad = (-len) & (bsize - 1);
        if (pad < bsize)
            pad += bsize;
        len = len + pad - 4;
        ba4[0] = (byte)(len >>> 24);
        ba4[1] = (byte)(len >>> 16);
        ba4[2] = (byte)(len >>> 8);
        ba4[3] = (byte)(len);
        System.arraycopy(ba4, 0, buffer.buffer, 0, 4);
        buffer.buffer[4] = (byte) pad;
        synchronized(random) {
            byte[] foo_fill = buffer.buffer;
            int start_fill = buffer.i_put;
            byte[] tmp_fill = new byte[16];
            if (pad > tmp_fill.length)
                tmp_fill = new byte[pad];
            random.nextBytes(tmp_fill);
            System.arraycopy(tmp_fill, 0, foo_fill, start_fill, pad);
        }
        buffer.skip_put(pad);
    }

    int shift(int len, int bsize, int mac) {
        int s = len + 5 + 9;
        int pad = (-s) & (bsize - 1);
        if (pad < bsize) pad += bsize;
        s += pad;
        s += mac;
        s += 32;
        if (buffer.buffer.length < s + buffer.i_put - 5 - 9 - len) {
            byte[] foo = new byte[s + buffer.i_put - 5 - 9 - len];
            System.arraycopy(buffer.buffer, 0, foo, 0, buffer.buffer.length);
            buffer.buffer = foo;
        }
        System.arraycopy(buffer.buffer, len + 5 + 9, buffer.buffer, s, buffer.i_put - 5 - 9 - len);
        buffer.i_put = 10;
        buffer.putInt(len);
        buffer.i_put = len + 5 + 9;
        return s;
    }
    void unshift(byte command, int recipient, int s, int len) {
        System.arraycopy(buffer.buffer, s, buffer.buffer, 5 + 9, len);
        buffer.buffer[5] = command;
        buffer.i_put = 6;
        buffer.putInt(recipient);
        buffer.putInt(len);
        buffer.i_put = len + 5 + 9;
    }
}

