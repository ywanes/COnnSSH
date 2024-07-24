class Packet{
    public static java.security.SecureRandom random = new java.security.SecureRandom();
    public Buffer buf;    

    public Packet(Buffer buf) {
        this.buf = buf;
    }
    public Packet() {
        this(new Buffer());
    }
    public void reset() {        
        buf.set_put(5);
    }
    void padding(int bsize) {
        int len = buf.get_put();
        int pad = (-len) & (bsize - 1);
        if (pad < bsize)
            pad += bsize;
        len = len + pad - 4;
        byte[] ba4 = new byte[4];
        ba4[0] = (byte)(len >>> 24);
        ba4[1] = (byte)(len >>> 16);
        ba4[2] = (byte)(len >>> 8);
        ba4[3] = (byte)(len);
        System.arraycopy(ba4, 0, buf.buffer, 0, 4);
        buf.buffer[4] = (byte) pad;
        int start_fill = buf.get_put();
        byte[] tmp_fill = new byte[16];
        if (pad > tmp_fill.length)
            tmp_fill = new byte[pad];
        random.nextBytes(tmp_fill);
        System.arraycopy(tmp_fill, 0, buf.buffer, start_fill, pad);
        buf.skip_put(pad);
    }
}

