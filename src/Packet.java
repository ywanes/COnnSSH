class Packet{    
    public Buffer buf;    

    public Packet(Buffer buf) {
        this.buf = buf;
    }
    public Packet() {
        this(new Buffer());
    }
}

