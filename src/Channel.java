class Channel extends UtilC{
    private java.io.InputStream in2 = System.in;
    private java.io.OutputStream out2 = System.out;
    private long rwsize2 = 0;
    public boolean channel_opened2=false;
    private int rmpsize2 = 0;
    private Session session2;

    public static int count_line_return2=-1;
    public static boolean can_print2(int len){
        if ( count_line_return2 == -1 )
            return true;
        count_line_return2++;        
        if ( count_line_return2 == 1 )
            return false;
        if ( count_line_return2 == 2 && len == 1 )
            return false;  
        return true;
    }    
    
    Channel(Session _session) {
        try {
            session2 = _session;
            session2.channel = this;
            connect2();
            working2();
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }    
    public void connect2() throws Exception {
        Packet packet = new Packet(new Buffer(new byte[100]));
        packet.reset();
        packet.buf.putByte((byte) 90);
        packet.buf.putValue(str2byte("session", "UTF-8"));
        packet.buf.putInt(0);
        packet.buf.putInt(0x100000);
        packet.buf.putInt(0x4000);
        session2.pre_write(packet);
        
        for ( int i=0;i<3000;i++ ){
            if ( !channel_opened2 ){
                sleep(10);
                continue;
            }
            break;
        }
        
        if ( !channel_opened2 )
            throw new Exception("channel is not opened.");
        byte[] terminal_mode = (byte[]) str2byte("", "UTF-8");
        int tcol = 80;
        int trow = 24;
        int twp = 640;
        int thp = 480;
                
        packet = new Packet();
        packet.reset();
        packet.buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        packet.buf.putInt(0);
        packet.buf.putValue(str2byte("pty-req", "UTF-8"));
        packet.buf.putByte((byte) 0);
        packet.buf.putValue(str2byte("vt100", "UTF-8"));
        packet.buf.putInt(tcol);
        packet.buf.putInt(trow);
        packet.buf.putInt(twp);
        packet.buf.putInt(thp);
        packet.buf.putValue(terminal_mode);
        session2.pre_write(packet);
        
        packet = new Packet();
        packet.reset();
        packet.buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        packet.buf.putInt(0);
        packet.buf.putValue(str2byte("shell", "UTF-8"));        
        packet.buf.putByte((byte) 0);
        session2.pre_write(packet);
    }
    public void working2(){
        ///////////
        // ponto critico!!
        Packet packet = new Packet(new Buffer(new byte[rmpsize2]));
        try {
            while (true){
                int i = in2.read(packet.buf.buffer, 14, packet.buf.buffer.length -14 -ECDH.nn);
                //System.out.write("[IN]".getBytes());
                //System.out.write(buf.buffer, 0, i);
                //System.out.write("[OUT]".getBytes());                
                count_line_return2=0;
                if (i == 0)
                    continue;
                if (i == -1)
                    break;
                packet.reset();
                packet.buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                packet.buf.putInt(0);
                packet.buf.putInt(i);
                packet.buf.skip_put(i);                
                session2.write(packet, i);
            }
        } catch (Exception e) {
            System.out.println("ex_20");
        }        
    }
    public void set_rwsize2(long a) {
        rwsize2 = a;
    }
    public void add_rwsize2(long a) {
        rwsize2 += a;
    }
    public long get_rwsize2() {
        return rwsize2;
    }
    public void rwsize_substract2(long a) {
        rwsize2 -= a;
    }
    public void set_rmpsize2(int a) {
        this.rmpsize2 = a;
    }
    void put2(byte[] array, int begin, int length) throws Exception {
        out2.write(array, begin, length);
        out2.flush();
    }
}

