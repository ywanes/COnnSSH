import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class Channel extends UtilC{
    //private static Channel channel = null;
    private InputStream in = System.in;
    private OutputStream out = System.out;
    private long rwsize = 0;
    private boolean close = false;
    private boolean eof_remote = false;
    private int recipient = -1;
    private int rmpsize = 0;
    private boolean connected = false;
    private Session session;

    public static int count_line_return=-1;
    public static boolean can_print(int len){
        if ( count_line_return == -1 )
            return true;
        count_line_return++;        
        if ( count_line_return == 1 )
            return false;
        if ( count_line_return == 2 && len == 1 )
            return false;  
        return true;
    }    
    
    Channel(Session session) {
        try {
            this.session = session;
            this.session.channel = this;
            connect();
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }    
    public void set_recipient(int recipient){
        this.recipient=recipient;
    }
    public void connect() throws Exception, Exception {
        if (!session.isConnected())
            throw new Exception("session is down");        
        Packet packet = new Packet(new Buffer(new byte[100]));
        packet.reset();
        packet.buf.putByte((byte) 90);
        packet.buf.putString(str2byte("session", "UTF-8"));
        packet.buf.putInt(0);
        packet.buf.putInt(0x100000);
        packet.buf.putInt(0x4000);
        session.pre_write(packet);
        
        // wait flag recipient           
        for ( int i=0;i<3000;i++ ){
            if ( recipient < 0 ){
                sleep(10);
                continue;
            }
            break;
        }
        
        if (!session.isConnected())
            throw new Exception("session is down");
        if (recipient == -1)
            throw new Exception("channel is not opened.");
        byte[] terminal_mode = (byte[]) str2byte("", "UTF-8");
        int tcol = 80;
        int trow = 24;
        int twp = 640;
        int thp = 480;
                
        packet = new Packet();
        packet.reset();
        packet.buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        packet.buf.putInt(recipient);
        packet.buf.putString(str2byte("pty-req", "UTF-8"));
        packet.buf.putByte((byte) 0);
        packet.buf.putString(str2byte("vt100", "UTF-8"));
        packet.buf.putInt(tcol);
        packet.buf.putInt(trow);
        packet.buf.putInt(twp);
        packet.buf.putInt(thp);
        packet.buf.putString(terminal_mode);
        session.pre_write(packet);
        
        packet = new Packet();
        packet.reset();
        packet.buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        packet.buf.putInt(recipient);
        packet.buf.putString(str2byte("shell", "UTF-8"));        
        packet.buf.putByte((byte) 0);
        session.pre_write(packet);
        connected = true;
        
        ///////////
        // ponto critico!!
        packet = new Packet(new Buffer(new byte[rmpsize]));
        try {
            while (isConnected()) {
                int i = in.read(packet.buf.buffer, 14, packet.buf.buffer.length -14 -ECDH.nn);
                //System.out.write("[IN]".getBytes());
                //System.out.write(buf.buffer, 0, i);
                //System.out.write("[OUT]".getBytes());                
                count_line_return=0;
                if (i == 0)
                    continue;
                if (i == -1)
                    break;
                if (close){
                    break;
                }
                packet.reset();
                packet.buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                packet.buf.putInt(recipient);
                packet.buf.putInt(i);
                packet.buf.skip_put(i);                
                session.write(packet, i);
            }
        } catch (Exception e) {
            System.out.println("ex_20");
        }
    }
    public void set_eof_remote(boolean a) {
        eof_remote = a;
    }
    public void set_close(boolean a) {
        close = a;
    }
    public boolean get_close() {
        return close;
    }
    public void set_rwsize(long a) {
        rwsize = a;
    }
    public void add_rwsize(long a) {
        rwsize += a;
    }
    public long get_rwsize() {
        return rwsize;
    }
    public void rwsize_substract(long a) {
        rwsize -= a;
    }
    public void set_rmpsize(int a) {
        this.rmpsize = a;
    }
    void put(byte[] array, int begin, int length) throws IOException {
        out.write(array, begin, length);
        out.flush();
    }
    public boolean isConnected() {
        return session != null && session.isConnected() && connected;
    }
}

