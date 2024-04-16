import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class Channel extends UtilC{
    private static Channel channel = null;
    private InputStream in = System.in;
    private OutputStream out = System.out;
    private OutputStream out_ext = null;
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
            channel = this;
            connect();
            while (!eof_remote) {}
        } catch (Exception e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }    
    static Channel getChannel() {
        return channel;
    }
    public void set_recipient(int recipient){
        this.recipient=recipient;
    }
    public void connect() throws ExceptionC, Exception {
        if (!session.isConnected())
            throw new ExceptionC("session is down");
        Buffer buf = new Buffer(new byte[100]);
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) 90);
        buf.putString(str2byte("session", "UTF-8"));
        buf.putInt(0);
        buf.putInt(0x100000);
        buf.putInt(0x4000);
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
            throw new ExceptionC("session is down");
        if (recipient == -1)
            throw new ExceptionC("channel is not opened.");
        byte[] terminal_mode = (byte[]) str2byte("", "UTF-8");
        int tcol = 80;
        int trow = 24;
        int twp = 640;
        int thp = 480;
        
        buf = new Buffer();
        packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(recipient);
        buf.putString(str2byte("pty-req", "UTF-8"));
        buf.putByte((byte) 0);
        buf.putString(str2byte("vt100", "UTF-8"));
        buf.putInt(tcol);
        buf.putInt(trow);
        buf.putInt(twp);
        buf.putInt(thp);
        buf.putString(terminal_mode);
        session.pre_write(packet);
        
        buf = new Buffer();
        packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(recipient);
        buf.putString(str2byte("shell", "UTF-8"));
        buf.putByte((byte) 0);
        session.pre_write(packet);
        connected = true;
        
        // ponto critico!!
        buf = new Buffer(new byte[rmpsize]);
        packet = new Packet(buf);
        try {
            while (isConnected()) {
                int i = in.read(buf.buffer, 14, buf.buffer.length -14 -ECDH.nn);
                count_line_return=0;
                if (i == 0)
                    continue;
                if (i == -1)
                    break;
                if (close)
                    break;
                packet.reset();
                buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                buf.putInt(recipient);
                buf.putInt(i);
                buf.skip_put(i);                
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
    void put_ext(byte[] array, int begin, int length) throws IOException {
        out_ext.write(array, begin, length);
        out_ext.flush();
    }
    public boolean isConnected() {
        return session != null && session.isConnected() && connected;
    }
}

