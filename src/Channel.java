import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class Channel extends UtilC implements Runnable {
    private static Channel channel = null;
    private InputStream in = System.in;
    private OutputStream out = System.out;
    private OutputStream out_ext = null;
    private int notifyme = 0;
    private long rwsize = 0;
    private boolean close = false;
    private boolean eof_remote = false;
    private int recipient = -1;
    private int rmpsize = 0;
    private boolean connected = false;
    private Session session;

    Channel(Session session) {
        try {
            this.session = session;
            this.channel = this;
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
    synchronized public void set_recipient(int foo) {
        this.recipient = foo;
        if (notifyme > 0)
            notifyAll();
    }
    public void connect() throws ExceptionC, Exception {
        if (!session.isConnected())
            throw new ExceptionC("session is down");
        Buffer buf = new Buffer(100);
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) 90);
        buf.putString(str2byte("session", "UTF-8"));
        buf.putInt(0);
        buf.putInt(0x100000);
        buf.putInt(0x4000);
        session.pre_write(packet);
        int retry = 2000;
        synchronized(this) {
            if (recipient == -1 && session.isConnected() && retry > 0) {
                try {
                    notifyme = 1;
                    wait(30000);
                } finally {
                    notifyme = 0;
                }
                retry--;
            }
        }
        if (!session.isConnected())
            throw new ExceptionC("session is down");
        if (recipient == -1)
            throw new ExceptionC("channel is not opened.");
        byte[] terminal_mode = (byte[]) str2byte("", "UTF-8");
        String ttype = "vt100";
        int tcol = 80;
        int trow = 24;
        int twp = 640;
        int thp = 480;
        Buffer buf2 = new Buffer();
        Packet packet2 = new Packet(buf2);
        packet2.reset();
        buf2.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        buf2.putInt(recipient);
        buf2.putString(str2byte("pty-req", "UTF-8"));
        buf2.putByte((byte) 0);
        buf2.putString(str2byte(ttype, "UTF-8"));
        buf2.putInt(tcol);
        buf2.putInt(trow);
        buf2.putInt(twp);
        buf2.putInt(thp);
        buf2.putString(terminal_mode);
        session.pre_write(packet2);
        buf2 = new Buffer();
        packet2 = new Packet(buf2);
        packet2.reset();
        buf2.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        buf2.putInt(recipient);
        buf2.putString(str2byte("shell", "UTF-8"));
        buf2.putByte((byte) 0);
        session.pre_write(packet2);
        new Thread(this).start();
        connected = true;
    }
    public void add_notifyme(int a) {
        notifyme += a;
    }
    public void notifyme_substract(int a) {
        notifyme -= a;
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
    public void run() {
        // ponto critico!!
        Buffer buf = new Buffer(rmpsize);
        Packet packet = new Packet(buf);
        try {
            while (isConnected()) {
                int i = in.read(buf.buffer, 14, buf.buffer.length -142);
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
                buf.skip(i);
                session.write(packet, i);
            }
        } catch (Exception e) {
            System.out.println("ex_20");
        }
    }
}

