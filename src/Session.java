import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Proxy;
import java.net.Socket;

class Session extends UtilC{
    static final int SSH_MSG_DISCONNECT = 1;
    static final int SSH_MSG_IGNORE = 2;
    static final int SSH_MSG_UNIMPLEMENTED = 3;
    static final int SSH_MSG_DEBUG = 4;
    static final int SSH_MSG_SERVICE_REQUEST = 5;
    static final int SSH_MSG_KEXINIT = 20;
    static final int SSH_MSG_NEWKEYS = 21;
    static final int SSH_MSG_KEXDH_INIT = 30;
    static final int SSH_MSG_KEXDH_REPLY = 31;
    static final int SSH_MSG_KEX_DH_GEX_GROUP = 31;
    static final int SSH_MSG_KEX_DH_GEX_INIT = 32;
    static final int SSH_MSG_KEX_DH_GEX_REPLY = 33;
    static final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;
    static final int SSH_MSG_GLOBAL_REQUEST = 80;
    static final int SSH_MSG_REQUEST_SUCCESS = 81;
    static final int SSH_MSG_REQUEST_FAILURE = 82;
    static final int SSH_MSG_CHANNEL_OPEN = 90;
    static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    static final int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    static final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    static final int SSH_MSG_CHANNEL_DATA = 94;
    static final int SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    static final int SSH_MSG_CHANNEL_EOF = 96;
    static final int SSH_MSG_CHANNEL_CLOSE = 97;
    static final int SSH_MSG_CHANNEL_REQUEST = 98;
    static final int SSH_MSG_CHANNEL_SUCCESS = 99;
    static final int SSH_MSG_CHANNEL_FAILURE = 100;
    private static final int PACKET_MAX_SIZE = 256 * 1024;
    private byte[] V_S;
    private byte[] V_C = str2byte("SSH-2.0-CUSTOM", "UTF-8");
    private byte[] I_C;
    private byte[] I_S;
    private byte[] session_ids;
    private byte[] IVc2s;
    private byte[] IVs2c;
    private byte[] Ec2s;
    private byte[] Es2c;
    private byte[] MACc2s;
    private byte[] MACs2c;
    private int seqi = 0;
    private int seqo = 0;
    String[] guess = null;
    private javax.crypto.Cipher s2ccipher;
    private javax.crypto.Cipher c2scipher;
    private javax.crypto.Mac s2cmac;
    private javax.crypto.Mac c2smac;
    private byte[] s2cmac_result1;
    private byte[] s2cmac_result2;
    private Socket socket;
    private int timeout = 0;
    private boolean isConnected = false;
    private boolean isAuthed = false;
    private Object lock = new Object();
    InputStream in = System.in;
    OutputStream out = System.out;
    private boolean in_dontclose = false;
    private boolean out_dontclose = false;
    static java.security.SecureRandom random;
    Buffer buf;
    Packet packet;
    private Proxy proxy = null;
    private String hostKeyAlias = null;
    private int serverAliveInterval = 0;
    private int serverAliveCountMax = 1;
    private long kex_start_time = 0L;
    int max_auth_tries = 6;
    int auth_failures = 0;
    String host = null;
    int port = 22;
    String username = null;
    byte[] password = null;

    Session(String host, String username, int port, String password) throws Exception {
        buf = new Buffer();
        packet = new Packet(buf);
        this.username = username;
        this.port = port;
        setPassword(password);
        connect();       
        if (isConnected)
            threading();
    }
    
    public void connect() throws ExceptionC {
        random = new java.security.SecureRandom();
        Packet.setRandom(random);
        try {
            int i, j;
            if (proxy == null) {
                try{
                    socket = new Socket(host, port);
                    in = socket.getInputStream();
                    out = socket.getOutputStream();
                    socket.setTcpNoDelay(true);
                }catch (Exception e) {
                    throw new ExceptionC("Error session connect socket " + e);
                }
            }
            isConnected = true;
            byte[] foo = new byte[V_C.length + 1];
            System.arraycopy(V_C, 0, foo, 0, V_C.length);
            foo[foo.length - 1] = (byte)'\n';
            put(foo, 0, foo.length);
            while (true) {
                i = 0;
                j = 0;
                while (i < buf.buffer.length) {
                    j = getByte();
                    if (j < 0) break;
                    buf.buffer[i] = (byte) j;
                    i++;
                    if (j == 10)
                        break;
                }
                if (j < 0)
                    throw new ExceptionC("connection is closed by foreign host");
                if (buf.buffer[i - 1] == 10) {
                    i--;
                    if (i > 0 && buf.buffer[i - 1] == 13)
                        i--;
                }
                if (i <= 3 || ((i != buf.buffer.length) && (buf.buffer[0] != 'S' || buf.buffer[1] != 'S' || buf.buffer[2] != 'H' || buf.buffer[3] != '-')))
                    continue;
                if (i == buf.buffer.length ||
                    i < 7 ||
                    (buf.buffer[4] == '1' && buf.buffer[6] != '9')
                )                    
                    throw new ExceptionC("invalid server's version string");
                break;
            }
            V_S = new byte[i];
            System.arraycopy(buf.buffer, 0, V_S, 0, i);
            send_kexinit();
            buf = read(buf);
            if (buf.getCommand() != SSH_MSG_KEXINIT) {
                in_kex = false;
                throw new ExceptionC("invalid protocol: " + buf.getCommand());
            }
            ECDH kex = receive_kexinit(buf);
            while (true) {
                buf = read(buf);
                if (kex.getState() == buf.getCommand()) {
                    kex_start_time = System.currentTimeMillis();
                    boolean result = kex.next(buf);
                    if (!result) {
                        in_kex = false;
                        throw new ExceptionC("verify: " + result);
                    }
                } else {
                    in_kex = false;
                    throw new ExceptionC("invalid protocol(kex): " + buf.getCommand());
                }
                if (kex.getState() == ECDH.STATE_END)
                    break;
            }
            in_prompt = false;
            send_newkeys();
            buf = read(buf);
            if (buf.getCommand() == SSH_MSG_NEWKEYS) {
                receive_newkeys(buf, kex);
            } else {
                in_kex = false;
                throw new ExceptionC("invalid protocol(newkyes): " + buf.getCommand());
            }
            try {
                packet.reset();
                buf.putByte((byte) Session.SSH_MSG_SERVICE_REQUEST);
                buf.putString(str2byte("ssh-userauth", "UTF-8"));
                pre_write(packet);
                buf = read(buf); // ?
            } catch (Exception e) {
                throw new ExceptionC("Error Session 180 " + e.toString());
            }
            int SSH_MSG_USERAUTH_REQUEST = 50;
            int SSH_MSG_USERAUTH_FAILURE = 51;
            int SSH_MSG_USERAUTH_BANNER = 53;
            int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
            if (password == null)
                throw new Exception("Error AuthCancel - not found password");
            if (auth_failures >= max_auth_tries)
                return;
            packet.reset();
            buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
            buf.putString(str2byte(username, "UTF-8"));
            buf.putString(str2byte("ssh-connection", "UTF-8"));
            buf.putString(str2byte("password", "UTF-8"));
            buf.putByte((byte) 0);
            buf.putString(password);
            pre_write(packet);
            buf = read(buf);
            int command = buf.getCommand() & 0xff;
            if (command == SSH_MSG_USERAUTH_BANNER)
                throw new Exception("USERAUTH_BANNER");
            if (command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
                throw new Exception("Stop - USERAUTH_PASSWD_CHANGEREQ");
            if (command == SSH_MSG_USERAUTH_FAILURE)
                throw new Exception("UserAuth Fail!");
            if (socket != null && timeout > 0)
                socket.setSoTimeout(timeout);
            isAuthed = true;
        }catch(Exception e){
            //System.err.println("[]"+ e);
            in_kex = false;
            try {
                if (isConnected) {
                    String message = e.toString();
                    packet.reset();
                    buf.resize_buffer(1 + 4 * 3 + message.length() + 2 + ECDH.nn);
                    buf.putByte((byte)SSH_MSG_DISCONNECT);
                    buf.putInt(3);
                    buf.putString(str2byte(message, "UTF-8"));
                    buf.putString(str2byte("en", "UTF-8"));
                    pre_write(packet);
                }
            } catch (Exception ee) {
                throw new ExceptionC("Error Session 224 " + e.toString());
            }
            isConnected = false;
            if (e instanceof RuntimeException) 
                throw new ExceptionC(".Session.connect: " + e);
            if (e instanceof ExceptionC) 
                throw new ExceptionC("..Session.connect: " + e);
            throw new ExceptionC("...Session.connect: " + e);
        }
    }

    public void threading(){
        new Thread(){
            public void run(){
                Buffer buf = new Buffer();
                Packet packet = new Packet(buf);
                Channel channel;
                ECDH kex = null;
                int stimeout = 0;        
                try {
                    while (isConnected) {
                        try {
                            buf = read(buf);
                            stimeout = 0;
                        } catch (InterruptedIOException ee) {
                            if (!in_kex && stimeout < serverAliveCountMax) {
                                sendKeepAliveMsg();
                                stimeout++;
                                continue;
                            } else if (in_kex && stimeout < serverAliveCountMax) {
                                stimeout++;
                                continue;
                            }
                            throw new ExceptionC("Error Session 261 " + ee);
                        }
                        int msgType = buf.getCommand() & 0xff;                
                        if (kex != null && kex.getState() == msgType) {
                            kex_start_time = System.currentTimeMillis();
                            boolean result = kex.next(buf);
                            if (!result) {
                                throw new ExceptionC("verify: " + result);
                            }
                            continue;
                        }
                        switch (msgType) {
                            case SSH_MSG_CHANNEL_DATA:
                                buf.getInt();
                                buf.getByte();
                                buf.getByte();
                                buf.getInt();
                                channel = Channel.getChannel();
                                byte[] a = buf.getBytes();
                                if (channel == null || a.length == 0)
                                    break;
                                try {
                                    // ponto critico retorno out
                                    if ( Channel.can_print(a.length) )
                                        channel.put(a, 0, a.length);
                                } catch (Exception e) {
                                    throw new ExceptionC("Error Session 287 " + e);                                    
                                }
                                break;
                            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                                buf.getInt();
                                buf.getShort();
                                buf.getInt();
                                channel = Channel.getChannel();
                                buf.getInt();
                                buf.getInt();
                                int rps = buf.getInt();
                                if (channel != null) {
                                    channel.set_recipient(0);                                        
                                    channel.set_rwsize(0);
                                    channel.set_rmpsize(rps);
                                }
                                break;
                            case SSH_MSG_GLOBAL_REQUEST:
                                buf.getInt();
                                buf.getShort();
                                buf.getBytes();
                                if (buf.getByte() != 0) {
                                    packet.reset();
                                    buf.putByte((byte) SSH_MSG_REQUEST_FAILURE);
                                    pre_write(packet);
                                }
                                break;
                            case SSH_MSG_CHANNEL_EOF:
                                System.exit(0);
                            default:
                                throw new IOException("msgType " + msgType+" not found. - Only 3 msgType implementations");
                        }
                    }
                } catch (Exception e) {
                    System.out.println("ex_151 " + e.toString());
                    in_kex = false;
                }
                System.exit(0);
                isConnected = false;                    
            }
        }.start();            
    }
    
    private ECDH receive_kexinit(Buffer buf) throws Exception {
        int j = buf.getInt();
        if (j != buf.getLength()) {
            buf.getByte();
            I_S = new byte[buf.i_put - 5];
        } else
            I_S = new byte[j - 1 - buf.getByte()];
        System.arraycopy(buf.buffer, buf.i_get, I_S, 0, I_S.length);
        if (!in_kex)
            send_kexinit();
        guess = ECDH.guess(I_S, I_C);
        if (guess == null)
            throw new ExceptionC("Algorithm negotiation fail");
        if (!isAuthed && (guess[ECDH.PROPOSAL_ENC_ALGS_CTOS].equals("none") || (guess[ECDH.PROPOSAL_ENC_ALGS_STOC].equals("none"))))
            throw new ExceptionC("NONE Cipher should not be chosen before authentification is successed.");
        ECDH kex = new ECDH();
        kex.init(this, V_S, V_C, I_S, I_C);
        return kex;
    }
    private boolean in_kex = false;
    private boolean in_prompt = false;
    public void rekey() throws Exception {
        send_kexinit();
    }

    private void send_kexinit() throws Exception {
        if (in_kex)
            return;

        in_kex = true;
        kex_start_time = System.currentTimeMillis();
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) SSH_MSG_KEXINIT);
        synchronized(random) {
            int start_fill = buf.i_put;
            int len_fill = 16;
            byte[] tmp_fill = new byte[16];
            if (len_fill > tmp_fill.length) {
                tmp_fill = new byte[len_fill];
            }
            random.nextBytes(tmp_fill);
            System.arraycopy(tmp_fill, 0, buf.buffer, start_fill, len_fill);
            buf.skip_put(16);
        }
        buf.putString(str2byte(ECDH.cipher, "UTF-8"));
        buf.putString(str2byte(ECDH.groupCipher, "UTF-8"));
        buf.putString(str2byte("aes256-ctr", "UTF-8"));
        buf.putString(str2byte("aes256-ctr", "UTF-8"));
        buf.putString(str2byte("hmac-sha1", "UTF-8"));
        buf.putString(str2byte("hmac-sha1", "UTF-8"));
        buf.putString(str2byte("none", "UTF-8"));
        buf.putString(str2byte("none", "UTF-8"));
        buf.putString(str2byte("", "UTF-8"));
        buf.putString(str2byte("", "UTF-8"));
        buf.putByte((byte) 0);
        buf.putInt(0);
        buf.set_get(5);
        I_C = buf.getBytesAll();
        pre_write(packet);
    }

    private void send_newkeys() throws Exception {
        packet.reset();
        buf.putByte((byte) SSH_MSG_NEWKEYS);
        pre_write(packet);
    }

    public void encode(Packet packet) throws Exception {
        if (c2scipher != null) {
            packet.padding(c2scipher_size);
            int pad = packet.buffer.buffer[4];
            synchronized(random) {
                byte[] foo_fill = packet.buffer.buffer;
                int start_fill = packet.buffer.i_put - pad;
                int len_fill = pad;
                byte[] tmp_fill = new byte[16];
                if (len_fill > tmp_fill.length)
                    tmp_fill = new byte[len_fill];
                random.nextBytes(tmp_fill);
                System.arraycopy(tmp_fill, 0, foo_fill, start_fill, len_fill);
            }
        } else {
            packet.padding(8);
        }
        if (c2smac != null) {
            byte[] tmp = new byte[4];
            tmp[0] = (byte)(seqo >>> 24);
            tmp[1] = (byte)(seqo >>> 16);
            tmp[2] = (byte)(seqo >>> 8);
            tmp[3] = (byte) seqo;
            c2smac.update(tmp, 0, 4);
            c2smac.update(packet.buffer.buffer, 0, packet.buffer.i_put);
            c2smac.doFinal(packet.buffer.buffer, packet.buffer.i_put);
        }
        if (c2scipher != null) {
            byte[] buf = packet.buffer.buffer;
            c2scipher.update(buf, 0, packet.buffer.i_put, buf, 0);
        }
        if (c2smac != null) {
            packet.buffer.skip_put(20);
        }
    }

    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;
    public Buffer read(Buffer buf) throws Exception {
        int j = 0;
        while (true) {
            buf.reset();
            getByte(buf.buffer, buf.i_put, s2ccipher_size, 1);
            buf.i_put += s2ccipher_size;
            if (s2ccipher != null)
                s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
            j = ((buf.buffer[0] << 24) & 0xff000000) | ((buf.buffer[1] << 16) & 0x00ff0000) | ((buf.buffer[2] << 8) & 0x0000ff00) | ((buf.buffer[3]) & 0x000000ff);
            int need = j + 4 - s2ccipher_size;
            if ((buf.i_put + need) > buf.buffer.length) {
                byte[] foo = new byte[buf.i_put + need];
                System.arraycopy(buf.buffer, 0, foo, 0, buf.i_put);
                buf.buffer = foo;
            }
            if (need > 0) {
                getByte(buf.buffer, buf.i_put, need, 2);
                buf.i_put += (need);
                if (s2ccipher != null) {
                    s2ccipher.update(buf.buffer, s2ccipher_size, need, buf.buffer, s2ccipher_size);
                }
            }
            if (s2cmac != null) {
                byte[] tmp = new byte[4];
                tmp[0] = (byte)(seqi >>> 24);
                tmp[1] = (byte)(seqi >>> 16);
                tmp[2] = (byte)(seqi >>> 8);
                tmp[3] = (byte) seqi;
                s2cmac.update(tmp, 0, 4);
                s2cmac.update(buf.buffer, 0, buf.i_put);
                s2cmac.doFinal(s2cmac_result1, 0);
                getByte(s2cmac_result2, 0, s2cmac_result2.length, 3);
                if (!java.util.Arrays.equals(s2cmac_result1, s2cmac_result2)) {
                    if (need > PACKET_MAX_SIZE)
                        throw new IOException("MAC Error");
                    continue;
                }
            }
            seqi++;
            int type = buf.getCommand() & 0xff;
            if (type == SSH_MSG_DISCONNECT) {
                buf.reset_get();
                buf.getInt();
                buf.getShort();
                int reason_code = buf.getInt();
                byte[] text = buf.getBytes();
                byte[] language_tag = buf.getBytes();
                throw new ExceptionC("SSH_MSG_DISCONNECT" + reason_code + " " + byte2str(text) + " " + byte2str(language_tag));
            } else if (type == SSH_MSG_IGNORE) {
            } else if (type == SSH_MSG_UNIMPLEMENTED) {
                buf.reset_get();
                buf.getInt();
                buf.getShort();
                buf.getInt();
            } else if (type == SSH_MSG_DEBUG) {
                buf.reset_get();
                buf.getInt();
                buf.getShort();
            } else if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
                buf.reset_get();
                buf.getInt();
                buf.getShort();
                buf.getInt();
                Channel c = Channel.getChannel();
                if (c != null)
                    c.add_rwsize(buf.getInt());
            } else {
                isAuthed = true;
                break;
            }
        }
        buf.reset_get();
        return buf;
    }

    private void receive_newkeys(Buffer buf, ECDH kex) throws Exception {
        in_kex = false;
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        java.security.MessageDigest sha512 = kex.getHash();
        if (session_ids == null) {
            session_ids = new byte[H.length];
            System.arraycopy(H, 0, session_ids, 0, H.length);
        }
        buf.reset();
        buf.putMPInt(K);
        buf.putBytes(H, 0, H.length);
        buf.putByte((byte) 0x41);
        buf.putBytes(session_ids, 0, session_ids.length);
        sha512.update(buf.buffer, 0, buf.i_put);
        IVc2s = sha512.digest();
        int j = buf.i_put - session_ids.length - 1;
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.i_put);
        IVs2c = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.i_put);
        Ec2s = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.i_put);
        Es2c = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.i_put);
        MACc2s = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.i_put);
        MACs2c = sha512.digest();
        try {
            while (32 > Es2c.length) {
                buf.reset();
                buf.putMPInt(K);
                buf.putBytes(H, 0, H.length);
                buf.putBytes(Es2c, 0, Es2c.length);
                sha512.update(buf.buffer, 0, buf.i_put);
                byte[] foo = sha512.digest();
                byte[] bar = new byte[Es2c.length + foo.length];
                System.arraycopy(Es2c, 0, bar, 0, Es2c.length);
                System.arraycopy(foo, 0, bar, Es2c.length, foo.length);
                Es2c = bar;
            }
            byte[] tmp;
            if (IVs2c.length > 16) {
                tmp = new byte[16];
                System.arraycopy(IVs2c, 0, tmp, 0, tmp.length);
                IVs2c = tmp;
            }
            if (Es2c.length > 32) {
                tmp = new byte[32];
                System.arraycopy(Es2c, 0, tmp, 0, tmp.length);
                Es2c = tmp;
            }
            s2ccipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            synchronized(javax.crypto.Cipher.class) {
                s2ccipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(Es2c, "AES"), new javax.crypto.spec.IvParameterSpec(IVs2c));
            }
            s2ccipher_size = 16;
            if (MACs2c.length > 20) {
                byte[] tmp2 = new byte[20];
                System.arraycopy(MACs2c, 0, tmp2, 0, 20);
                MACs2c = tmp2;
            }
            s2cmac = javax.crypto.Mac.getInstance("HmacSHA1");
            s2cmac.init(new javax.crypto.spec.SecretKeySpec(MACs2c, "HmacSHA1"));
            s2cmac_result1 = new byte[20];
            s2cmac_result2 = new byte[20];
            while (32 > Ec2s.length) {
                buf.reset();
                buf.putMPInt(K);
                buf.putBytes(H, 0, H.length);
                buf.putBytes(Ec2s, 0, Ec2s.length);
                sha512.update(buf.buffer, 0, buf.i_put);
                byte[] foo = sha512.digest();
                byte[] bar = new byte[Ec2s.length + foo.length];
                System.arraycopy(Ec2s, 0, bar, 0, Ec2s.length);
                System.arraycopy(foo, 0, bar, Ec2s.length, foo.length);
                Ec2s = bar;
            }
            byte[] tmp3;
            if (IVc2s.length > 16) {
                tmp3 = new byte[16];
                System.arraycopy(IVc2s, 0, tmp3, 0, tmp3.length);
                IVc2s = tmp3;
            }
            if (Ec2s.length > 32) {
                tmp3 = new byte[32];
                System.arraycopy(Ec2s, 0, tmp3, 0, tmp3.length);
                Ec2s = tmp3;
            }
            c2scipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            synchronized(javax.crypto.Cipher.class) {
                c2scipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(Ec2s, "AES"), new javax.crypto.spec.IvParameterSpec(IVc2s));
            }
            c2scipher_size = 16;
            if (MACc2s.length > 20) {
                byte[] tmp4 = new byte[20];
                System.arraycopy(MACc2s, 0, tmp4, 0, 20);
                MACc2s = tmp4;
            }
            c2smac = javax.crypto.Mac.getInstance("HmacSHA1");
            c2smac.init(new javax.crypto.spec.SecretKeySpec(MACc2s, "HmacSHA1"));
        } catch (Exception e) {
            System.out.println("ex_149");
            if (e instanceof ExceptionC)
                throw e;
            throw new ExceptionC(e.toString(), e);
        }
    }
    public void pre_write(Packet packet) throws Exception {
        long t = getTimeout();
        while (in_kex) {
            if (t > 0L && (System.currentTimeMillis() - kex_start_time) > t && !in_prompt)
                throw new ExceptionC("timeout in waiting for rekeying process.");
            byte command = packet.buffer.getCommand();
            if (command == SSH_MSG_KEXINIT ||
                command == SSH_MSG_NEWKEYS ||
                command == SSH_MSG_KEXDH_INIT ||
                command == SSH_MSG_KEXDH_REPLY ||
                command == SSH_MSG_KEX_DH_GEX_GROUP ||
                command == SSH_MSG_KEX_DH_GEX_INIT ||
                command == SSH_MSG_KEX_DH_GEX_REPLY ||
                command == SSH_MSG_KEX_DH_GEX_REQUEST ||
                command == SSH_MSG_DISCONNECT) {
                break;
            }
            sleep(10);
        }
        pos_write(packet);
    }
    void write(Packet packet, int length) throws Exception {
        Channel c = Channel.getChannel();
        long t = getTimeout();
        while (true) {
            if (c.get_close() || !c.isConnected())
                throw new Exception("channel is broken");
            if (in_kex)
                sleep(10);
            int s = 0;
            if (c.get_rwsize() > 0) {
                long len = c.get_rwsize();
                if (len > length)
                    len = length;
                if (len != length)
                    s = packet.shift((int) len, c2scipher_size, 20);
                byte command = packet.buffer.getCommand();
                length -= len;
                c.rwsize_substract(len);
                pos_write(packet);
                if (length == 0)
                    return;
                packet.unshift(command, -1, s, length);
            }
            if (in_kex)
                continue;
            if (c.get_rwsize() >= length) {
                c.rwsize_substract(length);
                break;
            }
        }
        pos_write(packet);
    }
    private void pos_write(Packet packet) throws Exception {
        encode(packet);
        put(packet);
        seqo++;
    }
    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }
    public void setHost(String host) {
        this.host = host;
    }
    public void setPort(int port) {
        this.port = port;
    }
    public void setInputStream(InputStream in ) {
        this.in = in ;
    }
    public void setOutputStream(OutputStream out) {
        this.out = out;
    }
    public void setPassword(String password) {
        if (password != null)
            this.password = str2byte(password, "UTF-8");
    }
    public boolean isConnected() {
        return isConnected;
    }
    public int getTimeout() {
        return timeout;
    }
    public void setTimeout(int timeout) throws ExceptionC {
        if (socket == null) {
            if (timeout < 0) {
                throw new ExceptionC("invalid timeout value");
            }
            this.timeout = timeout;
            return;
        }
        try {
            socket.setSoTimeout(timeout);
            this.timeout = timeout;
        } catch (Exception e) {
            System.out.println("ex_156");
            if (e instanceof Throwable)
                throw new ExceptionC(e.toString(), (Throwable) e);
            throw new ExceptionC(e.toString());
        }
    }
    public String getServerVersion() {
        return byte2str(V_S);
    }
    public String getClientVersion() {
        return byte2str(V_C);
    }
    public void setClientVersion(String cv) {
        V_C = str2byte(cv, "UTF-8");
    }
    public void sendIgnore() throws Exception {
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) SSH_MSG_IGNORE);
        pre_write(packet);
    }
    private static final byte[] keepalivemsg = str2byte("", "UTF-8");
    public void sendKeepAliveMsg() throws Exception {
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) SSH_MSG_GLOBAL_REQUEST);
        buf.putString(keepalivemsg);
        buf.putByte((byte) 1);
        pre_write(packet);
    }
    private static final byte[] nomoresessions = str2byte("no-more-sessions@openssh.com", "UTF-8");
    public void noMoreSessionChannels() throws Exception {
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) SSH_MSG_GLOBAL_REQUEST);
        buf.putString(nomoresessions);
        buf.putByte((byte) 0);
        pre_write(packet);
    }
    public String getHost() {
        return host;
    }
    public String getUserName() {
        return username;
    }
    public int getPort() {
        return port;
    }
    public void setHostKeyAlias(String hostKeyAlias) {
        this.hostKeyAlias = hostKeyAlias;
    }
    public String getHostKeyAlias() {
        return hostKeyAlias;
    }
    public void setServerAliveInterval(int interval) throws ExceptionC {
        setTimeout(interval);
        this.serverAliveInterval = interval;
    }
    public int getServerAliveInterval() {
        return this.serverAliveInterval;
    }
    public void setServerAliveCountMax(int count) {
        this.serverAliveCountMax = count;
    }
    public int getServerAliveCountMax() {
        return this.serverAliveCountMax;
    }
    public void put(Packet p) throws IOException, java.net.SocketException {
        out.write(p.buffer.buffer, 0, p.buffer.i_put);
        out.flush();
    }
    void put(byte[] array, int begin, int length) throws IOException {
        out.write(array, begin, length);
        out.flush();
    }
    int getByte() throws IOException {
        return in.read();
    }
    void getByte(byte[] array, int begin, int length, int identity) throws IOException {
        do {
            int completed = in.read(array, begin, length);            
            show("cipher", completed, array);
            // here error ubuntu
            if (completed < 0)
                throw new IOException("End of IO Stream Read - identity: " + identity);
            begin += completed;
            length -= completed;
        }
        while (length > 0);
    }
    void out_close() {
        try {
            if (out != null && !out_dontclose) 
                out.close();
            out = null;
        } catch (Exception ee) {}
    }
    public void close() {
        try {
            if ( in != null && !in_dontclose) 
                in.close(); 
            in = null;
        } catch (Exception ee) {}
        out_close();
    }
}


