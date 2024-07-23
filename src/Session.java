import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
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
    InputStream in = System.in;
    OutputStream out = System.out;
    private boolean in_dontclose = false;
    private boolean out_dontclose = false;
    Packet _packet;
    private int serverAliveCountMax = 1;
    private long kex_start_time = 0L;
    public Channel channel=null;    
    String host = null;
    int port = 22;
    String username = null;
    byte[] password = null;
    private boolean in_kex = false;
    private boolean in_prompt = false;    
    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;

    Session(String host, String username, int port, String password) throws Exception {        
        _packet = new Packet();
        this.host=host;
        this.username = username;
        this.port = port;
        setPassword(password);
        connect();       
        if (isConnected)
            threading();
    }
    
    public void connect() throws Exception {        
        try {
            int i, j;
            try{
                socket = new Socket(host, port);
                in = socket.getInputStream();
                out = socket.getOutputStream();
            }catch (Exception e) {
                throw new Exception("Error session connect socket " + e);
            }
            isConnected = true;
            byte[] foo = new byte[V_C.length + 1];
            System.arraycopy(V_C, 0, foo, 0, V_C.length);
            foo[foo.length - 1] = (byte)'\n';            
            put(foo, 0, foo.length);
            while (true) {
                i = 0;
                j = 0;
                while (i < _packet.buf.buffer.length) {
                    j = getByte();
                    if (j < 0) break;
                    _packet.buf.buffer[i] = (byte) j;
                    i++;
                    if (j == 10)
                        break;
                }
                if (j < 0)
                    throw new Exception("connection is closed by foreign host");
                if (_packet.buf.buffer[i - 1] == 10) {
                    i--;
                    if (i > 0 && _packet.buf.buffer[i - 1] == 13)
                        i--;
                }
                if (i <= 3 || ((i != _packet.buf.buffer.length) && (_packet.buf.buffer[0] != 'S' || _packet.buf.buffer[1] != 'S' || _packet.buf.buffer[2] != 'H' || _packet.buf.buffer[3] != '-')))
                    continue;
                if (i == _packet.buf.buffer.length ||
                    i < 7 ||
                    (_packet.buf.buffer[4] == '1' && _packet.buf.buffer[6] != '9')
                )                    
                    throw new Exception("invalid server's version string");
                break;
            }
            V_S = new byte[i];
            System.arraycopy(_packet.buf.buffer, 0, V_S, 0, i);
            send_kexinit();
            _packet.buf = read(_packet.buf);
            if (_packet.buf.getCommand() != SSH_MSG_KEXINIT) {
                in_kex = false;
                throw new Exception("invalid protocol: " + _packet.buf.getCommand());
            }
            ECDH kex = receive_kexinit(_packet.buf);
            while (true) {
                _packet.buf = read(_packet.buf);
                if (kex.getState() == _packet.buf.getCommand()) {
                    kex_start_time = System.currentTimeMillis();
                    boolean result = kex.next(_packet.buf);
                    if (!result) {
                        in_kex = false;
                        throw new Exception("verify: " + result);
                    }
                } else {
                    in_kex = false;
                    throw new Exception("invalid protocol(kex): " + _packet.buf.getCommand());
                }
                if (kex.getState() == ECDH.STATE_END)
                    break;
            }
            in_prompt = false;
            send_newkeys();
            _packet.buf = read(_packet.buf);
            if (_packet.buf.getCommand() == SSH_MSG_NEWKEYS) {
                receive_newkeys(_packet.buf, kex);
            } else {
                in_kex = false;
                throw new Exception("invalid protocol(newkyes): " + _packet.buf.getCommand());
            }
            try {
                _packet.reset();
                _packet.buf.putByte((byte) Session.SSH_MSG_SERVICE_REQUEST);
                _packet.buf.putValue(str2byte("ssh-userauth", "UTF-8"));
                pre_write(_packet);
                _packet.buf = read(_packet.buf); // ?
            } catch (Exception e) {
                throw new Exception("Error Session 180 " + e.toString());
            }
            int SSH_MSG_USERAUTH_REQUEST = 50;
            int SSH_MSG_USERAUTH_FAILURE = 51;
            int SSH_MSG_USERAUTH_BANNER = 53;
            int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
            if (password == null)
                throw new Exception("Error AuthCancel - not found password");
            _packet.reset();
            _packet.buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
            _packet.buf.putValue(str2byte(username, "UTF-8"));
            _packet.buf.putValue(str2byte("ssh-connection", "UTF-8"));
            _packet.buf.putValue(str2byte("password", "UTF-8"));
            _packet.buf.putByte((byte) 0);
            _packet.buf.putValue(password);
            pre_write(_packet);
            _packet.buf = read(_packet.buf);
            int command = _packet.buf.getCommand() & 0xff;
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
            in_kex = false;
            try {
                if (isConnected) {
                    String message = e.toString();
                    _packet.reset();
                    _packet.buf.resize_buffer(1 + 4 * 3 + message.length() + 2 + ECDH.nn);
                    _packet.buf.putByte((byte)SSH_MSG_DISCONNECT);
                    _packet.buf.putInt(3);
                    _packet.buf.putValue(str2byte(message, "UTF-8"));
                    _packet.buf.putValue(str2byte("en", "UTF-8"));
                    pre_write(_packet);
                }
            } catch (Exception ee) {
                throw new Exception("Error Session 224 " + e.toString());
            }
            isConnected = false;
            if (e instanceof RuntimeException) 
                throw new Exception(".Session.connect: " + e);
            throw new Exception("...Session.connect: " + e);
        }
    }

    public void threading(){
        new Thread(){
            public void run(){
                Packet packet = new Packet();
                int stimeout = 0;        
                try {
                    while (isConnected) {
                        try {
                            packet.buf = read(packet.buf);
                            stimeout = 0;
                        } catch (InterruptedIOException ee) {
                            // nao ha problemas aqui
                            if (!in_kex && stimeout < serverAliveCountMax) {
                                sendKeepAliveMsg();
                                stimeout++;
                                continue;
                            } else if (in_kex && stimeout < serverAliveCountMax) {
                                stimeout++;
                                continue;
                            }
                            throw new Exception("Error Session 261 " + ee);
                        }
                        int msgType = packet.buf.getCommand() & 0xff;                
                        switch (msgType) {
                            case SSH_MSG_CHANNEL_DATA:
                                packet.buf.getInt();
                                packet.buf.getByte();
                                packet.buf.getByte();
                                packet.buf.getInt();
                                byte[] a = packet.buf.getValue();
                                if (channel == null || a.length == 0)
                                    break;
                                try {
                                    // ponto critico retorno out
                                    // enviando ls ele só retorna ls
                                    // analisando o send, dá para observar que ele manda o dado
                                    // ainda não sei porque ele nao me responde corretamente.
                                    ///////////                                    
                                    if ( channel.can_print(a.length) )
                                        channel.put(a, 0, a.length);
                                } catch (Exception e) {
                                    throw new Exception("Error Session 287 " + e);                                    
                                }
                                break;
                            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                                packet.buf.getInt();
                                packet.buf.getShort();
                                packet.buf.getInt();
                                packet.buf.getInt();
                                packet.buf.getInt();
                                int rps = packet.buf.getInt();
                                if (channel != null) {
                                    //channel.set_recipient(0);                                        
                                    channel.channel_opened=true;
                                    channel.set_rwsize(0);
                                    channel.set_rmpsize(rps);
                                }
                                break;
                            case SSH_MSG_GLOBAL_REQUEST:
                                packet.buf.getInt();
                                packet.buf.getShort();
                                packet.buf.getValue();
                                if (packet.buf.getByte() != 0) {
                                    packet.reset();
                                    packet.buf.putByte((byte) SSH_MSG_REQUEST_FAILURE);
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
            I_S = new byte[buf.get_put() - 5];
        } else
            I_S = new byte[j - 1 - buf.getByte()];
        System.arraycopy(buf.buffer, buf.get_get(), I_S, 0, I_S.length);
        if (!in_kex)
            send_kexinit();
        guess = ECDH.guess(I_S, I_C);
        if (guess == null)
            throw new Exception("Algorithm negotiation fail");
        if (!isAuthed && (guess[ECDH.PROPOSAL_ENC_ALGS_CTOS].equals("none") || (guess[ECDH.PROPOSAL_ENC_ALGS_STOC].equals("none"))))
            throw new Exception("NONE Cipher should not be chosen before authentification is successed.");
        ECDH kex = new ECDH();
        kex.init(this, V_S, V_C, I_S, I_C);
        return kex;
    }
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
        int start_fill = buf.get_put();
        int len_fill = 16;
        byte[] tmp_fill = new byte[16];
        if (len_fill > tmp_fill.length) {
            tmp_fill = new byte[len_fill];
        }
        Packet.random.nextBytes(tmp_fill);
        System.arraycopy(tmp_fill, 0, buf.buffer, start_fill, len_fill);
        buf.skip_put(16);
        buf.putValue(str2byte(ECDH.cipher, "UTF-8"));
        buf.putValue(str2byte(ECDH.groupCipher, "UTF-8"));
        buf.putValue(str2byte("aes256-ctr", "UTF-8"));
        buf.putValue(str2byte("aes256-ctr", "UTF-8"));
        buf.putValue(str2byte("hmac-sha1", "UTF-8"));
        buf.putValue(str2byte("hmac-sha1", "UTF-8"));
        buf.putValue(str2byte("none", "UTF-8"));
        buf.putValue(str2byte("none", "UTF-8"));
        buf.putValue(str2byte("", "UTF-8"));
        buf.putValue(str2byte("", "UTF-8"));
        buf.putByte((byte) 0);
        buf.putInt(0);
        buf.set_get(5);
        I_C = buf.getValueAllLen();
        pre_write(packet);
    }

    private void send_newkeys() throws Exception {
        _packet.reset();
        _packet.buf.putByte((byte) SSH_MSG_NEWKEYS);
        pre_write(_packet);
    }

    public void encode(Packet packet) throws Exception {
        if (c2scipher != null) {
            packet.padding(c2scipher_size);
            int pad = packet.buf.buffer[4];
            byte[] foo_fill = packet.buf.buffer;
            int start_fill = packet.buf.get_put() - pad;
            int len_fill = pad;
            byte[] tmp_fill = new byte[16];
            if (len_fill > tmp_fill.length)
                tmp_fill = new byte[len_fill];
            Packet.random.nextBytes(tmp_fill);
            System.arraycopy(tmp_fill, 0, foo_fill, start_fill, len_fill);
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
            c2smac.update(packet.buf.buffer, 0, packet.buf.get_put());
            c2smac.doFinal(packet.buf.buffer, packet.buf.get_put());
        }
        if (c2scipher != null) {
            byte[] buf = packet.buf.buffer;
            c2scipher.update(buf, 0, packet.buf.get_put(), buf, 0);
        }
        if (c2smac != null) {
            packet.buf.skip_put(20);
        }
    }

    public Buffer read(Buffer buf) throws Exception {
        int j = 0;
        while (true) {
            buf.reset();            
            getByte(buf.buffer, buf.get_put(), s2ccipher_size, 1);
            buf.add_put(s2ccipher_size);
            if (s2ccipher != null)
                s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
            j = ((buf.buffer[0] << 24) & 0xff000000) | ((buf.buffer[1] << 16) & 0x00ff0000) | ((buf.buffer[2] << 8) & 0x0000ff00) | ((buf.buffer[3]) & 0x000000ff);
            int need = j + 4 - s2ccipher_size;
            if ((buf.get_put() + need) > buf.buffer.length) {
                byte[] foo = new byte[buf.get_put() + need];
                System.arraycopy(buf.buffer, 0, foo, 0, buf.get_put());
                buf.buffer = foo;
            }
            if (need > 0) {
                getByte(buf.buffer, buf.get_put(), need, 2);
                buf.add_put(need);
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
                s2cmac.update(buf.buffer, 0, buf.get_put());
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
                byte[] text = buf.getValue();
                byte[] language_tag = buf.getValue();
                throw new Exception("SSH_MSG_DISCONNECT" + reason_code + " " + byte2str(text) + " " + byte2str(language_tag));
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
                if (channel != null)
                    channel.add_rwsize(buf.getInt());
            } else {
                //////////////
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
        buf.putValue(K);
        buf.putBytes(H);
        buf.putByte((byte) 0x41);
        buf.putBytes(session_ids);
        sha512.update(buf.buffer, 0, buf.get_put());
        IVc2s = sha512.digest();
        int j = buf.get_put() - session_ids.length - 1;
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.get_put());
        IVs2c = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.get_put());
        Ec2s = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.get_put());
        Es2c = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.get_put());
        MACc2s = sha512.digest();
        buf.buffer[j]++;
        sha512.update(buf.buffer, 0, buf.get_put());
        MACs2c = sha512.digest();
        try {
            while (32 > Es2c.length) {
                buf.reset();
                buf.putValue(K);
                buf.putBytes(H);
                buf.putBytes(Es2c);
                sha512.update(buf.buffer, 0, buf.get_put());
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
            s2ccipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(Es2c, "AES"), new javax.crypto.spec.IvParameterSpec(IVs2c));
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
                buf.putValue(K);
                buf.putBytes(H);
                buf.putBytes(Ec2s);
                sha512.update(buf.buffer, 0, buf.get_put());
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
            c2scipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(Ec2s, "AES"), new javax.crypto.spec.IvParameterSpec(IVc2s));
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
            if (e instanceof Exception)
                throw e;
            throw new Exception(e.toString());
        }
    }
    public void pre_write(Packet packet) throws Exception {
        long t = getTimeout();
        while (in_kex) {
            if (t > 0L && (System.currentTimeMillis() - kex_start_time) > t && !in_prompt)
                throw new Exception("timeout in waiting for rekeying process.");
            byte command = packet.buf.getCommand();
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
        while (true) {
            if (channel.get_close() || !channel.isConnected())
                throw new Exception("channel is broken");
            if (in_kex)
                sleep(10);
            int s = 0;
            if (channel.get_rwsize() > 0) {
                long len = channel.get_rwsize();
                if (len > length)
                    len = length;
                if (len != length)
                    s = packet.shift((int) len, c2scipher_size, 20);
                byte command = packet.buf.getCommand();
                length -= len;
                channel.rwsize_substract(len);
                pos_write(packet);
                if (length == 0)
                    return;
                packet.unshift(command, -1, s, length);
            }
            if (in_kex)
                continue;
            if (channel.get_rwsize() >= length) {
                channel.rwsize_substract(length);
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
    public void setTimeout(int timeout) throws Exception {
        if (socket == null) {
            if (timeout < 0) {
                throw new Exception("invalid timeout value");
            }
            this.timeout = timeout;
            return;
        }
        try {
            socket.setSoTimeout(timeout);
            this.timeout = timeout;
        } catch (Exception e) {
            System.out.println("ex_156");
            throw new Exception(e.toString());
        }
    }
    private static final byte[] keepalivemsg = str2byte("", "UTF-8");
    public void sendKeepAliveMsg() throws Exception {
        Buffer buf = new Buffer();
        Packet packet = new Packet(buf);
        packet.reset();
        buf.putByte((byte) SSH_MSG_GLOBAL_REQUEST);
        buf.putValue(keepalivemsg);
        buf.putByte((byte) 1);
        pre_write(packet);
    }
    public void put(Packet p) throws IOException, java.net.SocketException {
        //////////// System.out.write(p.buffer.buffer, 0, p.buffer.get_put());
        out.write(p.buf.buffer, 0, p.buf.get_put());
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


