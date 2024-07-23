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
    private javax.crypto.Cipher s2ccipher;
    private javax.crypto.Cipher c2scipher;
    private javax.crypto.Mac s2cmac;
    private javax.crypto.Mac c2smac;
    private byte[] s2cmac_result1;
    private byte[] s2cmac_result2;
    private java.net.Socket socket;
    private boolean isAuthed = false;
    Packet _packet;
    private long kex_start_time = 0L;
    String username = null;
    byte[] password = null;
    private boolean in_kex = false;
    private boolean in_prompt = false;    
    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;

    java.io.InputStream in = null;
    java.io.OutputStream out = null;
    private long rwsize2 = 0;
    public boolean channel_opened=false;
    private int rmpsize = 0;

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
    
    Session(String host, String username, int port, String password) throws Exception {                
        connect_stream(host, username, port, password);           
        new Thread(){
            public void run(){
                working_stream();
            }
        }.start();        
        connect();
        working();
    }
    
    public void connect_stream(String host, String username, int port, String _password) throws Exception{
        this.username = username;
        this.password = str2byte(_password, "UTF-8");
        _packet = new Packet();
        try {
            int i, j;
            try{
                socket = new java.net.Socket(host, port);
                in = socket.getInputStream();
                out = socket.getOutputStream();
            }catch (Exception e) {
                throw new Exception("Error session connect socket " + e);
            }
            byte[] foo = new byte[V_C.length + 1];
            System.arraycopy(V_C, 0, foo, 0, V_C.length);
            foo[foo.length - 1] = (byte)'\n';            
            put_stream(foo, 0, foo.length);
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
            isAuthed = true;
        }catch(Exception e){
            throw new Exception("Error Session 224 " + e.toString());
        }
    }

    public void working_stream(){
        Packet packet = new Packet();
        try {
            while (true) {
                try {
                    packet.buf = read(packet.buf);
                } catch (java.io.InterruptedIOException ee) {
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
                        if (a.length == 0)
                            break;
                        try {
                            // ponto critico retorno out
                            // enviando ls ele só retorna ls
                            // analisando o send, dá para observar que ele manda o dado
                            // ainda não sei porque ele nao me responde corretamente.
                            ///////////                                    
                            if ( can_print(a.length) )
                                put(a, 0, a.length);
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
                        channel_opened=true;
                        set_rwsize(0);
                        set_rmpsize(rps);                        
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
                        throw new java.io.IOException("msgType " + msgType+" not found. - Only 3 msgType implementations");
                }
            }
        } catch (Exception e) {
            System.out.println("ex_151 " + e.toString());
            in_kex = false;
        }
        System.exit(0);
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
        String[] guess = ECDH.guess(I_S, I_C);
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
            buf.skip_put(s2ccipher_size);
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
                buf.skip_put(need);
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
                        throw new java.io.IOException("MAC Error");
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
                add_rwsize(buf.getInt());
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
        long t = 0;
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
            if (in_kex)
                sleep(10);
            int s = 0;
            if (get_rwsize() > 0) {
                long len = get_rwsize();
                if (len > length)
                    len = length;
                if (len != length)
                    s = packet.shift((int) len, c2scipher_size, 20);
                byte command = packet.buf.getCommand();
                length -= len;
                rwsize_substract(len);
                pos_write(packet);
                if (length == 0)
                    return;
                packet.unshift(command, -1, s, length);
            }
            if (in_kex)
                continue;
            if (get_rwsize() >= length) {
                rwsize_substract(length);
                break;
            }
        }
        pos_write(packet);
    }
    private void pos_write(Packet packet) throws Exception {
        encode(packet);
        put_stream(packet);
        seqo++;
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
    public void put_stream(Packet p) throws java.io.IOException, java.net.SocketException {
        //////////// System.out.write(p.buffer.buffer, 0, p.buffer.get_put());
        out.write(p.buf.buffer, 0, p.buf.get_put());
        out.flush();
    }
    void put_stream(byte[] array, int begin, int length) throws java.io.IOException {
        out.write(array, begin, length);
        out.flush();
    }
    int getByte() throws java.io.IOException {
        return in.read();
    }
    void getByte(byte[] array, int begin, int length, int identity) throws java.io.IOException {
        do {
            int completed = in.read(array, begin, length);            
            if (completed < 0)
                throw new java.io.IOException("End of IO Stream Read - identity: " + identity);
            begin += completed;
            length -= completed;
        }
        while (length > 0);
    }
    void out_close(){
        try {
            if (out != null) 
                out.close();
            out = null;
        } catch (Exception ee) {}
    }
    public void close() {
        try {
            if ( in != null) 
                in.close(); 
            in = null;
        } catch (Exception ee) {}
        out_close();
    }
    
    public void connect() throws Exception {
        Packet packet = new Packet(new Buffer(new byte[100]));
        packet.reset();
        packet.buf.putByte((byte) 90);
        packet.buf.putValue(str2byte("session", "UTF-8"));
        packet.buf.putInt(0);
        packet.buf.putInt(0x100000);
        packet.buf.putInt(0x4000);
        pre_write(packet);
        
        for ( int i=0;i<3000;i++ ){
            if ( !channel_opened ){
                sleep(10);
                continue;
            }
            break;
        }
        
        if ( !channel_opened )
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
        pre_write(packet);
        
        packet = new Packet();
        packet.reset();
        packet.buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        packet.buf.putInt(0);
        packet.buf.putValue(str2byte("shell", "UTF-8"));        
        packet.buf.putByte((byte) 0);
        pre_write(packet);
    }
    public void working(){
        ///////////
        // ponto critico!!
        Packet packet = new Packet(new Buffer(new byte[rmpsize]));
        try {
            while (true){
                int i = System.in.read(packet.buf.buffer, 14, packet.buf.buffer.length -14 -ECDH.nn);
                //System.out.write("[IN]".getBytes());
                //System.out.write(buf.buffer, 0, i);
                //System.out.write("[OUT]".getBytes());                
                count_line_return=0;
                if (i == 0)
                    continue;
                if (i == -1)
                    break;
                packet.reset();
                packet.buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                packet.buf.putInt(0);
                packet.buf.putInt(i);
                packet.buf.skip_put(i);                
                write(packet, i);
            }
        } catch (Exception e) {
            System.out.println("ex_20");
        }        
    }
    public void set_rwsize(long a) {
        rwsize2 = a;
    }
    public void add_rwsize(long a) {
        rwsize2 += a;
    }
    public long get_rwsize() {
        return rwsize2;
    }
    public void rwsize_substract(long a) {
        rwsize2 -= a;
    }
    public void set_rmpsize(int a) {
        this.rmpsize = a;
    }
    void put(byte[] array, int begin, int length) throws Exception {
        System.out.write(array, begin, length);
        System.out.flush();
    }    
}



