class Session{
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
    private int seqo = 0;    
    private javax.crypto.Cipher s2ccipher;
    private javax.crypto.Cipher c2scipher;
    private javax.crypto.Mac s2cmac;
    private javax.crypto.Mac c2smac;
    private byte[] s2cmac_result1;
    private byte[] s2cmac_result2;
    private java.net.Socket socket;    
    private boolean wait_kex = false;
    private int s2ccipher_size = 8;
    private int c2scipher_size = 8;
    Buf _buf;
    
    java.io.InputStream in = null;
    java.io.OutputStream out = null;
    private long rwsize = 0;
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
        new Thread(){public void run(){
            working_stream();
        }}.start();                
        connect();
        working();
    }
    
    public void connect_stream(String host, String username, int port, String password) throws Exception{                
        _buf = new Buf();
        byte barra_r=new byte[]{13}[0];
        byte barra_n=new byte[]{10}[0];
        try {
            int i, j;
            try{
                socket = new java.net.Socket(host, port);
                in = socket.getInputStream();
                out = socket.getOutputStream();
            }catch(Exception e){
                throw new Exception("Error session connect socket " + e);
            }
            // colocar \r\n nao resolve o problema no linux
            byte[] a = new byte[V_C.length + 1];
            System.arraycopy(V_C, 0, a, 0, V_C.length);
            a[a.length - 1] = barra_n;            
            put_stream(a);
            while(true){
                i = 0;
                j = 0;
                while(i < _buf.buffer.length){
                    j = getByte();
                    if (j < 0) 
                        break;
                    _buf.buffer[i++] = (byte) j;
                    if (j == barra_n){
                        i--;
                        if (i > 0 && _buf.buffer[i - 1] == barra_r)
                            i--;
                        break;
                    }
                }
                break;
            }
            V_S = new byte[i];
            System.arraycopy(_buf.buffer, 0, V_S, 0, i);
            send_kexinit();
            _buf = read(_buf);
            ECDH kex = receive_kexinit(_buf);
            while(true){
                _buf = read(_buf);
                if (kex.getState() != _buf.getCommand()) 
                    throw new Exception("invalid protocol(kex): " + _buf.getCommand());
                if (!kex.next(_buf)) 
                    throw new Exception("verify: false");
                if (kex.getState() == 0)
                    break;
            }
            _buf.reset_packet();
            _buf.putByte((byte) SSH_MSG_NEWKEYS);
            write(_buf);
            _buf = read(_buf);
            if (_buf.getCommand() != SSH_MSG_NEWKEYS )
                throw new Exception("invalid protocol(newkyes): " + _buf.getCommand());
            receive_newkeys(_buf, kex);
            _buf.reset_packet();
            _buf.putByte((byte) Session.SSH_MSG_SERVICE_REQUEST);
            _buf.putValue(str2byte("ssh-userauth", "UTF-8"));
            write(_buf);
            _buf = read(_buf);
            int SSH_MSG_USERAUTH_REQUEST = 50;
            int SSH_MSG_USERAUTH_FAILURE = 51;
            int SSH_MSG_USERAUTH_BANNER = 53;
            int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
            _buf.reset_packet();
            _buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
            _buf.putValue(str2byte(username, "UTF-8"));
            _buf.putValue(str2byte("ssh-connection", "UTF-8"));
            _buf.putValue(str2byte("password", "UTF-8"));
            _buf.putByte((byte) 0);
            _buf.putValue(str2byte(password, "UTF-8"));
            write(_buf);
            _buf = read(_buf);
            int command = _buf.getCommand() & 0xff;
            if (command == SSH_MSG_USERAUTH_BANNER)
                throw new Exception("USERAUTH_BANNER");
            if (command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
                throw new Exception("Stop - USERAUTH_PASSWD_CHANGEREQ");
            if (command == SSH_MSG_USERAUTH_FAILURE)
                throw new Exception("UserAuth Fail!");
        }catch(Exception e){
            throw new Exception("Error Session 224 " + e.toString());
        }
    }

    public void working_stream(){
        Buf buf=new Buf();
        try {
            while(true) {
                try{
                    buf = read(buf);
                }catch (java.io.InterruptedIOException ee){
                    throw new Exception("Error Session 261 " + ee);
                }
                int msgType = buf.getCommand() & 0xff;                
                switch (msgType) {
                    case SSH_MSG_CHANNEL_DATA:
                        buf.getInt();
                        buf.getByte();
                        buf.getByte();
                        buf.getInt();
                        byte[] a = buf.getValue();
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
                        buf.getInt();
                        buf.getShort();
                        buf.getInt();
                        buf.getInt();
                        buf.getInt();
                        int rps = buf.getInt();
                        channel_opened=true;
                        set_rwsize(0);
                        set_rmpsize(rps);                        
                        break;
                    case SSH_MSG_GLOBAL_REQUEST:
                        buf.getInt();
                        buf.getShort();
                        buf.getValue();
                        if (buf.getByte() != 0) {
                            buf.reset_packet();
                            buf.putByte((byte) SSH_MSG_REQUEST_FAILURE);
                            write(buf);
                        }
                        break;
                    case SSH_MSG_CHANNEL_EOF:
                        System.exit(0);
                    default:
                        throw new Exception("msgType " + msgType+" not found. - Only 3 msgType implementations");
                }
            }
        } catch (Exception e) {
            System.out.println("ex_151 " + e.toString());
            System.exit(1);
        }
        System.exit(0);
    }

    private void send_kexinit() throws Exception {
        wait_kex = true;
        Buf buf = new Buf();
        buf.reset_packet();
        buf.putByte((byte) SSH_MSG_KEXINIT);
        int start_fill = buf.get_put();
        int len_fill = 16;
        byte[] tmp_fill = new byte[16];
        if (len_fill > tmp_fill.length)
            tmp_fill = new byte[len_fill];
        Buf.random.nextBytes(tmp_fill);
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
        write(buf);
    }
    
    private ECDH receive_kexinit(Buf buf) throws Exception {
        int j = buf.getInt();
        if (j != buf.getLength()){
            buf.getByte();
            I_S = new byte[buf.get_put() - 5];
        }else
            I_S = new byte[j - 1 - buf.getByte()];
        System.arraycopy(buf.buffer, buf.get_get(), I_S, 0, I_S.length);
        ECDH kex = new ECDH(V_S, V_C, I_S, I_C);
        if ( kex.buf != null )
            write(kex.buf);
        return kex;
    }

    public Buf read(Buf buf) throws Exception {        
        while(true){
            buf.reset();            
            getByte(buf.buffer, buf.get_put(), s2ccipher_size, 1);
            buf.skip_put(s2ccipher_size);
            if (s2ccipher != null)
                s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
            int need = (((buf.buffer[0] << 24) & 0xff000000) | ((buf.buffer[1] << 16) & 0x00ff0000) | ((buf.buffer[2] << 8) & 0x0000ff00) | ((buf.buffer[3]) & 0x000000ff)) + 4 - s2ccipher_size;
            if ((buf.get_put() + need) > buf.buffer.length) {
                byte[] a = new byte[buf.get_put() + need];
                System.arraycopy(buf.buffer, 0, a, 0, buf.get_put());
                buf.buffer = a;
            }
            if (need > 0) {
                getByte(buf.buffer, buf.get_put(), need, 2);
                buf.skip_put(need);
                if (s2ccipher != null)
                    s2ccipher.update(buf.buffer, s2ccipher_size, need, buf.buffer, s2ccipher_size);
            }
            if (s2cmac != null) {
                s2cmac.update(buf.buffer, 0, buf.get_put());
                s2cmac.doFinal(s2cmac_result1, 0);
                getByte(s2cmac_result2, 0, s2cmac_result2.length, 3);
            }            
            int type = buf.getCommand() & 0xff;
            if (type == SSH_MSG_DISCONNECT) {
                System.exit(0);
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
                break;
            }
        }
        buf.reset_get();
        return buf;
    }

    private void receive_newkeys(Buf buf, ECDH kex) throws Exception {
        wait_kex = false;
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        java.security.MessageDigest sha = kex.getHash();
        if (session_ids == null) {
            session_ids = new byte[H.length];
            System.arraycopy(H, 0, session_ids, 0, H.length);
        }
        buf.reset();
        buf.putValue(K);
        buf.putBytes(H);
        buf.putByte((byte) 0x41);
        buf.putBytes(session_ids);
        int j = buf.get_put() - session_ids.length - 1;        
        sha.update(buf.buffer, 0, buf.get_put());
        IVc2s = digest_trunc_len(sha.digest(), 16);
        buf.buffer[j]++;
        sha.update(buf.buffer, 0, buf.get_put());
        IVs2c = digest_trunc_len(sha.digest(), 16);
        buf.buffer[j]++;
        sha.update(buf.buffer, 0, buf.get_put());
        Ec2s = digest_trunc_len(sha.digest(), 32);
        buf.buffer[j]++;
        sha.update(buf.buffer, 0, buf.get_put());
        Es2c = digest_trunc_len(sha.digest(), 32);
        buf.buffer[j]++;
        sha.update(buf.buffer, 0, buf.get_put());
        MACc2s = digest_trunc_len(sha.digest(), 20);
        buf.buffer[j]++;
        sha.update(buf.buffer, 0, buf.get_put());
        MACs2c = digest_trunc_len(sha.digest(), 20);
        try{
            s2ccipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            s2ccipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(Es2c, "AES"), new javax.crypto.spec.IvParameterSpec(IVs2c));
            s2ccipher_size = 16;
            s2cmac = javax.crypto.Mac.getInstance("HmacSHA1");
            s2cmac.init(new javax.crypto.spec.SecretKeySpec(MACs2c, "HmacSHA1"));
            s2cmac_result1 = new byte[20];
            s2cmac_result2 = new byte[20];
            c2scipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            c2scipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(Ec2s, "AES"), new javax.crypto.spec.IvParameterSpec(IVc2s));
            c2scipher_size = 16;
            c2smac = javax.crypto.Mac.getInstance("HmacSHA1");
            c2smac.init(new javax.crypto.spec.SecretKeySpec(MACc2s, "HmacSHA1"));
        }catch (Exception e){
            throw new Exception("ex_149 - " + e.toString());
        }
    }
    private byte[] digest_trunc_len(byte[] digest, int len){
        if (digest.length <= len)
            return digest;
        byte [] a = new byte[len];
        System.arraycopy(digest, 0, a, 0, a.length);
        return a;
    }
    public void write(Buf buf) throws Exception {
        if (c2scipher == null) {
            buf.padding(8);
        }else{
            buf.padding(c2scipher_size);
            int pad = buf.buffer[4];
            int put = buf.get_put();
            byte[] a = new byte[16];
            if (pad > 16)
                a = new byte[pad];
            Buf.random.nextBytes(a);
            System.arraycopy(a, 0, buf.buffer, put - pad, pad);
            a = new byte[4];
            a[0] = (byte)(seqo >>> 24);
            a[1] = (byte)(seqo >>> 16);
            a[2] = (byte)(seqo >>> 8);
            a[3] = (byte) seqo;
            c2smac.update(a);
            c2smac.update(buf.buffer, 0, buf.get_put());
            c2smac.doFinal(buf.buffer, buf.get_put());
            c2scipher.update(buf.buffer, 0, buf.get_put(), buf.buffer, 0);            
            buf.skip_put(20);
        }
        put_stream(buf);
        seqo++;
    }
    public void put_stream(Buf buf) throws java.io.IOException, java.net.SocketException {
        //////////// 
        out.write(buf.buffer, 0, buf.get_put());
        out.flush();
    }
    void put_stream(byte[] array) throws java.io.IOException {
        out.write(array, 0, array.length);
        out.flush();
    }
    int getByte() throws java.io.IOException {
        return in.read();
    }
    void getByte(byte[] array, int begin, int length, int identity) throws java.io.IOException {
        while (length > 0){
            int completed = in.read(array, begin, length);            
            begin += completed;
            length -= completed;
        }
    }

    public void connect() throws Exception {
        Buf buf=new Buf(new byte[100]);
        buf.reset_packet();
        buf.putByte((byte) 90);
        buf.putValue(str2byte("session", "UTF-8"));
        buf.putInt(0);
        buf.putInt(0x100000);
        buf.putInt(0x4000);
        write(buf);
        
        int limit=3000;
        while(limit-->0 && !channel_opened )
            try { Thread.sleep(10); } catch (Exception e) {};        
        if ( !channel_opened )
            throw new Exception("channel is not opened.");        
        int tcol = 10000;//80;
        int trow = 24;
        int twp = 640;
        int thp = 480;
                
        buf.reset_packet();
        buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putValue(str2byte("pty-req", "UTF-8"));
        buf.putByte((byte) 0);
        buf.putValue(str2byte("vt100", "UTF-8"));
        buf.putInt(tcol);
        buf.putInt(trow);
        buf.putInt(twp);
        buf.putInt(thp);
        buf.putValue(str2byte("", "UTF-8"));
        write(buf);
        
        buf.reset_packet();
        buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putValue(str2byte("shell", "UTF-8"));        
        buf.putByte((byte) 0);
        write(buf);
    }
    public void working(){
        ///////////
        // ponto critico!!
        Buf buf=new Buf(new byte[rmpsize]);
        try {
            int i=0;
            while ( (i = System.in.read(buf.buffer, 14, buf.buffer.length -14 -(ECDH.nn_cipher+64))) >= 0 ){            
                // input send
                //System.out.write("[".getBytes());
                //System.out.write(buf.buffer, 14, i);
                //System.out.write("]".getBytes());                
                count_line_return=0;
                if (i == 0)
                    continue;
                buf.reset_packet();
                buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                buf.putInt(0);
                buf.putInt(i);
                buf.skip_put(i);                
                if ( get_rwsize() > i )
                    rwsize_substract(i);
                else
                    rwsize_substract(get_rwsize());
                write(buf);
            }
        } catch (Exception e) {
            System.out.println("ex_20");
        }        
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
    void put(byte[] array, int begin, int length) throws Exception {
        System.out.write(array, begin, length);
        System.out.flush();
    }    
    byte[] str2byte(String str, String encoding) {
        if (str == null) return null;
        try {
            return str.getBytes(encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            System.err.println("..Util UnsupportedEncodingException " + e);
            return str.getBytes();
        }
    }       
}