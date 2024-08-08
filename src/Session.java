class Session{
    final int SSH_MSG_DISCONNECT = 1;
    final int SSH_MSG_IGNORE = 2;
    final int SSH_MSG_UNIMPLEMENTED = 3;
    final int SSH_MSG_DEBUG = 4;
    final int SSH_MSG_SERVICE_REQUEST = 5;
    final int SSH_MSG_KEXINIT = 20;
    final int SSH_MSG_NEWKEYS = 21;
    final int SSH_MSG_KEXDH_INIT = 30;
    final int SSH_MSG_KEXDH_REPLY = 31;
    final int SSH_MSG_KEX_DH_GEX_GROUP = 31;
    final int SSH_MSG_KEX_DH_GEX_INIT = 32;
    final int SSH_MSG_KEX_DH_GEX_REPLY = 33;
    final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;
    final int SSH_MSG_USERAUTH_REQUEST = 50;
    final int SSH_MSG_USERAUTH_FAILURE = 51;
    final int SSH_MSG_USERAUTH_BANNER = 53;
    final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
    final int SSH_MSG_GLOBAL_REQUEST = 80;
    final int SSH_MSG_REQUEST_SUCCESS = 81;
    final int SSH_MSG_REQUEST_FAILURE = 82;
    final int SSH_MSG_CHANNEL_OPEN = 90;
    final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    final int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
    final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    final int SSH_MSG_CHANNEL_DATA = 94;
    final int SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
    final int SSH_MSG_CHANNEL_EOF = 96;
    final int SSH_MSG_CHANNEL_CLOSE = 97;
    final int SSH_MSG_CHANNEL_REQUEST = 98;
    final int SSH_MSG_CHANNEL_SUCCESS = 99;
    final int SSH_MSG_CHANNEL_FAILURE = 100;
    private byte[] V_S;
    private byte[] V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
    private byte[] I_C;
    private byte[] I_S;
    private byte[] session_ids;    
    private javax.crypto.Cipher reader_cipher;
    private javax.crypto.Mac reader_mac;    
    private javax.crypto.Cipher writer_cipher;
    private javax.crypto.Mac writer_mac;
    private int writer_seq = 0;    
    private java.net.Socket socket;    
    private int reader_cipher_size = 8;
    Buf _buf;
    byte barra_r=new byte[]{13}[0];
    byte barra_n=new byte[]{10}[0];
    java.io.InputStream in = null;
    java.io.OutputStream out = null;
    private long rwsize = 0;
    private boolean channel_opened=false;
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
            out.write(V_C, 0, V_C.length);
            out.write(barra_n);
            out.flush();
            
            while(true){
                i = 0;
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
            ECDH kex = receive_kexinit(read());
            _buf = read();
            kex.next(_buf);
            _buf.reset_command(SSH_MSG_NEWKEYS);
            write(_buf);
            _buf = read();
            if (_buf.getCommand() != SSH_MSG_NEWKEYS )
                throw new Exception("invalid protocol(newkyes): " + _buf.getCommand());
            receive_newkeys(_buf, kex);
            _buf.reset_command(SSH_MSG_SERVICE_REQUEST);
            _buf.putValue("ssh-userauth".getBytes("UTF-8"));
            write(_buf);
            _buf = read();
            _buf.reset_command(SSH_MSG_USERAUTH_REQUEST);
            _buf.putValue(username.getBytes("UTF-8"));
            _buf.putValue("ssh-connection".getBytes("UTF-8"));
            _buf.putValue("password".getBytes("UTF-8"));
            _buf.putByte((byte) 0);
            _buf.putValue(password.getBytes("UTF-8"));
            write(_buf);
            _buf = read();
            int command = _buf.getCommand() & 0xff;
            if (command == SSH_MSG_USERAUTH_FAILURE)
                throw new Exception("UserAuth Fail!");
            if (command == SSH_MSG_USERAUTH_BANNER || command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ )
                throw new Exception("USERAUTH BANNER or PASSWD_CHANGEREQ");
        }catch(Exception e){
            throw new Exception("Error Session 224 " + e.toString());
        }
    }

    public void working_stream(){
        Buf buf=new Buf();
        try {
            while(true) {
                try{
                    buf = read();
                }catch (java.io.InterruptedIOException ee){
                    throw new Exception("Error Session 261 " + ee);
                }
                int msgType = buf.getCommand() & 0xff;        
                if ( msgType == SSH_MSG_CHANNEL_DATA){
                    buf.getInt();
                    buf.getByte();
                    buf.getByte();
                    buf.getInt();
                    byte[] a = buf.getValue();
                    if (a.length == 0)
                        System.exit(0);
                    try {
                        // ponto critico retorno out
                        // enviando ls ele só retorna ls
                        // analisando o send, dá para observar que ele manda o dado
                        // ainda não sei porque ele nao me responde corretamente.
                        ///////////                                    
                        if ( can_print(a.length) ){
                            System.out.write(a);
                            System.out.flush();                            
                        }
                    } catch (Exception e) {
                        throw new Exception("Error Session 287 " + e);                                    
                    }
                    continue;
                }
                if ( msgType == SSH_MSG_CHANNEL_OPEN_CONFIRMATION){
                    buf.getInt();
                    buf.getShort();
                    buf.getInt();
                    buf.getInt();
                    buf.getInt();
                    int rps = buf.getInt();
                    channel_opened=true;
                    set_rwsize(0);
                    set_rmpsize(rps);                        
                    continue;
                }
                if ( msgType == SSH_MSG_GLOBAL_REQUEST ){
                    buf.getInt();
                    buf.getShort();
                    buf.getValue();
                    if (buf.getByte() != 0) {
                        buf.reset_command(SSH_MSG_REQUEST_FAILURE);
                        write(buf);
                    }
                    continue;
                }
                if ( msgType == SSH_MSG_CHANNEL_EOF ){
                    System.exit(0);
                }
                throw new Exception("msgType " + msgType+" not found. - Only 4 msgType implementations");
            }
        } catch (Exception e) {
            System.out.println("ex_151 " + e.toString());
            System.exit(1);
        }
        System.exit(0);
    }

    private void send_kexinit() throws Exception {
        Buf buf = new Buf();
        buf.reset_command(SSH_MSG_KEXINIT);
        int start_fill = buf.get_put();
        byte[] a = new byte[16];
        Buf.random.nextBytes(a);
        System.arraycopy(a, 0, buf.buffer, start_fill, a.length);
        buf.skip_put(16);
        buf.putValue(("ecdh-sha2-nistp" + ECDH.key_size).getBytes("UTF-8"));
        buf.putValue(("ssh-rsa,ecdsa-sha2-nistp" + ECDH.key_size).getBytes("UTF-8"));
        buf.putValue("aes256-ctr".getBytes("UTF-8"));
        buf.putValue("aes256-ctr".getBytes("UTF-8"));
        buf.putValue("hmac-sha1".getBytes("UTF-8"));
        buf.putValue("hmac-sha1".getBytes("UTF-8"));
        buf.putValue("none".getBytes("UTF-8"));
        buf.putValue("none".getBytes("UTF-8"));
        buf.putValue("".getBytes("UTF-8"));
        buf.putValue("".getBytes("UTF-8"));
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

    private void receive_newkeys(Buf buf, ECDH kex) throws Exception {
        try{
            byte[] K = kex.getK();
            byte[] H = kex.getH();
            java.security.MessageDigest sha = kex.getHash();
            if (session_ids == null) {
                session_ids = new byte[H.length];
                System.arraycopy(H, 0, session_ids, 0, H.length);
            }
            buf=new Buf();
            buf.putValue(K);
            buf.putBytes(H);
            buf.putByte((byte) 0x41);
            buf.putBytes(session_ids);
            int j = buf.get_put() - session_ids.length - 1;        
            sha.update(buf.buffer, 0, buf.get_put());
            byte[] _writer_cipher_IV = digest_trunc_len(sha.digest(), 16);
            buf.buffer[j]++;
            sha.update(buf.buffer, 0, buf.get_put());
            byte[] _reader_cipher_IV = digest_trunc_len(sha.digest(), 16);
            buf.buffer[j]++;
            sha.update(buf.buffer, 0, buf.get_put());
            byte[] _writer_cipher = digest_trunc_len(sha.digest(), 32);
            buf.buffer[j]++;
            sha.update(buf.buffer, 0, buf.get_put());
            byte[] _reader_cipher = digest_trunc_len(sha.digest(), 32);
            buf.buffer[j]++;
            sha.update(buf.buffer, 0, buf.get_put());
            byte[] _writer_mac = digest_trunc_len(sha.digest(), 20);
            buf.buffer[j]++;
            sha.update(buf.buffer, 0, buf.get_put());
            byte[] _reader_mac = digest_trunc_len(sha.digest(), 20);
            writer_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            writer_cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(_writer_cipher, "AES"), new javax.crypto.spec.IvParameterSpec(_writer_cipher_IV));
            writer_mac = javax.crypto.Mac.getInstance("HmacSHA1");
            writer_mac.init(new javax.crypto.spec.SecretKeySpec(_writer_mac, "HmacSHA1"));
            reader_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            reader_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(_reader_cipher, "AES"), new javax.crypto.spec.IvParameterSpec(_reader_cipher_IV));
            reader_cipher_size = 16;
            reader_mac = javax.crypto.Mac.getInstance("HmacSHA1");
            reader_mac.init(new javax.crypto.spec.SecretKeySpec(_reader_mac, "HmacSHA1"));            
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

    public Buf read() throws Exception {        
        Buf buf=new Buf();
        while(true){
            buf=new Buf();
            getByte(buf.buffer, buf.get_put(), reader_cipher_size, 1);
            buf.skip_put(reader_cipher_size);
            if (reader_cipher != null)
                reader_cipher.update(buf.buffer, 0, reader_cipher_size, buf.buffer, 0);
            int need = (((buf.buffer[0] << 24) & 0xff000000) | ((buf.buffer[1] << 16) & 0x00ff0000) | ((buf.buffer[2] << 8) & 0x0000ff00) | ((buf.buffer[3]) & 0x000000ff)) + 4 - reader_cipher_size;
            if ((buf.get_put() + need) > buf.buffer.length) {
                byte[] a = new byte[buf.get_put() + need];
                System.arraycopy(buf.buffer, 0, a, 0, buf.get_put());
                buf.buffer = a;
            }
            if (need > 0) {
                getByte(buf.buffer, buf.get_put(), need, 2);
                buf.skip_put(need);
                if (reader_cipher != null)
                    reader_cipher.update(buf.buffer, reader_cipher_size, need, buf.buffer, reader_cipher_size);
            }            
            if (reader_mac != null) {
                reader_mac.update(buf.buffer, 0, buf.get_put());
                getByte(new byte[20], 0, 20, 3);
            }           
            int type = buf.getCommand() & 0xff;
            if (type == SSH_MSG_DISCONNECT)
                System.exit(0);
            if ( type != SSH_MSG_IGNORE && type != SSH_MSG_UNIMPLEMENTED && type != SSH_MSG_DEBUG && type != SSH_MSG_CHANNEL_WINDOW_ADJUST )
                break;
        }
        buf.reset_get();
        return buf;
    }
    
    public void write(Buf buf) throws Exception {
        if (writer_cipher == null) {
            buf.padding(8);
        }else{
            buf.padding(16);
            int pad = buf.buffer[4];
            int put = buf.get_put();
            byte[] a = new byte[16];
            if (pad > 16)
                a = new byte[pad];
            Buf.random.nextBytes(a);
            System.arraycopy(a, 0, buf.buffer, put - pad, pad);
            a = new byte[4];
            a[0] = (byte)(writer_seq >> 24);
            a[1] = (byte)(writer_seq >> 16);
            a[2] = (byte)(writer_seq >> 8);
            a[3] = (byte) writer_seq;
            writer_mac.update(a);
            writer_mac.update(buf.buffer, 0, buf.get_put());
            writer_mac.doFinal(buf.buffer, buf.get_put());
            writer_cipher.update(buf.buffer, 0, buf.get_put(), buf.buffer, 0);            
            buf.skip_put(20);
        }
        out.write(buf.buffer, 0, buf.get_put());
        out.flush();
        writer_seq++;
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
        buf.reset_command(SSH_MSG_CHANNEL_OPEN);
        buf.putValue("session".getBytes("UTF-8"));
        buf.putInt(0);
        buf.putInt(0x100000);
        buf.putInt(0x4000);
        write(buf);
        
        int limit=3000;
        while( limit-->0 && !channel_opened )
            try { Thread.sleep(10); } catch (Exception e) {};        
        if ( !channel_opened )
            throw new Exception("channel is not opened.");        
        int tcol = 10000;//80;
        int trow = 24;
        int twp = 640;
        int thp = 480;
                
        buf.reset_command(SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putValue("pty-req".getBytes("UTF-8"));
        buf.putByte((byte) 0);
        buf.putValue("vt100".getBytes("UTF-8"));
        buf.putInt(tcol);
        buf.putInt(trow);
        buf.putInt(twp);
        buf.putInt(thp);
        buf.putValue("".getBytes("UTF-8"));
        write(buf);
        
        buf.reset_command(SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putValue("shell".getBytes("UTF-8"));
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
                buf.reset_command(SSH_MSG_CHANNEL_DATA);
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
        rmpsize = a;
    }
}