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
    public byte[] V_S;
    public byte[] V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
    public byte[] I_C;
    public byte[] I_S;
    public javax.crypto.Cipher reader_cipher;
    public javax.crypto.Mac reader_mac;    
    public javax.crypto.Cipher writer_cipher;
    public javax.crypto.Mac writer_mac;
    public int writer_seq = 0;    
    public java.net.Socket socket;    
    public int reader_cipher_size = 8;
    Buf _buf;
    byte barra_r=new byte[]{13}[0];
    byte barra_n=new byte[]{10}[0];
    java.io.InputStream in = null;
    java.io.OutputStream out = null;
    public boolean channel_opened=false;
    public int rmpsize = 0;
    boolean verbose=1==2?true:false;
    public ECDH kex=null;

    public int count_line_return=-1;
    public boolean can_print(int len, int first){
        if ( count_line_return == -1 )
            return true;
        count_line_return++;        
        if ( count_line_return == 1 )
            return false;
        if ( count_line_return == 2 && len == 1 && first == 10 )
            return false;  
        return true;
    }    
    
    Session(String host, String username, int port, String password) throws Exception {                
        kex=new ECDH();
        connect_stream(host, username, port, password);
        new Thread(){public void run(){
            reading_stream();
        }}.start();                
        connect_stdin();
        writing_stdin(); // send msg by keyboard
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
            out.write(V_C, 0, V_C.length);
            out.write(barra_n);
            out.flush();
            i = 0;
            while( (j = in.read(_buf.buffer, i, 1)) > 0 ){
                if ( i > 0 && _buf.buffer[i-1] == barra_r && _buf.buffer[i] == barra_n ){
                    i--;
                    break;
                }
                i++;
            }
            V_S = new byte[i];
            System.arraycopy(_buf.buffer, 0, V_S, 0, i);
            debug("connect stream <-: ", V_S); // SSH-2.0-OpenSSH_for_Windows_8.1
            _buf = new Buf();
            _buf.reset_command(SSH_MSG_KEXINIT);
            int start_fill = _buf.i_put;//_buf.i_put;
            byte[] a = new byte[16];
            _buf.random.nextBytes(a);
            System.arraycopy(a, 0, _buf.buffer, start_fill, a.length);
            _buf.i_put+=16;
            _buf.putValue(("ecdh-sha2-nistp" + kex.key_size).getBytes("UTF-8"));
            _buf.putValue(("ssh-rsa,ecdsa-sha2-nistp" + kex.key_size).getBytes("UTF-8"));
            _buf.putValue("aes256-ctr".getBytes("UTF-8"));
            _buf.putValue("aes256-ctr".getBytes("UTF-8"));
            _buf.putValue("hmac-sha1".getBytes("UTF-8"));
            _buf.putValue("hmac-sha1".getBytes("UTF-8"));
            _buf.putValue("none".getBytes("UTF-8"));
            _buf.putValue("none".getBytes("UTF-8"));
            _buf.putValue("".getBytes("UTF-8"));
            _buf.putValue("".getBytes("UTF-8"));
            _buf.putByte((byte) 0);
            _buf.putInt(0);
            _buf.i_get=5;
            I_C = _buf.getValueAllLen();
            write(_buf);
            debug("connect stream ->: ", _buf);
            
            _buf = read();
            j = _buf.getInt();
            if (j != (_buf.i_put - _buf.i_get)){
                _buf.getByte();
                I_S = new byte[_buf.i_put - 5];
            }else
                I_S = new byte[j - 1 - _buf.getByte()];
            System.arraycopy(_buf.buffer, _buf.i_get, I_S, 0, I_S.length);
            debug("connect stream <-: ", I_S);
            
            kex.init(V_S, V_C, I_S, I_C);
            _buf = new Buf();
            _buf.reset_command(SSH_MSG_KEXDH_INIT);
            _buf.putValue(kex.Q_C);
            write(_buf);
            debug("connect stream ->: ", _buf);
            _buf = read();
            kex.next(_buf);
            _buf.reset_command(SSH_MSG_NEWKEYS);
            write(_buf);
            
            _buf = read();
            if (_buf.getCommand() != SSH_MSG_NEWKEYS )
                throw new Exception("invalid protocol(newkyes): " + _buf.getCommand());            
            
            _buf=new Buf();
            _buf.putValue(kex.K);
            _buf.putBytes(kex.H);
            _buf.putByte((byte) 0x41);
            _buf.putBytes(kex.H);
            j = _buf.i_put - kex.H.length - 1;        
            kex.sha.update(_buf.buffer, 0, _buf.i_put);
            byte[] _writer_cipher_IV = digest_trunc_len(kex.sha.digest(), 16);
            _buf.buffer[j]++;
            kex.sha.update(_buf.buffer, 0, _buf.i_put);
            byte[] _reader_cipher_IV = digest_trunc_len(kex.sha.digest(), 16);
            _buf.buffer[j]++;
            kex.sha.update(_buf.buffer, 0, _buf.i_put);
            byte[] _writer_cipher = digest_trunc_len(kex.sha.digest(), 32);
            _buf.buffer[j]++;
            kex.sha.update(_buf.buffer, 0, _buf.i_put);
            byte[] _reader_cipher = digest_trunc_len(kex.sha.digest(), 32);
            _buf.buffer[j]++;
            kex.sha.update(_buf.buffer, 0, _buf.i_put);
            byte[] _writer_mac = digest_trunc_len(kex.sha.digest(), 20);
            _buf.buffer[j]++;
            kex.sha.update(_buf.buffer, 0, _buf.i_put);
            byte[] _reader_mac = digest_trunc_len(kex.sha.digest(), 20);
            writer_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            writer_cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(_writer_cipher, "AES"), new javax.crypto.spec.IvParameterSpec(_writer_cipher_IV));
            writer_mac = javax.crypto.Mac.getInstance("HmacSHA1");
            writer_mac.init(new javax.crypto.spec.SecretKeySpec(_writer_mac, "HmacSHA1"));
            reader_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
            reader_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(_reader_cipher, "AES"), new javax.crypto.spec.IvParameterSpec(_reader_cipher_IV));
            reader_cipher_size = 16;
            reader_mac = javax.crypto.Mac.getInstance("HmacSHA1");
            reader_mac.init(new javax.crypto.spec.SecretKeySpec(_reader_mac, "HmacSHA1"));                        
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
            int command = _buf.getCommand();
            if (command == SSH_MSG_USERAUTH_FAILURE)
                throw new Exception("UserAuth Fail!");
            if (command == SSH_MSG_USERAUTH_BANNER || command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ )
                throw new Exception("USERAUTH BANNER or PASSWD_CHANGEREQ");
        }catch(Exception e){
            throw new Exception("Error Session 224 " + e.toString());
        }
    }

    public boolean texto_oculto(byte [] a){
        // 033 ] 0 ; .... \a
        return a.length > 6 && (int)a[0] == 27 && (int)a[1] == 93 && (int)a[2] == 48 && (int)a[3] == 59 && (int)a[a.length-1] == 7;
    }
    public void mostra_bytes(byte [] a){
        String s="";
        for ( int i=0;i<a.length;i++ )
            s+=(int)a[i]+",";
        s="["+s+"]";
        System.out.println(s);
    }
    public void reading_stream(){
        Buf buf=new Buf();
        try {
            while(true) {
                buf = read();
                int msgType = buf.getCommand();
                if ( msgType == SSH_MSG_CHANNEL_DATA){
                    buf.getInt();
                    buf.getByte();
                    buf.getByte();
                    buf.getInt();
                    byte[] a = buf.getValue();
                    if (a.length == 0){
                        System.out.println("a.length == 0");
                        System.exit(0);
                    }
                    try {
                        if ( texto_oculto(a) )// ocorre no começo e fim de cada interação
                            continue;                            
                        ////////////////
                        // recebendo texto
                        if ( can_print(a.length, (int)a[0]) ){
                            System.out.write(a);
                            System.out.flush();                                                        
                            //mostra_bytes(a);
                        }
                    } catch (Exception e) {
                        throw new Exception("Error Session 287 " + e);                                    
                    }
                    continue;
                }
                if ( msgType == SSH_MSG_CHANNEL_OPEN_CONFIRMATION){
                    buf.getInt();
                    buf.getByte();
                    buf.getByte();
                    buf.getInt();
                    buf.getInt();
                    buf.getInt();
                    int rps = buf.getInt();
                    channel_opened=true;
                    rmpsize=rps;
                    continue;
                }
                if ( msgType == SSH_MSG_GLOBAL_REQUEST ){
                    buf.getInt();
                    buf.getByte();
                    buf.getByte();
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
            System.out.println("ex_3 " + e.toString());
            System.exit(1);
        }
        System.exit(0);
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
            in.read(buf.buffer, buf.i_put, reader_cipher_size);
            buf.i_put+=reader_cipher_size;
            if (reader_cipher != null)
                reader_cipher.update(buf.buffer, 0, reader_cipher_size, buf.buffer, 0);
            int need = (((buf.buffer[0] << 24) & 0xff000000) | ((buf.buffer[1] << 16) & 0x00ff0000) | ((buf.buffer[2] << 8) & 0x0000ff00) | ((buf.buffer[3]) & 0x000000ff)) + 4 - reader_cipher_size;
            if ((buf.i_put + need) > buf.buffer.length) {
                byte[] a = new byte[buf.i_put + need];
                System.arraycopy(buf.buffer, 0, a, 0, buf.i_put);
                buf.buffer = a;
            }
            if (need > 0) {
                in.read(buf.buffer, buf.i_put, need);
                buf.i_put+=need;
                if (reader_cipher != null)
                    reader_cipher.update(buf.buffer, reader_cipher_size, need, buf.buffer, reader_cipher_size);
            }            
            if (reader_mac != null) {
                reader_mac.update(buf.buffer, 0, buf.i_put);
                in.read(new byte[20], 0, 20);
            }           
            int type = buf.getCommand();
            if (type == SSH_MSG_DISCONNECT){
                System.exit(0);
            }
            if ( type != SSH_MSG_IGNORE && type != SSH_MSG_UNIMPLEMENTED && type != SSH_MSG_DEBUG && type != SSH_MSG_CHANNEL_WINDOW_ADJUST ){
                // 20, 31 /////////////////// SSH_MSG_KEXINIT = 20; SSH_MSG_NEWKEYS = 21; SSH_MSG_KEX_DH_GEX_GROUP = 31;
                //System.out.println("type? " + type);
                // muitas vezes para o programa após ocorrer um desses 3 types aqui
                break;
            }
        }
        buf.i_get=0;
        return buf;
    }
    
    public void write(Buf buf) throws Exception {
        if (writer_cipher == null) {
            buf.padding(8);
        }else{
            buf.padding(16);
            int pad = buf.buffer[4];
            int put = buf.i_put;
            byte[] a = new byte[16];
            if (pad > 16)
                a = new byte[pad];
            buf.random.nextBytes(a);
            System.arraycopy(a, 0, buf.buffer, put - pad, pad);
            a = new byte[4];
            a[0] = (byte)(writer_seq >> 24);
            a[1] = (byte)(writer_seq >> 16);
            a[2] = (byte)(writer_seq >> 8);
            a[3] = (byte) writer_seq;
            writer_mac.update(a);
            writer_mac.update(buf.buffer, 0, buf.i_put);
            writer_mac.doFinal(buf.buffer, buf.i_put);
            writer_cipher.update(buf.buffer, 0, buf.i_put, buf.buffer, 0);            
            buf.i_put+=20;
        }
        out.write(buf.buffer, 0, buf.i_put);
        out.flush();
        writer_seq++;
    }
    
    public void connect_stdin() throws Exception {
        Buf buf=new Buf();
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
    
    public void writing_stdin(){
        Buf buf=new Buf(new byte[rmpsize]);
        try {
            int i=0;
            int off=14;
            /////////////////
            // enviando texto
            while ( (i = System.in.read(buf.buffer, off, buf.buffer.length -off -(kex.nn_cipher+64))) >= 0 ){                                            
                if ( buf.buffer[i-2+off] != barra_r || buf.buffer[i-1+off] != barra_n ){ // linux fazendo \r\n para ssh windows
                    i++;
                    buf.buffer[i-2+14]=barra_r;
                    buf.buffer[i-1+14]=barra_n;
                }
                for ( int j=0;j<off;j++ )
                    buf.buffer[j]=0;
                debug(buf.buffer, 14, i); // input text debug
                count_line_return=0;
                if (i == 0)
                    continue;
                buf.reset_command(SSH_MSG_CHANNEL_DATA);
                buf.putInt(0);
                buf.putInt(i);
                buf.i_put+=i;                
                write(buf);
            }
        } catch (Exception e) {
            System.err.println("ex_1");
            System.exit(1);
        }        
    }

    private void debug(String a, byte[] b) {
        if ( verbose ){
            System.out.println(a + new String(b));        
            System.out.flush();
        }
    }

    private void debug(String a, Buf _buf) {
        if ( verbose ){
            System.out.print(a);
            System.out.write(_buf.buffer, 0, _buf.i_put);
            System.out.println();
            System.out.flush();
        }
    }

    private void debug(byte[] a, int i, int i0) throws Exception {
        if ( verbose ){
            System.out.write("[".getBytes());
            System.out.write(a, i, i0);
            System.out.write("]".getBytes());                
        }        
    }
}