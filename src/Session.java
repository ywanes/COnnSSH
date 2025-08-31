class Session{
    final int SSH_MSG_DISCONNECT = 1;
    final int SSH_MSG_IGNORE = 2;
    final int SSH_MSG_UNIMPLEMENTED = 3;
    final int SSH_MSG_DEBUG = 4;
    final int SSH_MSG_SERVICE_REQUEST = 5;
    final int SSH_MSG_KEXINIT = 20;
    final int SSH_MSG_NEWKEYS = 21;
    final int SSH_MSG_KEXDH_INIT = 30;
    final int SSH_MSG_USERAUTH_REQUEST = 50;
    final int SSH_MSG_USERAUTH_FAILURE = 51;
    final int SSH_MSG_USERAUTH_BANNER = 53;
    final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
    final int SSH_MSG_GLOBAL_REQUEST = 80;
    final int SSH_MSG_REQUEST_FAILURE = 82;
    final int SSH_MSG_CHANNEL_OPEN = 90;
    final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
    final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
    final int SSH_MSG_CHANNEL_DATA = 94;
    final int SSH_MSG_CHANNEL_EOF = 96;
    final int SSH_MSG_CHANNEL_REQUEST = 98;
    public byte[] V_S;
    public byte[] V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
    public byte[] I_C;
    public byte[] I_S;
    public javax.crypto.Cipher reader_cipher;
    public javax.crypto.Mac reader_mac;    
    public javax.crypto.Cipher writer_cipher;
    public javax.crypto.Mac writer_mac;
    public int writer_seq = 0;        
    public int reader_cipher_size = 8;
    byte barra_r=new byte[]{13}[0];
    byte barra_n=new byte[]{10}[0];
    java.io.InputStream in = null;
    java.io.OutputStream out = null;
    public boolean channel_opened=false;
    public int rmpsize = 0;
    boolean verbose=1==2?true:false;
    public ECDH kex=null;
    java.security.SecureRandom random = null;
    
    public int count_line_return=-1;
    public boolean can_print(byte [] a){
        if ( count_line_return == -1 )
            return true;
        count_line_return++;        
        if ( count_line_return == 1 )
            return false;
        if ( count_line_return == 2 && a.length == 1 && (int)a[0] == 10 )
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
        Buf buf = new Buf();
        int i, j;
        try{
            java.net.Socket socket = new java.net.Socket(host, port);
            in = socket.getInputStream();
            out = socket.getOutputStream();
        }catch(Exception e){
            throw new Exception("Error session connect socket " + e);
        }
        out.write(V_C, 0, V_C.length);
        out.write(barra_n);
        out.flush();
        i = 0;
        while( (j = in.read(buf.buffer, i, 1)) > 0 ){
            if ( i > 0 && buf.buffer[i-1] == barra_r && buf.buffer[i] == barra_n ){
                i--;
                break;
            }
            i++;
        }
        V_S = new byte[i];
        System.arraycopy(buf.buffer, 0, V_S, 0, i);
        debug("connect stream <-: ", V_S); // SSH-2.0-OpenSSH_for_Windows_8.1
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXINIT);
        int start_fill = buf.i_put;
        byte[] a = get_random_bytes(16);
        System.arraycopy(a, 0, buf.buffer, start_fill, a.length);
        buf.i_put+=16;
        buf.putValue(("ecdh-sha2-nistp521").getBytes("UTF-8"));
        buf.putValue(("ssh-rsa,ecdsa-sha2-nistp521").getBytes("UTF-8"));
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
        buf.i_get=5;
        I_C = buf.getValueAllLen();
        write(buf);
        debug("connect stream ->: ", buf);

        buf = read();
        j = buf.getInt();
        if (j != (buf.i_put - buf.i_get)){
            buf.getByte();
            I_S = new byte[buf.i_put - 5];
        }else
            I_S = new byte[j - 1 - buf.getByte()];
        System.arraycopy(buf.buffer, buf.i_get, I_S, 0, I_S.length);
        debug("connect stream <-: ", I_S);

        kex.init(V_S, V_C, I_S, I_C);
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXDH_INIT);
        buf.putValue(kex.Q_C);
        write(buf);
        debug("connect stream ->: ", buf);
        // as vezes falha aqui "java.net.SocketException: Connection reset"
        buf = read();
        kex.next(buf);
        buf.reset_command(SSH_MSG_NEWKEYS);
        write(buf);
        buf = read();
        if (buf.getCommand() != SSH_MSG_NEWKEYS )
            throw new Exception("invalid protocol(newkyes): " + buf.getCommand());            

        buf=new Buf();
        buf.putValue(kex.K);
        buf.putBytes(kex.H);
        buf.putByte((byte) 0x41);
        buf.putBytes(kex.H);
        j = buf.i_put - kex.H.length - 1;        
        kex.sha.update(buf.buffer, 0, buf.i_put);
        byte[] _writer_cipher_IV = digest_trunc_len(kex.sha.digest(), 16);
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        byte[] _reader_cipher_IV = digest_trunc_len(kex.sha.digest(), 16);
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        byte[] _writer_cipher = digest_trunc_len(kex.sha.digest(), 32);
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        byte[] _reader_cipher = digest_trunc_len(kex.sha.digest(), 32);
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        byte[] _writer_mac = digest_trunc_len(kex.sha.digest(), 20);
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
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
        buf.reset_command(SSH_MSG_SERVICE_REQUEST);
        buf.putValue("ssh-userauth".getBytes("UTF-8"));
        write(buf);
        
        // as vezes falha aqui "java.net.SocketException: Connection reset"
        buf = read();
        buf.reset_command(SSH_MSG_USERAUTH_REQUEST);
        buf.putValue(username.getBytes("UTF-8"));
        buf.putValue("ssh-connection".getBytes("UTF-8"));
        buf.putValue("password".getBytes("UTF-8"));
        buf.putByte((byte) 0);
        buf.putValue(password.getBytes("UTF-8"));
        write(buf);

        buf = read();
        int command = buf.getCommand();
        if (command == SSH_MSG_USERAUTH_FAILURE)
            throw new Exception("UserAuth Fail!");
        if (command == SSH_MSG_USERAUTH_BANNER || command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ )
            throw new Exception("USERAUTH BANNER or PASSWD_CHANGEREQ");
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
        try {
            Buf buf=new Buf();
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
                    if ( texto_oculto(a) )// ocorre no começo e fim de cada interação
                        continue;                            
                    ////////////////
                    // recebendo texto
                    if ( can_print(a) ){
                        System.out.write(a);
                        System.out.flush();                                                        
                        //mostra_bytes(a);
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
                if ( msgType == SSH_MSG_CHANNEL_EOF )
                    System.exit(0);
                System.err.println("msgType " + msgType+" not found. - Only 4 msgType implementations");
                System.exit(1);
            }
        } catch (Exception e) {
            System.out.println("ex_3 " + e.toString());
            System.exit(1);
        }
    }
    
    private byte[] digest_trunc_len(byte[] digest, int len){
        if (digest.length <= len)
            return digest;
        byte [] a = new byte[len];
        System.arraycopy(digest, 0, a, 0, a.length);
        return a;
    }

    public byte [] get_random_bytes(int n){
        if ( random == null )
            random = new java.security.SecureRandom();
        byte[] a = new byte[n];        
        random.nextBytes(a);
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
            if (type == SSH_MSG_DISCONNECT)
                System.exit(0);
            if ( type != SSH_MSG_IGNORE && type != SSH_MSG_UNIMPLEMENTED && type != SSH_MSG_DEBUG && type != SSH_MSG_CHANNEL_WINDOW_ADJUST )
                break;
        }
        buf.i_get=0;
        return buf;
    }
        
    public void write(Buf buf) throws Exception {
        int len = buf.i_put;
        int pad = (-len) & (15);
        if (pad < 16)
            pad += 16;
        len = len + pad - 4;
        buf.buffer[0] = (byte)(len >> 24);
        buf.buffer[1] = (byte)(len >> 16);
        buf.buffer[2] = (byte)(len >> 8);
        buf.buffer[3] = (byte)len;
        buf.buffer[4] = (byte) pad;
        System.arraycopy(new byte[pad>16?pad:16], 0, buf.buffer, buf.i_put, pad);
        buf.i_put+=pad;
        if (writer_cipher != null) {
            pad = buf.buffer[4];
            int put = buf.i_put;
            System.arraycopy(get_random_bytes(pad>16?pad:16), 0, buf.buffer, put - pad, pad);
            writer_mac.update(new byte[]{(byte)(writer_seq >> 24), (byte)(writer_seq >> 16), (byte)(writer_seq >> 8), (byte)writer_seq});
            writer_mac.update(buf.buffer, 0, buf.i_put);
            writer_mac.doFinal(buf.buffer, buf.i_put);
            writer_cipher.update(buf.buffer, 0, buf.i_put, buf.buffer, 0);            
            buf.i_put+=20;
        }
        out.write(buf.buffer, 0, buf.i_put);
        out.flush();
        writer_seq++;
    }
    
    public void connect_stdin() throws Exception{
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
    
    public void writing_stdin() throws Exception{
        Buf buf=new Buf(new byte[rmpsize]);
        int i=0;
        int off=14;
        /////////////////
        // enviando texto
        while ( (i = System.in.read(buf.buffer, off, buf.buffer.length -off -128)) >= 0 ){                                            
            if ( buf.buffer[i-2+off] != barra_r || buf.buffer[i-1+off] != barra_n ){ // linux fazendo \r\n para ssh windows
                i++;
                buf.buffer[i-2+off]=barra_r;
                buf.buffer[i-1+off]=barra_n;
            }
            for ( int j=0;j<off;j++ )
                buf.buffer[j]=0;
            debug(buf.buffer, off, i); // input text debug
            count_line_return=0;
            if (i == 0)
                continue;
            buf.reset_command(SSH_MSG_CHANNEL_DATA);
            buf.putInt(0);
            buf.putInt(i);
            buf.i_put+=i;                
            write(buf);
        }
    }

    private void debug(String a, byte[] b) {
        if ( verbose ){
            System.out.println(a + new String(b));        
            System.out.flush();
        }
    }

    private void debug(String a, Buf buf) {
        if ( verbose ){
            System.out.print(a);
            System.out.write(buf.buffer, 0, buf.i_put);
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