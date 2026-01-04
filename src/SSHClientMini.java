/*
class SSHClientMini{
    final int SSH_MSG_DISCONNECT = 1, SSH_MSG_IGNORE = 2, SSH_MSG_UNIMPLEMENTED = 3, SSH_MSG_DEBUG = 4,
              SSH_MSG_SERVICE_REQUEST = 5, SSH_MSG_KEXINIT = 20, SSH_MSG_NEWKEYS = 21, SSH_MSG_KEXDH_INIT = 30,
              SSH_MSG_USERAUTH_REQUEST = 50, SSH_MSG_USERAUTH_FAILURE = 51, SSH_MSG_USERAUTH_BANNER = 53, 
              SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60, SSH_MSG_GLOBAL_REQUEST = 80, SSH_MSG_REQUEST_FAILURE = 82, 
              SSH_MSG_CHANNEL_OPEN = 90, SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91, SSH_MSG_CHANNEL_WINDOW_ADJUST = 93, 
              SSH_MSG_CHANNEL_DATA = 94, SSH_MSG_CHANNEL_EOF = 96, SSH_MSG_CHANNEL_REQUEST = 98;    
    private byte[] V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8"), V_S, I_C, I_S;
    private javax.crypto.Cipher reader_cipher, writer_cipher;
    private javax.crypto.Mac reader_mac, writer_mac;
    private int writer_seq = 0, reader_cipher_size = 8, rmpsize = 0;
    private byte barra_r=new byte[]{13}[0], barra_n=new byte[]{10}[0];
    private java.io.InputStream in = null;
    private java.io.OutputStream out = null;
    private boolean channel_opened=false;
    private boolean verbose=true; // true/false
    private ECDH kex=null;
    private java.security.SecureRandom random = null;
        
    public SSHClientMini(String host, String username, int port, String password) throws Exception {                
        kex=new ECDH();
        connect_stream(host, username, port, password);
        new Thread(){public void run(){
            reading_stream();
        }}.start();   
        connect_stdin();
        writing_stdin(); // send msg by keyboard
    }
    
    private int count_line_return=-1;
    private boolean can_print(byte [] a){
        if ( count_line_return == -1 )
            return true;
        count_line_return++;        
        if ( count_line_return == 1 )
            return false;
        if ( count_line_return == 2 && a.length == 1 && (int)a[0] == 10 )
            return false;  
        return true;
    }    
    
    private void connect_stream(String host, String username, int port, String password) throws Exception{                
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
        buf.putString("ecdh-sha2-nistp256");        
        buf.putString("ssh-rsa,ecdsa-sha2-nistp256");
        buf.putString("aes256-ctr");
        buf.putString("aes256-ctr");
        buf.putString("hmac-sha2-256");
        buf.putString("hmac-sha2-256");
        buf.putString("none");
        buf.putString("none");
        buf.putInt(0);
        buf.putInt(0);
        buf.putByte((byte) 0);
        buf.putInt(0);
        buf.i_get=5;
        I_C = buf.getValueAllLen();
        write(buf);
        debug("connect stream ->: ", buf);

        buf = read();
        j = buf.getInt();
        if (j != (buf.i_put - buf.i_get)){
            buf.add_i_get(1);
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
        java.security.spec.AlgorithmParameterSpec writer_cipher_params = new javax.crypto.spec.IvParameterSpec(digest_trunc_len(kex.sha.digest(), 16));
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.spec.AlgorithmParameterSpec reader_cipher_params = new javax.crypto.spec.IvParameterSpec(digest_trunc_len(kex.sha.digest(), 16));
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key writer_cipher_key = new javax.crypto.spec.SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "AES");
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);        
        java.security.Key reader_cipher_key = new javax.crypto.spec.SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "AES");
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key writer_mac_key = new javax.crypto.spec.SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "HmacSHA256");
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key reader_mac_key = new javax.crypto.spec.SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "HmacSHA256");
        writer_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
        writer_cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, writer_cipher_key, writer_cipher_params);
        writer_mac = javax.crypto.Mac.getInstance("HmacSHA256");
        writer_mac.init(writer_mac_key);
        reader_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
        reader_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, reader_cipher_key, reader_cipher_params);
        reader_cipher_size = 16;
        reader_mac = javax.crypto.Mac.getInstance("HmacSHA256");
        reader_mac.init(reader_mac_key);
        buf.reset_command(SSH_MSG_SERVICE_REQUEST);
        buf.putString("ssh-userauth");
        write(buf);
        
        // as vezes falha aqui "java.net.SocketException: Connection reset"
        buf = read();
        buf.reset_command(SSH_MSG_USERAUTH_REQUEST);
        buf.putString(username);
        buf.putString("ssh-connection");
        buf.putString("password");
        buf.putByte((byte) 0);
        buf.putString(password);
        write(buf);

        buf = read();
        int command = buf.getCommand();
        if (command == SSH_MSG_USERAUTH_FAILURE)
            throw new Exception("UserAuth Fail!");
        if (command == SSH_MSG_USERAUTH_BANNER || command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ )
            throw new Exception("USERAUTH BANNER or PASSWD_CHANGEREQ");
    }

    private boolean texto_oculto(byte [] a){
        // 033 ] 0 ; .... \a
        return a.length > 6 && (int)a[0] == 27 && (int)a[1] == 93 && (int)a[2] == 48 && (int)a[3] == 59 && (int)a[a.length-1] == 7;
    }
    private void mostra_bytes(byte [] a){
        String s="";
        for ( int i=0;i<a.length;i++ )
            s+=(int)a[i]+",";
        s="["+s+"]";
        System.out.println(s);
    }
    private void reading_stream(){        
        try {
            Buf buf=new Buf();
            while(true) {
                buf = read();
                int msgType = buf.getCommand();
                if ( msgType == SSH_MSG_CHANNEL_DATA){
                    buf.add_i_get(10);
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
                    buf.add_i_get(18);
                    int rps = buf.getInt();
                    channel_opened=true;
                    rmpsize=rps;
                    continue;
                }
                if ( msgType == SSH_MSG_GLOBAL_REQUEST ){
                    buf.add_i_get(6);
                    buf.getValue();
                    if (buf.getByte() != 0) {
                        buf.reset_command(SSH_MSG_REQUEST_FAILURE);
                        write(buf);
                    }
                    continue;
                }
                if ( msgType == SSH_MSG_CHANNEL_EOF )
                    System.exit(0);
                System.err.println("msgType " + msgType + " not found. - Only 4 msgType implementations");
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

    private byte [] get_random_bytes(int n){
        if ( random == null )
            random = new java.security.SecureRandom();
        byte[] a = new byte[n];        
        random.nextBytes(a);
        return a;
    }
    
    private Buf read() throws Exception {        
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
                in.read(new byte[32], 0, 32);
            }           
            int type = buf.getCommand();
            if (type == SSH_MSG_DISCONNECT)
                System.exit(0);
            if ( type != SSH_MSG_IGNORE && type != SSH_MSG_UNIMPLEMENTED && type != SSH_MSG_DEBUG && type != SSH_MSG_CHANNEL_WINDOW_ADJUST ){
                //System.out.println("?? type " + type); ///////////////
                break;
            }else{
                //System.out.println("? type " + type); ///////////////
            }
        }
        buf.i_get=0;
        return buf;
    }
        
    private void write(Buf buf) throws Exception {
        int len = buf.i_put;
        int pad = (-len) & (15);
        if (pad < 16)
            pad += 16;
        len = len + pad - 4;
        buf.buffer[0] = (byte)(len >> 24);
        buf.buffer[1] = (byte)(len >> 16);
        buf.buffer[2] = (byte)(len >> 8);
        buf.buffer[3] = (byte)len;
        buf.buffer[4] = (byte)pad;
        System.arraycopy(new byte[pad>16?pad:16], 0, buf.buffer, buf.i_put, pad);
        buf.i_put+=pad;
        if (writer_cipher != null){
            pad = buf.buffer[4];
            int put = buf.i_put;
            System.arraycopy(get_random_bytes(pad>16?pad:16), 0, buf.buffer, put - pad, pad);
            writer_mac.update(new byte[]{(byte)(writer_seq >> 24), (byte)(writer_seq >> 16), (byte)(writer_seq >> 8), (byte)writer_seq});
            writer_mac.update(buf.buffer, 0, buf.i_put);
            byte[] mac = writer_mac.doFinal();
            System.arraycopy(mac, 0, buf.buffer, buf.i_put, 32);
            writer_cipher.update(buf.buffer, 0, buf.i_put, buf.buffer, 0);            
            buf.i_put+=32;
        }
        out.write(buf.buffer, 0, buf.i_put);
        out.flush();
        writer_seq++;
    }
    
    private void connect_stdin() throws Exception{
        Buf buf=new Buf();
        buf.reset_command(SSH_MSG_CHANNEL_OPEN);
        buf.putString("session");
        buf.putInt(0);
        buf.putInt(0x100000);
        buf.putInt(0x4000);
        write(buf);
        
        int limit=3000;
        while( limit-->0 && !channel_opened )
            try { Thread.sleep(10); } catch (Exception e) {};        
        if ( !channel_opened )
            throw new Exception("channel is not opened.");        
        buf.reset_command(SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putString("pty-req");
        buf.putByte((byte) 0);
        buf.putString("vt100");
        buf.putInt(10000); //tcol
        buf.putInt(24); // trow
        buf.putInt(640); // twp
        buf.putInt(480); // thp
        buf.putInt(0);
        write(buf);

        buf.reset_command(SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putString("shell");
        buf.putByte((byte) 0);
        write(buf);
    }
    
    private void writing_stdin() throws Exception{
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

class ECDH{    
    public byte[] K, H, Q_C;        
    private byte[] V_S, V_C, I_S, I_C;
    public java.security.MessageDigest sha = null;        
    private java.security.spec.ECParameterSpec params=null;
    private javax.crypto.KeyAgreement myKeyAgree = null;    

    public void init(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;        
        sha = java.security.MessageDigest.getInstance("SHA-256");
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.KeyPair kp = kpg.genKeyPair();
        java.security.PrivateKey privateKey = kp.getPrivate();
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) kp.getPublic();            
        params = publicKey.getParams();
        java.security.spec.ECPoint w = publicKey.getW();
        java.math.BigInteger x = w.getAffineX();
        java.math.BigInteger y = w.getAffineY();
        byte[] xBytes = toPaddedBytes(x, 32);
        byte[] yBytes = toPaddedBytes(y, 32);
        Q_C = new byte[1 + xBytes.length + yBytes.length];
        Q_C[0] = 4;        
        System.arraycopy(xBytes, 0, Q_C, 1, xBytes.length);
        System.arraycopy(yBytes, 0, Q_C, 1 + xBytes.length, yBytes.length);
        myKeyAgree = javax.crypto.KeyAgreement.getInstance("ECDH");
        myKeyAgree.init(privateKey);            
    }

    private byte[] toPaddedBytes(java.math.BigInteger bi, int length) {
        byte[] bytes = bi.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length > length) {
            if (bytes[0] == 0 && bytes.length == length + 1) {
                byte[] result = new byte[length];
                System.arraycopy(bytes, 1, result, 0, length);
                return result;
            }
        } else if (bytes.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        }
        return bytes;
    }
    
    public void next(Buf buf) throws Exception {
        buf.add_i_get(6);
        byte[] K_S = buf.getValue();
        byte[] Q_S = buf.getValue();
        if (Q_S[0] != 4)
            throw new Exception("Formato de ponto EC não suportado: " + Q_S[0]);
        int coordinateLength = 32;
        if (Q_S.length != 1 + coordinateLength * 2)
            coordinateLength = (Q_S.length - 1) / 2;
        byte[] xBytes = new byte[coordinateLength];
        byte[] yBytes = new byte[coordinateLength];
        System.arraycopy(Q_S, 1, xBytes, 0, coordinateLength);
        System.arraycopy(Q_S, 1 + coordinateLength, yBytes, 0, coordinateLength);
        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        java.math.BigInteger y = new java.math.BigInteger(1, yBytes);
        myKeyAgree.doPhase(
            java.security.KeyFactory.getInstance("EC").generatePublic(
                new java.security.spec.ECPublicKeySpec(
                    new java.security.spec.ECPoint(x, y), 
                    params
                )
            ), 
            true
        );
        K = myKeyAgree.generateSecret();
        buf=new Buf();
        buf.putValue(V_C);
        buf.putValue(V_S);
        buf.putValue(I_C);
        buf.putValue(I_S);
        buf.putValue(K_S);
        buf.putValue(Q_C);
        buf.putValue(Q_S);
        buf.putValue(K);
        sha.update(buf.getValueAllLen());
        H = sha.digest();
    }    
}

class Buf{
    byte[] buffer;
    int i_put, i_get;
    public Buf() {
        this(new byte[1024 * 10 * 2]);
    }
    public Buf(byte[] buffer) {
        this.buffer = buffer;
        i_put = i_get = 0;
    }
    public void putInt(int val) {
        buffer[i_put++] = (byte)(val >> 24);
        buffer[i_put++] = (byte)(val >> 16);
        buffer[i_put++] = (byte)(val >> 8);
        buffer[i_put++] = (byte)val;
    }
    public void putByte(byte a) {
        buffer[i_put++] = a;
    }
    public void putBytes(byte[] a) {
        System.arraycopy(a, 0, buffer, i_put, a.length);
        i_put+=a.length;
    }
    public void putValue(byte[] a) {
        putInt(a.length);
        putBytes(a);
    }
    public void putString(String a) throws Exception{
        putValue(a.getBytes("UTF-8"));
    }
    public byte getByte(){
        return buffer[i_get++];
    }
    public int getInt(){
        return (getByte() & 0xff) << 24 | (getByte() & 0xff) << 16 | (getByte() & 0xff) << 8 | (getByte() & 0xff); 
    }
    public byte[] getValue() {
        byte[] a = new byte[getInt()];
        System.arraycopy(buffer, i_get, a, 0, a.length);
        add_i_get(a.length);
        return a;
    }
    public void add_i_get(int a){
        i_get+=a;
    }
    public byte[] getValueAllLen(){
        byte[] a = new byte[i_put - i_get];
        System.arraycopy(buffer, i_get, a, 0, a.length);
        i_get+=a.length;
        return a;
    }
    public void reset_command(int command){
        i_put=5;
        putByte((byte) command);
    }
    public int getCommand(){
        return buffer[5];
    }
}
*/
