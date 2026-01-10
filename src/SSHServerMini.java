public class SSHServerMini {
    public SSHServerMini(int port, String username, String password) throws Exception {
        java.net.ServerSocket serverSocket = new java.net.ServerSocket(port);
        System.out.println("SSH Server listening on port " + port);
        System.out.println("Credentials: " + username + " / " + password);
        System.out.println("Server ready for multiple connections...\n");
        while (true) {
            try {
                java.net.Socket clientSocket = serverSocket.accept();
                System.out.println("New connection from: " + clientSocket.getInetAddress());
                Session session = new Session(clientSocket, username, password);
                new Thread(session).start();
            } catch (Exception e) {
                System.err.println("Accept error: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 2223;
        String user = "admin";
        String pass = "admin123";
        if (args.length == 3) {
            port = Integer.parseInt(args[0]);
            user = args[1];
            pass = args[2];
        }
        new SSHServerMini(port, user, pass);
    }
}

class Session implements Runnable {
    final int SSH_MSG_DISCONNECT = 1, SSH_MSG_IGNORE = 2, SSH_MSG_UNIMPLEMENTED = 3, SSH_MSG_DEBUG = 4,
            SSH_MSG_SERVICE_REQUEST = 5, SSH_MSG_SERVICE_ACCEPT = 6, SSH_MSG_KEXINIT = 20, SSH_MSG_NEWKEYS = 21,
            SSH_MSG_KEXDH_INIT = 30, SSH_MSG_KEXDH_REPLY = 31, SSH_MSG_USERAUTH_REQUEST = 50,
            SSH_MSG_USERAUTH_FAILURE = 51, SSH_MSG_USERAUTH_SUCCESS = 52, 
            SSH_MSG_CHANNEL_OPEN = 90, SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91, 
            SSH_MSG_CHANNEL_DATA = 94, SSH_MSG_CHANNEL_EOF = 96, SSH_MSG_CHANNEL_CLOSE = 97,
            SSH_MSG_CHANNEL_REQUEST = 98, SSH_MSG_CHANNEL_SUCCESS = 99;

    private java.net.Socket socket;
    private String expectedUsername;
    private String expectedPassword;
    
    private byte[] V_S, V_C, I_S, I_C;
    private javax.crypto.Cipher reader_cipher, writer_cipher;
    private javax.crypto.Mac reader_mac, writer_mac;
    private int reader_seq = 0, writer_seq = 0, reader_cipher_size = 8;
    private byte barra_r = 13, barra_n = 10;
    private java.io.InputStream in = null;
    private java.io.OutputStream out = null;
    private ECDH kex = null; // Unificado
    private java.security.SecureRandom random = null;
    private int clientChannel = 0;
    private Process shellProcess = null;
    private java.io.InputStream shellOutput = null;
    private java.io.OutputStream shellInput = null;
    private boolean authenticated = false;

    public Session(java.net.Socket socket, String user, String pass) {
        this.socket = socket;
        this.expectedUsername = user;
        this.expectedPassword = pass;
        this.random = new java.security.SecureRandom();
        try {
            this.V_S = "SSH-2.0-SSHSERVER_MINI".getBytes("UTF-8");
        } catch (Exception e) {}
    }

    public void run() {
        try {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(0); 
            in = socket.getInputStream();
            out = socket.getOutputStream();

            // Handshake de Versão
            out.write(V_S);
            out.write(barra_r);
            out.write(barra_n);
            out.flush();

            Buf buf = new Buf();
            int i = 0;
            int readByte;
            while ((readByte = in.read()) != -1) {
                buf.buffer[i] = (byte)readByte;
                if (i > 0 && buf.buffer[i-1] == barra_r && buf.buffer[i] == barra_n) {
                    i--; 
                    break;
                }
                if (readByte == barra_n) break;
                i++;
                if (i >= 255) break; 
            }
            V_C = new byte[i];
            System.arraycopy(buf.buffer, 0, V_C, 0, i);

            performKeyExchange();
            performAuthentication();

            if (authenticated) {
                handleChannel();
            }

        } catch (Exception e) {
            System.out.println("Connection closed (" + socket.getInetAddress() + "): " + e.getMessage());
        } finally {
            closeSession();
        }
    }

    private void closeSession() {
        if (shellProcess != null && shellProcess.isAlive()) {
            shellProcess.destroy();
        }
        try { socket.close(); } catch (Exception e) {}
    }

    private void performKeyExchange() throws Exception {
        Buf buf = read();
        if (buf.getCommand() != SSH_MSG_KEXINIT) throw new Exception("Expected KEXINIT");

        int packetLen = buf.getInt();
        int padLen = buf.getByte() & 0xff;
        int payloadLen = packetLen - padLen - 1;
        I_C = new byte[payloadLen];
        System.arraycopy(buf.buffer, 5, I_C, 0, payloadLen);

        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXINIT);
        buf.putBytes(get_random_bytes(16)); // Cookie
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
        I_S = new byte[buf.i_put - 5];
        System.arraycopy(buf.buffer, 5, I_S, 0, I_S.length);
        write(buf);

        kex = new ECDH();
        kex.init(V_S, V_C, I_S, I_C);
        buf = read(); // KEXDH_INIT
        buf.getInt(); buf.getByte(); buf.getByte(); // Skip headers
        byte[] Q_C = buf.getValue();
        byte[] K_S = generateHostKey();
        kex.next(Q_C, K_S);
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXDH_REPLY);
        buf.putValue(K_S);
        buf.putValue(kex.Q_S);
        buf.putValue(generateSignature());
        write(buf);
        buf = new Buf();
        buf.reset_command(SSH_MSG_NEWKEYS);
        write(buf);
        buf = read(); // NEWKEYS Client
        if (buf.getCommand() != SSH_MSG_NEWKEYS) throw new Exception("Expected NEWKEYS");
        deriveKeys();
    }

    private void deriveKeys() throws Exception {
        Buf buf = new Buf();
        buf.putValue(kex.K);
        buf.putBytes(kex.H);
        buf.putByte((byte) 0x41);
        buf.putBytes(kex.H);
        int j = buf.i_put - kex.H.length - 1;

        kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.spec.AlgorithmParameterSpec r_iv = new javax.crypto.spec.IvParameterSpec(digest_trunc(kex.sha.digest(), 16));
        buf.buffer[j]++; kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.spec.AlgorithmParameterSpec w_iv = new javax.crypto.spec.IvParameterSpec(digest_trunc(kex.sha.digest(), 16));
        buf.buffer[j]++; kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key r_key = new javax.crypto.spec.SecretKeySpec(digest_trunc(kex.sha.digest(), 32), "AES");
        buf.buffer[j]++; kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key w_key = new javax.crypto.spec.SecretKeySpec(digest_trunc(kex.sha.digest(), 32), "AES");
        buf.buffer[j]++; kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key r_mac = new javax.crypto.spec.SecretKeySpec(digest_trunc(kex.sha.digest(), 32), "HmacSHA256");
        buf.buffer[j]++; kex.sha.update(buf.buffer, 0, buf.i_put);
        java.security.Key w_mac = new javax.crypto.spec.SecretKeySpec(digest_trunc(kex.sha.digest(), 32), "HmacSHA256");
        reader_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
        reader_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, r_key, r_iv);
        reader_cipher_size = 16;
        reader_mac = javax.crypto.Mac.getInstance("HmacSHA256");
        reader_mac.init(r_mac);
        writer_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
        writer_cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, w_key, w_iv);
        writer_mac = javax.crypto.Mac.getInstance("HmacSHA256");
        writer_mac.init(w_mac);
    }

    private void performAuthentication() throws Exception {
        Buf buf = read(); // Service Request
        buf.getInt(); buf.getByte(); buf.getByte();
        String service = new String(buf.getValue(), "UTF-8");

        buf = new Buf();
        buf.reset_command(SSH_MSG_SERVICE_ACCEPT);
        buf.putString(service);
        write(buf);

        buf = read(); // Auth Request
        buf.getInt(); buf.getByte(); buf.getByte();
        String u = new String(buf.getValue(), "UTF-8");
        new String(buf.getValue(), "UTF-8"); // service
        new String(buf.getValue(), "UTF-8"); // method
        buf.getByte(); 
        String p = new String(buf.getValue(), "UTF-8");

        if (u.equals(expectedUsername) && p.equals(expectedPassword)) {
            buf = new Buf();
            buf.reset_command(SSH_MSG_USERAUTH_SUCCESS);
            write(buf);
            authenticated = true;
        } else {
            buf = new Buf();
            buf.reset_command(SSH_MSG_USERAUTH_FAILURE);
            buf.putString("password");
            buf.putByte((byte) 0);
            write(buf);
            throw new Exception("Auth failed");
        }
    }

    private void handleChannel() throws Exception {
        while (true) {
            Buf buf = read();
            int msgType = buf.getCommand();

            if (msgType == SSH_MSG_CHANNEL_OPEN) {
                buf.getInt(); buf.getByte(); buf.getByte();
                buf.getValue(); // type
                clientChannel = buf.getInt();
                
                buf = new Buf();
                buf.reset_command(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
                buf.putInt(clientChannel);
                buf.putInt(0);
                buf.putInt(0x100000);
                buf.putInt(0x4000);
                write(buf);
            
            } else if (msgType == SSH_MSG_CHANNEL_REQUEST) {
                buf.getInt(); buf.getByte(); buf.getByte();
                buf.getInt(); 
                String req = new String(buf.getValue(), "UTF-8");
                byte wantReply = buf.getByte();
                
                if (req.equals("shell")) {
                    startShell();
                }
                
                if (wantReply != 0) {
                    buf = new Buf();
                    buf.reset_command(SSH_MSG_CHANNEL_SUCCESS);
                    buf.putInt(clientChannel);
                    write(buf);
                }
                
            } else if (msgType == SSH_MSG_CHANNEL_DATA) {
                buf.getInt(); buf.getByte(); buf.getByte();
                buf.getInt(); 
                byte[] data = buf.getValue();
                if (shellInput != null) {
                    shellInput.write(data);
                    shellInput.flush();
                }
            } else if (msgType == SSH_MSG_CHANNEL_EOF || msgType == SSH_MSG_CHANNEL_CLOSE) {
                break;
            }
        }
    }

    private void startShell() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder pb;
        
        if (os.contains("win")) {
            pb = new ProcessBuilder("cmd.exe");
        } else {
            pb = new ProcessBuilder("/bin/bash", "-i");
        }
        
        pb.redirectErrorStream(true); 
        shellProcess = pb.start();
        shellOutput = shellProcess.getInputStream();
        shellInput = shellProcess.getOutputStream();

        new Thread(() -> {
            try {
                byte[] buffer = new byte[4096];
                int len;
                while (shellProcess.isAlive() && (len = shellOutput.read(buffer)) != -1) {
                    if (len > 0) {
                        synchronized(this) { 
                            Buf b = new Buf();
                            b.reset_command(SSH_MSG_CHANNEL_DATA);
                            b.putInt(clientChannel);
                            b.putInt(len);
                            b.putBytes(java.util.Arrays.copyOf(buffer, len));
                            write(b);
                        }
                    }
                }
                synchronized(this) {
                    Buf b = new Buf();
                    b.reset_command(SSH_MSG_CHANNEL_EOF);
                    b.putInt(clientChannel);
                    write(b);
                }
            } catch (Exception e) {}
        }).start();
    }

    private Buf read() throws Exception {
        Buf buf = new Buf();
        int total = 0;
        
        while (total < reader_cipher_size) {
            int r = in.read(buf.buffer, buf.i_put + total, reader_cipher_size - total);
            if (r == -1) throw new Exception("Socket closed");
            total += r;
        }
        buf.i_put += reader_cipher_size;
        
        if (reader_cipher != null) 
            reader_cipher.update(buf.buffer, 0, reader_cipher_size, buf.buffer, 0);

        int packetLen = ((buf.buffer[0] & 0xff) << 24) | ((buf.buffer[1] & 0xff) << 16) |
                        ((buf.buffer[2] & 0xff) << 8) | (buf.buffer[3] & 0xff);
        int need = packetLen + 4 - reader_cipher_size;

        if ((buf.i_put + need) > buf.buffer.length) {
            byte[] a = new byte[buf.i_put + need];
            System.arraycopy(buf.buffer, 0, a, 0, buf.i_put);
            buf.buffer = a;
        }

        total = 0;
        while (total < need) {
            int r = in.read(buf.buffer, buf.i_put + total, need - total);
            if (r == -1) throw new Exception("Socket closed");
            total += r;
        }
        buf.i_put += need;

        if (reader_cipher != null) 
            reader_cipher.update(buf.buffer, reader_cipher_size, need, buf.buffer, reader_cipher_size);
        
        if (reader_mac != null) {
            reader_mac.update(intToBytes(reader_seq));
            reader_mac.update(buf.buffer, 0, buf.i_put);
            reader_mac.doFinal();
            
            in.skip(32); 
            reader_seq++;
        }
        
        buf.i_get = 0;
        return buf;
    }

    private synchronized void write(Buf buf) throws Exception {
        int len = buf.i_put;
        int pad = (-len) & 15;
        if (pad < 16) pad += 16;
        len = len + pad - 4;

        buf.buffer[0] = (byte)(len >> 24);
        buf.buffer[1] = (byte)(len >> 16);
        buf.buffer[2] = (byte)(len >> 8);
        buf.buffer[3] = (byte)len;
        buf.buffer[4] = (byte)pad;

        System.arraycopy(get_random_bytes(pad), 0, buf.buffer, buf.i_put, pad);
        buf.i_put += pad;

        if (writer_cipher != null) {
            writer_mac.update(intToBytes(writer_seq));
            writer_mac.update(buf.buffer, 0, buf.i_put);
            byte[] mac = writer_mac.doFinal();
            
            writer_cipher.update(buf.buffer, 0, buf.i_put, buf.buffer, 0);
            out.write(buf.buffer, 0, buf.i_put);
            out.write(mac);
        } else {
            out.write(buf.buffer, 0, buf.i_put);
        }
        out.flush();
        writer_seq++;
    }

    private byte[] intToBytes(int i) {
        return new byte[]{(byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i};
    }
    
    private byte[] get_random_bytes(int n) {
        byte[] a = new byte[n];
        random.nextBytes(a);
        return a;
    }
    
    private byte[] digest_trunc(byte[] digest, int len) {
        byte[] a = new byte[len];
        System.arraycopy(digest, 0, a, 0, len);
        return a;
    }
    
    private byte[] generateHostKey() throws Exception {
        Buf buf = new Buf();
        buf.putString("ssh-rsa");
        buf.putValue(new byte[]{0x01, 0x00, 0x01});
        buf.putValue(get_random_bytes(128)); 
        return buf.getValueAllLen();
    }

    private byte[] generateSignature() throws Exception {
        Buf buf = new Buf();
        buf.putString("ssh-rsa");
        buf.putValue(get_random_bytes(128));
        return buf.getValueAllLen();
    }
}

