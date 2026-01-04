import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.*;

public class SSHServerMini {
    final int SSH_MSG_DISCONNECT = 1, SSH_MSG_IGNORE = 2, SSH_MSG_UNIMPLEMENTED = 3, SSH_MSG_DEBUG = 4,
              SSH_MSG_SERVICE_REQUEST = 5, SSH_MSG_SERVICE_ACCEPT = 6, SSH_MSG_KEXINIT = 20, SSH_MSG_NEWKEYS = 21,
              SSH_MSG_KEXDH_INIT = 30, SSH_MSG_KEXDH_REPLY = 31, SSH_MSG_USERAUTH_REQUEST = 50,
              SSH_MSG_USERAUTH_FAILURE = 51, SSH_MSG_USERAUTH_SUCCESS = 52, 
              SSH_MSG_GLOBAL_REQUEST = 80, SSH_MSG_REQUEST_FAILURE = 82,
              SSH_MSG_CHANNEL_OPEN = 90, SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91, SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
              SSH_MSG_CHANNEL_DATA = 94, SSH_MSG_CHANNEL_EOF = 96, SSH_MSG_CHANNEL_CLOSE = 97,
              SSH_MSG_CHANNEL_REQUEST = 98, SSH_MSG_CHANNEL_SUCCESS = 99;
    
    private byte[] V_S, V_C, I_S, I_C;
    private Cipher reader_cipher, writer_cipher;
    private Mac reader_mac, writer_mac;
    private int reader_seq = 0, writer_seq = 0, reader_cipher_size = 8;
    private byte barra_r = 13, barra_n = 10;
    private InputStream in = null;
    private OutputStream out = null;
    private boolean verbose = true;
    private ECDHZ kex = null;
    private SecureRandom random = null;
    private String expectedUsername;
    private String expectedPassword;
    private int clientChannel = 0;
    private Process shellProcess = null;
    private InputStream shellOutput = null;
    private OutputStream shellInput = null;

    public SSHServerMini(int port, String username, String password) throws Exception {
        expectedUsername = username;
        expectedPassword = password;
        random = new SecureRandom();
        V_S = "SSH-2.0-SSHSERVER_1.0".getBytes("UTF-8");
        
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("SSH Server listening on port " + port);
        System.out.println("Username: " + username + " / Password: " + password);
        System.out.println("Waiting for connections...\n");
        
        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected from: " + clientSocket.getInetAddress());
            
            new Thread(() -> {
                try {
                    handleClient(clientSocket);
                } catch (Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    if (verbose) e.printStackTrace();
                }
            }).start();
        }
    }

    private void handleClient(Socket socket) throws Exception {
        try {
            socket.setSoTimeout(30000); // 30 second timeout
            socket.setTcpNoDelay(true); // disable Nagle's algorithm
            in = socket.getInputStream();
            out = socket.getOutputStream();
            
            // Send server version
            debug("Sending server version");
            out.write(V_S);
            out.write(barra_n);
            out.flush();
            debug("Server version sent, waiting for client...");
            
            // Read client version
            debug("Reading client version");
            debug("Available bytes: " + in.available());
            BufZ buf = new BufZ();
            int i = 0;
            int readByte;
            boolean gotCR = false;
            while ((readByte = in.read()) != -1) {
                buf.buffer[i] = (byte)readByte;
                
                // Accept both \r\n and just \n
                if (readByte == barra_n) {
                    if (gotCR) i--; // remove the \r
                    break;
                }
                if (readByte == barra_r) {
                    gotCR = true;
                } else {
                    gotCR = false;
                }
                
                i++;
                if (i >= 255) {
                    debug("Version string too long!");
                    break;
                }
            }
            V_C = new byte[i];
            System.arraycopy(buf.buffer, 0, V_C, 0, i);
            debug("Client version: [" + new String(V_C) + "] (" + i + " bytes)");
            
            // Wait for client to be ready to send KEXINIT
            debug("Waiting for KEXINIT from client...");
            for (int waitCount = 0; waitCount < 50; waitCount++) {
                if (in.available() > 0) {
                    debug("Data available: " + in.available() + " bytes");
                    break;
                }
                Thread.sleep(100);
            }
            debug("Available after version exchange: " + in.available());
            
            // Key exchange
            performKeyExchange();
            
            // Authentication
            performAuthentication();
            
            // Handle channel
            handleChannel();
            
        } finally {
            if (shellProcess != null) {
                shellProcess.destroy();
            }
            try { socket.close(); } catch (Exception e) {}
        }
    }

    private void performKeyExchange() throws Exception {
        // Read client KEXINIT
        debug("Reading client KEXINIT");
        debug("Available before read: " + in.available());
        BufZ buf = read();
        debug("Got message type: " + buf.getCommand());
        if (buf.getCommand() != SSH_MSG_KEXINIT) {
            throw new Exception("Expected KEXINIT, got: " + buf.getCommand());
        }
        
        // Extract I_C - everything from message type onwards
        buf.i_get = 5; // skip packet header (4 bytes length + 1 byte padding)
        I_C = new byte[buf.i_put - buf.i_get];
        System.arraycopy(buf.buffer, buf.i_get, I_C, 0, I_C.length);
        debug("Got client KEXINIT, I_C length=" + I_C.length);
        
        // Send server KEXINIT
        debug("Sending server KEXINIT");
        buf = new BufZ();
        buf.reset_command(SSH_MSG_KEXINIT);
        byte[] cookie = get_random_bytes(16);
        buf.putBytes(cookie);
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
        
        // Extract I_S before adding packet framing
        int payload_start = 5; // after reset_command, we're at position 6 (command byte)
        I_S = new byte[buf.i_put - payload_start];
        System.arraycopy(buf.buffer, payload_start, I_S, 0, I_S.length);
        
        write(buf);
        debug("Sent server KEXINIT, I_S length=" + I_S.length);
        
        // Initialize ECDH
        kex = new ECDHZ();
        kex.init(V_S, V_C, I_S, I_C);
        
        // Read client KEXDH_INIT
        debug("Reading KEXDH_INIT");
        buf = read();
        if (buf.getCommand() != SSH_MSG_KEXDH_INIT) {
            throw new Exception("Expected KEXDH_INIT, got: " + buf.getCommand());
        }
        byte[] Q_C = buf.getValue();
        debug("Got Q_C: " + Q_C.length + " bytes");
        
        // Generate host key
        byte[] K_S = generateHostKey();
        
        // Complete ECDH
        kex.next_server(Q_C, K_S);
        debug("ECDH completed, K=" + kex.K.length + " bytes");
        
        // Send KEXDH_REPLY
        debug("Sending KEXDH_REPLY");
        buf = new BufZ();
        buf.reset_command(SSH_MSG_KEXDH_REPLY);
        buf.putValue(K_S);
        buf.putValue(kex.Q_S);
        buf.putValue(generateSignature());
        write(buf);
        
        // Send NEWKEYS
        debug("Sending NEWKEYS");
        buf = new BufZ();
        buf.reset_command(SSH_MSG_NEWKEYS);
        write(buf);
        
        // Read client NEWKEYS
        debug("Reading NEWKEYS");
        buf = read();
        if (buf.getCommand() != SSH_MSG_NEWKEYS) {
            throw new Exception("Expected NEWKEYS, got: " + buf.getCommand());
        }
        
        // Derive encryption keys
        debug("Deriving keys");
        deriveKeys();
        debug("Key exchange completed!");
    }

    private void deriveKeys() throws Exception {
        BufZ buf = new BufZ();
        buf.putValue(kex.K);
        buf.putBytes(kex.H);
        buf.putByte((byte) 0x41);
        buf.putBytes(kex.H);
        int j = buf.i_put - kex.H.length - 1;
        
        // Client to server IV (A)
        kex.sha.update(buf.buffer, 0, buf.i_put);
        AlgorithmParameterSpec reader_cipher_params = new IvParameterSpec(digest_trunc_len(kex.sha.digest(), 16));
        
        // Server to client IV (B)
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        AlgorithmParameterSpec writer_cipher_params = new IvParameterSpec(digest_trunc_len(kex.sha.digest(), 16));
        
        // Client to server key (C)
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        Key reader_cipher_key = new SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "AES");
        
        // Server to client key (D)
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        Key writer_cipher_key = new SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "AES");
        
        // Client to server MAC (E)
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        Key reader_mac_key = new SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "HmacSHA256");
        
        // Server to client MAC (F)
        buf.buffer[j]++;
        kex.sha.update(buf.buffer, 0, buf.i_put);
        Key writer_mac_key = new SecretKeySpec(digest_trunc_len(kex.sha.digest(), 32), "HmacSHA256");
        
        reader_cipher = Cipher.getInstance("AES/CTR/NoPadding");
        reader_cipher.init(Cipher.DECRYPT_MODE, reader_cipher_key, reader_cipher_params);
        reader_cipher_size = 16;
        reader_mac = Mac.getInstance("HmacSHA256");
        reader_mac.init(reader_mac_key);
        
        writer_cipher = Cipher.getInstance("AES/CTR/NoPadding");
        writer_cipher.init(Cipher.ENCRYPT_MODE, writer_cipher_key, writer_cipher_params);
        writer_mac = Mac.getInstance("HmacSHA256");
        writer_mac.init(writer_mac_key);
    }

    private void performAuthentication() throws Exception {
        // Read service request
        debug("Reading service request");
        BufZ buf = read();
        if (buf.getCommand() != SSH_MSG_SERVICE_REQUEST) {
            throw new Exception("Expected SERVICE_REQUEST, got: " + buf.getCommand());
        }
        String service = new String(buf.getValue(), "UTF-8");
        debug("Service: " + service);
        
        // Send service accept
        buf = new BufZ();
        buf.reset_command(SSH_MSG_SERVICE_ACCEPT);
        buf.putString(service);
        write(buf);
        debug("Sent SERVICE_ACCEPT");
        
        // Read auth request
        debug("Reading auth request");
        buf = read();
        if (buf.getCommand() != SSH_MSG_USERAUTH_REQUEST) {
            throw new Exception("Expected USERAUTH_REQUEST, got: " + buf.getCommand());
        }
        
        String username = new String(buf.getValue(), "UTF-8");
        String serviceName = new String(buf.getValue(), "UTF-8");
        String method = new String(buf.getValue(), "UTF-8");
        buf.getByte(); // change flag
        String password = new String(buf.getValue(), "UTF-8");
        
        debug("Auth: user=" + username + ", pass=" + password);
        
        if (username.equals(expectedUsername) && password.equals(expectedPassword)) {
            buf = new BufZ();
            buf.reset_command(SSH_MSG_USERAUTH_SUCCESS);
            write(buf);
            debug("Authentication SUCCESS!");
        } else {
            buf = new BufZ();
            buf.reset_command(SSH_MSG_USERAUTH_FAILURE);
            buf.putString("password");
            buf.putByte((byte) 0);
            write(buf);
            throw new Exception("Authentication FAILED!");
        }
    }

    private void handleChannel() throws Exception {
        debug("Handling channel operations");
        
        while (true) {
            BufZ buf = read();
            int msgType = buf.getCommand();
            debug("MSG: " + msgType);
            
            if (msgType == SSH_MSG_CHANNEL_OPEN) {
                String channelType = new String(buf.getValue(), "UTF-8");
                clientChannel = buf.getInt();
                buf.getInt(); // window
                buf.getInt(); // packet
                
                debug("CHANNEL_OPEN: " + channelType);
                
                buf = new BufZ();
                buf.reset_command(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
                buf.putInt(clientChannel);
                buf.putInt(0); // server channel
                buf.putInt(0x100000);
                buf.putInt(0x4000);
                write(buf);
                debug("Sent OPEN_CONFIRMATION");
                
            } else if (msgType == SSH_MSG_CHANNEL_REQUEST) {
                buf.getInt(); // channel
                String requestType = new String(buf.getValue(), "UTF-8");
                byte wantReply = buf.getByte();
                
                debug("CHANNEL_REQUEST: " + requestType);
                
                if (requestType.equals("pty-req")) {
                    String term = new String(buf.getValue(), "UTF-8");
                    debug("PTY: " + term);
                    
                    if (wantReply != 0) {
                        buf = new BufZ();
                        buf.reset_command(SSH_MSG_CHANNEL_SUCCESS);
                        buf.putInt(clientChannel);
                        write(buf);
                    }
                    
                } else if (requestType.equals("shell")) {
                    debug("Starting shell...");
                    startShell();
                    
                    if (wantReply != 0) {
                        buf = new BufZ();
                        buf.reset_command(SSH_MSG_CHANNEL_SUCCESS);
                        buf.putInt(clientChannel);
                        write(buf);
                    }
                    
                    startShellReader();
                }
                
            } else if (msgType == SSH_MSG_CHANNEL_DATA) {
                buf.add_i_get(4);
                byte[] data = buf.getValue();
                
                if (shellInput != null) {
                    shellInput.write(data);
                    shellInput.flush();
                }
                
            } else if (msgType == SSH_MSG_CHANNEL_EOF || msgType == SSH_MSG_CHANNEL_CLOSE) {
                debug("Channel closing");
                if (shellProcess != null) {
                    shellProcess.destroy();
                }
                break;
                
            } else if (msgType == SSH_MSG_GLOBAL_REQUEST) {
                buf.getValue(); // name
                byte wantReply = buf.getByte();
                
                if (wantReply != 0) {
                    buf = new BufZ();
                    buf.reset_command(SSH_MSG_REQUEST_FAILURE);
                    write(buf);
                }
            }
        }
    }

    private void startShell() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();
        
        if (os.contains("win")) {
            shellProcess = Runtime.getRuntime().exec("cmd.exe");
        } else {
            shellProcess = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-i"});
        }
        
        shellOutput = shellProcess.getInputStream();
        shellInput = shellProcess.getOutputStream();
        debug("Shell started!");
    }

    private void startShellReader() {
        new Thread(() -> {
            try {
                byte[] buffer = new byte[4096];
                int len;
                
                while ((len = shellOutput.read(buffer)) != -1) {
                    if (len > 0) {
                        byte[] output = new byte[len];
                        System.arraycopy(buffer, 0, output, 0, len);
                        
                        BufZ buf = new BufZ();
                        buf.reset_command(SSH_MSG_CHANNEL_DATA);
                        buf.putInt(clientChannel);
                        buf.putValue(output);
                        write(buf);
                    }
                }
                
            } catch (Exception e) {
                debug("Shell reader error: " + e.getMessage());
            }
        }).start();
    }

    private byte[] generateHostKey() throws Exception {
        BufZ buf = new BufZ();
        buf.putString("ssh-rsa");
        buf.putValue(new byte[]{0x01, 0x00, 0x01});
        buf.putValue(get_random_bytes(256));
        return buf.getValueAllLen();
    }

    private byte[] generateSignature() throws Exception {
        BufZ buf = new BufZ();
        buf.putString("ssh-rsa");
        buf.putValue(get_random_bytes(256));
        return buf.getValueAllLen();
    }

    private byte[] digest_trunc_len(byte[] digest, int len) {
        if (digest.length <= len) return digest;
        byte[] a = new byte[len];
        System.arraycopy(digest, 0, a, 0, len);
        return a;
    }

    private byte[] get_random_bytes(int n) {
        byte[] a = new byte[n];
        random.nextBytes(a);
        return a;
    }

    private BufZ read() throws Exception {
        BufZ buf;
        int loopCount = 0;
        while (true) {
            loopCount++;
            if (loopCount > 100) {
                throw new Exception("Read loop exceeded 100 iterations");
            }
            
            buf = new BufZ();
            debug("Reading packet, cipher_size=" + reader_cipher_size + ", available=" + in.available());
            int total = 0;
            while (total < reader_cipher_size) {
                debug("Attempting to read " + (reader_cipher_size - total) + " bytes...");
                int r = in.read(buf.buffer, buf.i_put + total, reader_cipher_size - total);
                if (r == -1) throw new Exception("Connection closed");
                debug("Read " + r + " bytes");
                total += r;
            }
            buf.i_put += reader_cipher_size;
            debug("Read first block: " + reader_cipher_size + " bytes");
            
            if (reader_cipher != null) {
                debug("Decrypting...");
                reader_cipher.update(buf.buffer, 0, reader_cipher_size, buf.buffer, 0);
            }
            
            int packet_length = (((buf.buffer[0] << 24) & 0xff000000) | ((buf.buffer[1] << 16) & 0x00ff0000) |
                       ((buf.buffer[2] << 8) & 0x0000ff00) | ((buf.buffer[3]) & 0x000000ff));
            int padding_length = buf.buffer[4] & 0xff;
            int need = packet_length + 4 - reader_cipher_size;
            
            debug("Packet: len=" + packet_length + ", pad=" + padding_length + ", need=" + need);
            
            if ((buf.i_put + need) > buf.buffer.length) {
                byte[] a = new byte[buf.i_put + need];
                System.arraycopy(buf.buffer, 0, a, 0, buf.i_put);
                buf.buffer = a;
            }
            
            if (need > 0) {
                total = 0;
                while (total < need) {
                    int r = in.read(buf.buffer, buf.i_put + total, need - total);
                    if (r == -1) throw new Exception("Connection closed");
                    total += r;
                }
                buf.i_put += need;
                debug("Read remaining: " + need + " bytes");
                if (reader_cipher != null)
                    reader_cipher.update(buf.buffer, reader_cipher_size, need, buf.buffer, reader_cipher_size);
            }
            
            if (reader_mac != null) {
                debug("Verifying MAC...");
                reader_mac.update(new byte[]{(byte)(reader_seq >> 24), (byte)(reader_seq >> 16),
                                             (byte)(reader_seq >> 8), (byte)reader_seq});
                reader_mac.update(buf.buffer, 0, buf.i_put);
                reader_mac.doFinal();
                byte[] macBytes = new byte[32];
                in.read(macBytes, 0, 32);
                reader_seq++;
            }
            
            int type = buf.getCommand();
            debug("Message type: " + type);
            if (type == SSH_MSG_DISCONNECT) {
                throw new Exception("Client disconnected");
            }
            if (type != SSH_MSG_IGNORE && type != SSH_MSG_UNIMPLEMENTED &&
                type != SSH_MSG_DEBUG && type != SSH_MSG_CHANNEL_WINDOW_ADJUST) {
                break;
            } else {
                debug("Skipping message type: " + type);
            }
        }
        buf.i_get = 0;
        return buf;
    }

    private synchronized void write(BufZ buf) throws Exception {
        int len = buf.i_put;
        int pad = (-len) & (15);
        if (pad < 16) pad += 16;
        len = len + pad - 4;
        
        buf.buffer[0] = (byte)(len >> 24);
        buf.buffer[1] = (byte)(len >> 16);
        buf.buffer[2] = (byte)(len >> 8);
        buf.buffer[3] = (byte)len;
        buf.buffer[4] = (byte)pad;
        
        System.arraycopy(new byte[pad], 0, buf.buffer, buf.i_put, pad);
        buf.i_put += pad;
        
        if (writer_cipher != null) {
            pad = buf.buffer[4];
            System.arraycopy(get_random_bytes(pad), 0, buf.buffer, buf.i_put - pad, pad);
            
            writer_mac.update(new byte[]{(byte)(writer_seq >> 24), (byte)(writer_seq >> 16),
                                        (byte)(writer_seq >> 8), (byte)writer_seq});
            writer_mac.update(buf.buffer, 0, buf.i_put);
            byte[] mac = writer_mac.doFinal();
            
            writer_cipher.update(buf.buffer, 0, buf.i_put, buf.buffer, 0);
            
            System.arraycopy(mac, 0, buf.buffer, buf.i_put, 32);
            buf.i_put += 32;
        }
        
        out.write(buf.buffer, 0, buf.i_put);
        out.flush();
        writer_seq++;
    }

    private void debug(String msg) {
        if (verbose) {
            System.out.println("[SERVER] " + msg);
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 2222;
        String username = "admin";
        String password = "admin123";
        
        if (args.length >= 3) {
            port = Integer.parseInt(args[0]);
            username = args[1];
            password = args[2];
        }
        
        new SSHServerMini(port, username, password);
    }
}

class ECDHZ {
    public byte[] K, H, Q_S;
    private byte[] V_S, V_C, I_S, I_C;
    public MessageDigest sha = null;
    private ECParameterSpec params = null;
    private KeyAgreement myKeyAgree = null;

    public void init(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        
        sha = MessageDigest.getInstance("SHA-256");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.genKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        java.security.interfaces.ECPublicKey publicKey = (java.security.interfaces.ECPublicKey) kp.getPublic();
        
        params = publicKey.getParams();
        ECPoint w = publicKey.getW();
        java.math.BigInteger x = w.getAffineX();
        java.math.BigInteger y = w.getAffineY();
        
        byte[] xBytes = toPaddedBytes(x, 32);
        byte[] yBytes = toPaddedBytes(y, 32);
        Q_S = new byte[1 + xBytes.length + yBytes.length];
        Q_S[0] = 4;
        System.arraycopy(xBytes, 0, Q_S, 1, xBytes.length);
        System.arraycopy(yBytes, 0, Q_S, 1 + xBytes.length, yBytes.length);
        
        myKeyAgree = KeyAgreement.getInstance("ECDH");
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

    public void next_server(byte[] Q_C, byte[] K_S) throws Exception {
        if (Q_C[0] != 4)
            throw new Exception("Unsupported EC point format");
        
        int coordinateLength = (Q_C.length - 1) / 2;
        byte[] xBytes = new byte[coordinateLength];
        byte[] yBytes = new byte[coordinateLength];
        System.arraycopy(Q_C, 1, xBytes, 0, coordinateLength);
        System.arraycopy(Q_C, 1 + coordinateLength, yBytes, 0, coordinateLength);
        
        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        java.math.BigInteger y = new java.math.BigInteger(1, yBytes);
        
        myKeyAgree.doPhase(
            KeyFactory.getInstance("EC").generatePublic(
                new ECPublicKeySpec(new ECPoint(x, y), params)
            ),
            true
        );
        
        K = myKeyAgree.generateSecret();
        
        BufZ buf = new BufZ();
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

class BufZ {
    byte[] buffer;
    int i_put, i_get;
    
    public BufZ() {
        this(new byte[1024 * 20]);
    }
    
    public BufZ(byte[] buffer) {
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
        i_put += a.length;
    }
    
    public void putValue(byte[] a) {
        putInt(a.length);
        putBytes(a);
    }
    
    public void putString(String a) throws Exception {
        putValue(a.getBytes("UTF-8"));
    }
    
    public byte getByte() {
        return buffer[i_get++];
    }
    
    public int getInt() {
        return (getByte() & 0xff) << 24 | (getByte() & 0xff) << 16 |
               (getByte() & 0xff) << 8 | (getByte() & 0xff);
    }
    
    public byte[] getValue() {
        byte[] a = new byte[getInt()];
        System.arraycopy(buffer, i_get, a, 0, a.length);
        add_i_get(a.length);
        return a;
    }
    
    public void add_i_get(int a) {
        i_get += a;
    }
    
    public byte[] getValueAllLen() {
        byte[] a = new byte[i_put - i_get];
        System.arraycopy(buffer, i_get, a, 0, a.length);
        i_get += a.length;
        return a;
    }
    
    public void reset_command(int command) {
        i_put = 5;
        putByte((byte) command);
    }
    
    public int getCommand() {
        return buffer[5] & 0xff;
    }
}