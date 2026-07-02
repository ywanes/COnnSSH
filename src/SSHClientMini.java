public class SSHClientMini {
    final int SSH_MSG_DISCONNECT = 1, SSH_MSG_IGNORE = 2, SSH_MSG_UNIMPLEMENTED = 3, SSH_MSG_DEBUG = 4,
              SSH_MSG_SERVICE_REQUEST = 5, SSH_MSG_KEXINIT = 20, SSH_MSG_NEWKEYS = 21, SSH_MSG_KEXDH_INIT = 30,
              SSH_MSG_USERAUTH_REQUEST = 50, SSH_MSG_USERAUTH_FAILURE = 51, SSH_MSG_USERAUTH_BANNER = 53,
              SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60, SSH_MSG_GLOBAL_REQUEST = 80, SSH_MSG_REQUEST_FAILURE = 82,
              SSH_MSG_CHANNEL_OPEN = 90, SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91, SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
              SSH_MSG_CHANNEL_DATA = 94, SSH_MSG_CHANNEL_EOF = 96, SSH_MSG_CHANNEL_REQUEST = 98;
    // Limite defensivo: um packet_length corrompido/malicioso nao deve tentar alocar GBs.
    private static final int MAX_PACKET = 1 << 20;
    private byte[] V_C, V_S, I_C, I_S;
    private javax.crypto.Cipher reader_cipher, writer_cipher;
    private javax.crypto.Mac reader_mac, writer_mac;
    // reader_seq/writer_seq: contam TODOS os pacotes desde o primeiro para o HMAC bater com o servidor.
    private int reader_seq = 0, writer_seq = 0, reader_cipher_size = 8;
    // rmpsize e escrito pela thread reading_stream e lido pela thread principal: volatile garante visibilidade.
    private volatile int rmpsize = 0;
    private byte barra_r = 13, barra_n = 10;
    private java.io.InputStream in = null;
    private java.io.OutputStream out = null;
    // channel_opened e escrito pela thread reading_stream e lido pela thread principal em connect_stdin.
    private volatile boolean channel_opened = false;
    private boolean verbose = false;
    private ECDH kex = null;
    private java.security.SecureRandom random = null;

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("uso: java SSHClientMini <host> <usuario> <porta> <senha>");
            return;
        }
        new SSHClientMini(args[0], args[1], Integer.parseInt(args[2]), args[3]);
    }

    public SSHClientMini(String host, String username, int port, String password) throws Exception {
        V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
        kex = new ECDH();
        connect_stream(host, username, port, password);
        new Thread() { public void run() {
            reading_stream();
        }}.start();
        connect_stdin();
        writing_stdin();
    }

    // count_line_return e escrito pela thread principal (writing_stdin) e lido pela reading_stream.
    private volatile int count_line_return = -1;
    private boolean can_print(byte[] a) {
        if (count_line_return == -1)
            return true;
        count_line_return++;
        if (count_line_return == 1)
            return false;
        if (count_line_return == 2 && a.length == 1 && (int)a[0] == 10)
            return false;
        return true;
    }

    private void connect_stream(String host, String username, int port, String password) throws Exception {
        Buf buf = new Buf();
        int i, j;
        try {
            java.net.Socket socket = new java.net.Socket(host, port);
            in = socket.getInputStream();
            out = socket.getOutputStream();
        } catch (Exception e) {
            throw new Exception("Error session connect socket " + e);
        }
        out.write(V_C, 0, V_C.length);
        out.write(barra_n);
        out.flush();
        i = 0;
        while ((j = in.read(buf.buffer, i, 1)) > 0) {
            if (i > 0 && buf.buffer[i-1] == barra_r && buf.buffer[i] == barra_n) {
                i--;
                break;
            }
            i++;
            if (i >= 255)   // par que nunca manda \r\n nao pode estourar o buffer
                throw new Exception("linha de versao do servidor muito longa");
        }
        V_S = new byte[i];
        System.arraycopy(buf.buffer, 0, V_S, 0, i);
        debug("connect stream <-: ", V_S);
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXINIT);
        int start_fill = buf.i_put;
        byte[] a = get_random_bytes(16);
        System.arraycopy(a, 0, buf.buffer, start_fill, a.length);
        buf.i_put += 16;
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
        buf.i_get = 5;
        I_C = buf.getValueAllLen();
        write(buf);
        debug("connect stream ->: ", buf);

        buf = read();
        j = buf.getInt();                     // packet_length
        int padLen = buf.getByte() & 0xff;    // padding_length
        I_S = new byte[j - 1 - padLen];       // payload = packet_length - 1 (byte pad_len) - padding
        System.arraycopy(buf.buffer, buf.i_get, I_S, 0, I_S.length);
        debug("connect stream <-: ", I_S);

        kex.init(V_S, V_C, I_S, I_C);
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXDH_INIT);
        buf.putValue(kex.Q_C);
        write(buf);
        debug("connect stream ->: ", buf);
        buf = read();
        kex.next(buf);
        buf.reset_command(SSH_MSG_NEWKEYS);
        write(buf);
        buf = read();
        if (buf.getCommand() != SSH_MSG_NEWKEYS)
            throw new Exception("invalid protocol(newkyes): " + buf.getCommand());

        buf = new Buf();
        buf.putValue(kex.K);
        buf.putBytes(kex.H);
        buf.putByte((byte) 0x41);
        buf.putBytes(kex.H);
        j = buf.i_put - kex.H.length - 1;
        // Cliente: escreve c->s (writer) e le s->c (reader). A=IV c->s, B=IV s->c,
        // C=chave c->s, D=chave s->c, E=MAC c->s, F=MAC s->c.
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
        if (command == SSH_MSG_USERAUTH_BANNER || command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
            throw new Exception("USERAUTH BANNER or PASSWD_CHANGEREQ");
    }

    private boolean texto_oculto(byte[] a) {
        return a.length > 6 && (int)a[0] == 27 && (int)a[1] == 93 && (int)a[2] == 48 && (int)a[3] == 59 && (int)a[a.length-1] == 7;
    }
    private void mostra_bytes(byte[] a) {
        String s = "";
        for (int i = 0; i < a.length; i++)
            s += (int)a[i] + ",";
        s = "[" + s + "]";
        System.out.println(s);
    }
    private void reading_stream() {
        try {
            Buf buf = new Buf();
            while (true) {
                buf = read();
                int msgType = buf.getCommand();
                if (msgType == SSH_MSG_CHANNEL_DATA) {
                    buf.add_i_get(10);
                    byte[] a = buf.getValue();
                    if (a.length == 0) {
                        System.out.println("a.length == 0");
                        System.exit(0);
                    }
                    if (texto_oculto(a))
                        continue;
                    if (can_print(a)) {
                        System.out.write(a);
                        System.out.flush();
                    }
                    continue;
                }
                if (msgType == SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
                    buf.add_i_get(18);
                    int rps = buf.getInt();
                    rmpsize = rps;
                    channel_opened = true;   // publicado depois de rmpsize (ambos volatile)
                    continue;
                }
                if (msgType == SSH_MSG_GLOBAL_REQUEST) {
                    buf.add_i_get(6);
                    buf.getValue();
                    if (buf.getByte() != 0) {
                        buf.reset_command(SSH_MSG_REQUEST_FAILURE);
                        write(buf);
                    }
                    continue;
                }
                if (msgType == SSH_MSG_CHANNEL_EOF)
                    System.exit(0);
                System.err.println("msgType " + msgType + " not found.");
                System.exit(1);
            }
        } catch (Exception e) {
            System.out.println("ex_3 " + e.toString());
            System.exit(1);
        }
    }

    private byte[] digest_trunc_len(byte[] digest, int len) {
        if (digest.length <= len)
            return digest;
        byte[] a = new byte[len];
        System.arraycopy(digest, 0, a, 0, a.length);
        return a;
    }

    private byte[] get_random_bytes(int n) {
        if (random == null)
            random = new java.security.SecureRandom();
        byte[] a = new byte[n];
        random.nextBytes(a);
        return a;
    }

    private byte[] intToBytes(int i) {
        return new byte[]{(byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i};
    }

    // Le exatamente 'len' bytes (in.read pode retornar menos que o pedido num socket TCP).
    private void readFully(byte[] b, int off, int len) throws Exception {
        int total = 0;
        while (total < len) {
            int r = in.read(b, off + total, len - total);
            if (r == -1) throw new Exception("Socket closed");
            total += r;
        }
    }

    private Buf read() throws Exception {
        Buf buf;
        while (true) {
            buf = new Buf();

            // Bloco inicial: contem o campo packet_length (4 bytes).
            readFully(buf.buffer, 0, reader_cipher_size);
            buf.i_put += reader_cipher_size;
            if (reader_cipher != null)
                reader_cipher.update(buf.buffer, 0, reader_cipher_size, buf.buffer, 0);

            int packetLen = ((buf.buffer[0] & 0xff) << 24) | ((buf.buffer[1] & 0xff) << 16) |
                            ((buf.buffer[2] & 0xff) << 8) | (buf.buffer[3] & 0xff);
            if (packetLen < 0 || packetLen > MAX_PACKET)   // evita OOM por packet_length invalido
                throw new Exception("packet_length invalido: " + packetLen);
            int need = packetLen + 4 - reader_cipher_size;

            if ((buf.i_put + need) > buf.buffer.length) {
                byte[] a = new byte[buf.i_put + need];
                System.arraycopy(buf.buffer, 0, a, 0, buf.i_put);
                buf.buffer = a;
            }
            if (need > 0) {
                readFully(buf.buffer, buf.i_put, need);
                buf.i_put += need;
                if (reader_cipher != null)
                    reader_cipher.update(buf.buffer, reader_cipher_size, need, buf.buffer, reader_cipher_size);
            }
            if (reader_mac != null) {
                reader_mac.update(intToBytes(reader_seq));
                reader_mac.update(buf.buffer, 0, buf.i_put);
                byte[] calc = reader_mac.doFinal();
                byte[] recv = new byte[32];
                readFully(recv, 0, 32);   // le o MAC completo (era in.read sem laco)
                if (!java.security.MessageDigest.isEqual(calc, recv))   // comparacao constant-time
                    throw new Exception("MAC invalido (pacote adulterado ou fora de sincronia)");
            }
            reader_seq++;   // conta todo pacote, mesmo os de texto claro do KEX

            buf.i_get = 0;
            int type = buf.getCommand();
            if (type == SSH_MSG_DISCONNECT)
                System.exit(0);
            if (type != SSH_MSG_IGNORE && type != SSH_MSG_UNIMPLEMENTED
                    && type != SSH_MSG_DEBUG && type != SSH_MSG_CHANNEL_WINDOW_ADJUST)
                break;
        }
        buf.i_get = 0;
        return buf;
    }

    // synchronized: writing_stdin e reading_stream escrevem em paralelo (writer_seq/writer_cipher).
    private synchronized void write(Buf buf) throws Exception {
        int len = buf.i_put;
        int pad = (-len) & 15;
        if (pad < 4) pad += 16;   // SSH exige padding >= 4; somar 16 preserva o alinhamento de bloco
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

    private void connect_stdin() throws Exception {
        Buf buf = new Buf();
        buf.reset_command(SSH_MSG_CHANNEL_OPEN);
        buf.putString("session");
        buf.putInt(0);
        buf.putInt(0x100000);
        buf.putInt(0x4000);
        write(buf);

        int limit = 3000;
        while (limit-- > 0 && !channel_opened)
            try { Thread.sleep(10); } catch (Exception e) {};
        if (!channel_opened)
            throw new Exception("channel is not opened.");
        buf.reset_command(SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putString("pty-req");
        buf.putByte((byte) 0);
        buf.putString("vt100");
        buf.putInt(10000);
        buf.putInt(24);
        buf.putInt(640);
        buf.putInt(480);
        buf.putInt(0);
        write(buf);

        buf.reset_command(SSH_MSG_CHANNEL_REQUEST);
        buf.putInt(0);
        buf.putString("shell");
        buf.putByte((byte) 0);
        write(buf);
    }

    private void writing_stdin() throws Exception {
        Buf buf = new Buf(new byte[rmpsize]);
        int i = 0;
        int off = 14;
        while ((i = System.in.read(buf.buffer, off, buf.buffer.length - off - 128)) >= 0) {
            if (i <= 0)   // nada lido: nao mexe no buffer (i-2+off apontaria pro cabecalho)
                continue;
            if (buf.buffer[i-2+off] != barra_r || buf.buffer[i-1+off] != barra_n) {
                i++;
                buf.buffer[i-2+off] = barra_r;
                buf.buffer[i-1+off] = barra_n;
            }
            for (int j = 0; j < off; j++)
                buf.buffer[j] = 0;
            debug(buf.buffer, off, i);
            count_line_return = 0;
            buf.reset_command(SSH_MSG_CHANNEL_DATA);
            buf.putInt(0);
            buf.putInt(i);
            buf.i_put += i;
            write(buf);
        }
    }

    private void debug(String a, byte[] b) {
        if (verbose) {
            System.out.println(a + new String(b));
            System.out.flush();
        }
    }
    private void debug(String a, Buf buf) {
        if (verbose) {
            System.out.print(a);
            System.out.write(buf.buffer, 0, buf.i_put);
            System.out.println();
            System.out.flush();
        }
    }
    private void debug(byte[] a, int i, int i0) throws Exception {
        if (verbose) {
            System.out.write("[".getBytes());
            System.out.write(a, i, i0);
            System.out.write("]".getBytes());
        }
    }
}
