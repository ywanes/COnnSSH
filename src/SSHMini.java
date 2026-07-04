// SSHMini.java — projeto inteiro num unico arquivo, para rodar SEM javac.
// Single-file source launcher (JEP 330): "java SSHMini.java ..." compila tudo em memoria.
//
// Formatos aceitos:
//   java SSHMini.java                                    cliente: key.txt (login automatico) ou ywanes@192.168.0.100
//   java SSHMini.java -P 333                             idem, na porta 333
//   java SSHMini.java admin,admin123@localhost           cliente para o alvo informado
//   java SSHMini.java admin,admin123@localhost -P 333    cliente para o alvo, porta 333
//   java SSHMini.java -server admin,admin123@localhost           servidor (usuario/senha do arg)
//   java SSHMini.java -server admin,admin123@localhost -P 333    servidor na porta 333
//   java SSHMini.java -test                                      auto-teste: sobe servidor local na 3004 so p/ o teste
//   java SSHMini.java -test admin,admin123@localhost             auto-teste
//   java SSHMini.java -test -P 333                               auto-teste na porta 333
//   java SSHMini.java -test admin,admin123@localhost -P 333      auto-teste na porta 333
//
//   ssh -p 333 ywanes@192.168.0.100
//
// A ordem das opcoes e livre. Porta default = 22 (padrao SSH); use -P (ex.: -P 2223 p/ o servidor de teste).
// Cliente e -test sem alvo: se existir a key.txt faz login automatico; senao ywanes@192.168.0.100 (pede a senha).
// ATENCAO: nao rode "javac *.java" com este arquivo junto dos originais -> "duplicate class".
public class SSHMini {
    public static void main(String[] args) throws Exception {
        String mode = "client";
        String access = null;
        int port = -1;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("-server")) {
                mode = "server";
            } else if (a.equals("-test")) {
                mode = "test";
            } else if (a.equals("-P")) {
                if (i + 1 >= args.length) { erro("-P exige um numero de porta"); return; }
                try {
                    port = Integer.parseInt(args[++i]);
                } catch (Exception e) {
                    erro("porta invalida: " + args[i]); return;
                }
            } else if (!a.startsWith("-")) {
                access = a;
            } else {
                erro("opcao desconhecida: " + a); return;
            }
        }

        if (mode.equals("server")) {
            if (port <= 0) port = 2223;                 // servidor de teste
            String user = "admin", pass = "admin123";
            String[] p = parseAccess(access);
            if (p != null) { user = p[0]; pass = p[1]; }
            new SSHServerMini(port, user, pass);
        } else if (mode.equals("test")) {
            if (access == null && port == -1) {
                // "-test" sozinho -> auto-teste: sobe um servidor local SO durante o teste (porta 3004),
                // roda o cliente contra ele e encerra. A thread do servidor e daemon: morre no System.exit.
                System.setOut(TesteSSH.indentador(System.out));   // recua as linhas de "ruido" (servidor/resumo); os [checks] ficam na margem
                int portaAuto = 3004;
                // Pre-checa a porta: se estiver OCUPADA, aborta. Sem isso o teste conectaria num
                // servidor DESCONHECIDO que estivesse na 3004 e daria checks [OK] enganosos.
                try (java.net.ServerSocket probe = new java.net.ServerSocket(portaAuto)) {
                    // porta livre (o probe fecha ao sair do try; o servidor de teste rebinda em seguida)
                } catch (Exception e) {
                    System.out.println("[FALHA] auto-teste abortado: porta " + portaAuto + " ja em uso (" + e.getMessage() + "). Libere-a e rode de novo.");
                    System.exit(1);
                }
                boolean[] servidorNoAr = { false };
                Thread servidor = new Thread(() -> {
                    try { servidorNoAr[0] = true; new SSHServerMini(portaAuto, "admin", "admin123"); }
                    catch (Exception e) { servidorNoAr[0] = false; System.out.println("[FALHA] auto-teste: servidor de teste caiu na " + portaAuto + ": " + e); }
                });
                servidor.setDaemon(true);
                servidor.start();
                try { Thread.sleep(300); } catch (Exception e) {}   // deixa o bind acontecer
                if (!servidorNoAr[0]) {
                    System.out.println("[FALHA] auto-teste abortado: servidor de teste nao subiu na " + portaAuto + ".");
                    System.exit(1);
                }
                TesteSSH.runAuto("java \"" + caminhoFonte(args) + "\" admin,admin123@localhost -P " + portaAuto);
                System.exit(0);
            }
            // -test <alvo> e/ou -P -> testa um servidor EXTERNO (precisa ja estar no ar)
            if (port <= 0) port = 22;
            String alvo = resolverAcesso(access);
            if (alvo == null) return;
            String _jar = "java \"" + caminhoFonte(args) + "\" " + alvo + " -P " + port;   // caminho real do fonte: roda de qualquer dir
            TesteSSH.run(_jar);
        } else {
            if (port <= 0) port = 22;                   // cliente: porta SSH padrao
            String alvo = resolverAcesso(access);       // sem alvo: key.txt (login automatico) ou ywanes (pede senha)
            if (alvo == null) return;
            int c = alvo.indexOf(','), at = alvo.lastIndexOf('@');
            String user = alvo.substring(0, c), pass = alvo.substring(c + 1, at), host = alvo.substring(at + 1);
            try {
                new SSHClientMini(host, user, port, pass);
            } catch (Exception e) {
                System.err.println(e.toString().contains("UserAuth Fail") ? "UserAuth Fail!!" : e.toString());
            }
            System.exit(0);
        }
    }

    // Caminho do proprio .java como foi invocado (sun.java.command no modo source-file vem como
    // "[launcher ]<fonte> <args>"). Permite rodar o -test de qualquer diretorio, nao so de dentro
    // da pasta do fonte; funciona tambem com espacos no nome ("SSHMini - Copia (N).java").
    static String caminhoFonte(String[] args) {
        String cmd = System.getProperty("sun.java.command", "");
        String suf = args.length == 0 ? "" : " " + String.join(" ", args);
        if (cmd.endsWith(suf)) cmd = cmd.substring(0, cmd.length() - suf.length());
        if (new java.io.File(cmd).isFile()) return cmd;                  // JDKs que poem so o fonte
        int sp = cmd.indexOf(' ');                                       // JDKs que prefixam o launcher
        if (sp > 0 && new java.io.File(cmd.substring(sp + 1)).isFile()) return cmd.substring(sp + 1);
        return "SSHMini.java";                                           // fallback: comportamento antigo (dir atual)
    }

    // Cliente sem alvo na linha de comando: tenta login automatico pela key.txt; senao, alvo default.
    static String autoAccess() {
        java.io.File f = new java.io.File("D:\\DADOSSSSS\\Desktopsss\\desktop\\COnnSSH\\key.txt");
        if (f.exists() && f.isFile())
            return lendo_arquivo_ofuscado(f.getAbsolutePath()) + "@192.168.0.100";
        return "ywanes@192.168.0.100";
    }

    // Resolve o alvo completo "usuario,senha@host": usa autoAccess() se nao veio alvo e pede a senha
    // no console quando ela nao esta embutida. Usado tanto pelo cliente quanto pelo -test. null em erro.
    static String resolverAcesso(String access) {
        if (access == null) access = autoAccess();       // key.txt (login automatico) ou ywanes@192.168.0.100
        int at = access.lastIndexOf('@');
        if (at < 0) { erro("formato esperado: usuario[,senha]@host"); return null; }
        int c = access.indexOf(',');
        if (c >= 0 && c < at) return access;              // senha ja embutida
        String user = access.substring(0, at);
        String host = access.substring(at + 1);
        java.io.Console con = System.console();
        if (con == null) { erro("alvo sem senha e sem console para digita-la: " + access); return null; }
        char[] pc = con.readPassword(user + "@" + host + "'s password: ");
        String pass = (pc != null) ? new String(pc) : "";
        if (pass.trim().isEmpty()) { erro("senha vazia"); return null; }
        return user + "," + pass + "@" + host;
    }

    // "usuario,senha@host" -> {usuario, senha, host}; null se invalido/nulo
    static String[] parseAccess(String access) {
        if (access == null) return null;
        int c = access.indexOf(',');
        int at = access.lastIndexOf('@');
        if (c < 0 || at < 0 || at < c) return null;
        return new String[] { access.substring(0, c), access.substring(c + 1, at), access.substring(at + 1) };
    }

    // Le a key.txt e reconstroi as credenciais pelos indices ofuscados (identico ao COnnSSH original).
    static String lendo_arquivo_ofuscado(String caminho) {
        String result = "";
        try {
            java.util.List<String> lines = java.nio.file.Files.readAllLines(java.nio.file.Paths.get(caminho), java.nio.charset.StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++)
                result += lines.get(i) + "\n";
        } catch (Exception e) {
            System.err.println("Error read file ");
        }
        int[] ofuscado = new int[] {152,143,254,408,149,261,354,281,131,134,274,439,352};
        String result2 = "";
        for (int i = 0; i < ofuscado.length; i++)
            result2 += result.substring(ofuscado[i], ofuscado[i] + 1);
        return result2;
    }

    static void erro(String msg) {
        System.err.println("erro: " + msg);
        System.err.println("uso: java SSHMini.java [-server|-test] [usuario,senha@host] [-P porta]");
    }
}

class SSHClientMini {
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
        buf.putString("ecdsa-sha2-nistp256");
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

class SSHServerMini {
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
        } else if (args.length != 0) {
            System.err.println("uso: java SSHServerMini [porta usuario senha]");
            return;
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

    // Limite defensivo: um packet_length corrompido/malicioso nao deve tentar alocar GBs.
    private static final int MAX_PACKET = 1 << 20;

    private java.net.Socket socket;
    private String expectedUsername;
    private String expectedPassword;

    private byte[] V_S, V_C, I_S, I_C;
    private javax.crypto.Cipher reader_cipher, writer_cipher;
    private javax.crypto.Mac reader_mac, writer_mac;
    // reader_seq/writer_seq contam TODOS os pacotes desde o primeiro (inclusive os em texto
    // claro do KEX). Isso e obrigatorio: o HMAC usa esse contador e as duas pontas precisam
    // estar sincronizadas, senao a verificacao de MAC falha.
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
        buf.putString("ecdsa-sha2-nistp256");
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

        // Letras A..F do RFC 4253: A=IV c->s, B=IV s->c, C=chave c->s, D=chave s->c,
        // E=MAC c->s, F=MAC s->c. O servidor le c->s (reader) e escreve s->c (writer).
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
        Buf buf = read(); // Service Request (ssh-userauth)
        buf.getInt(); buf.getByte(); buf.getByte();
        String service = new String(buf.getValue(), "UTF-8");
        buf = new Buf();
        buf.reset_command(SSH_MSG_SERVICE_ACCEPT);
        buf.putString(service);
        write(buf);

        // O OpenSSH manda um probe "none" (e talvez "publickey") antes da senha.
        // Responde FAILURE (oferecendo "password") ate chegar a senha correta.
        while (true) {
            buf = read();
            if (buf.getCommand() != SSH_MSG_USERAUTH_REQUEST) continue;
            buf.getInt(); buf.getByte(); buf.getByte();
            String u = new String(buf.getValue(), "UTF-8");      // usuario
            new String(buf.getValue(), "UTF-8");                  // servico
            String method = new String(buf.getValue(), "UTF-8");  // metodo
            if (method.equals("password")) {
                buf.getByte();                                    // boolean FALSE
                String p = new String(buf.getValue(), "UTF-8");
                if (u.equals(expectedUsername) && p.equals(expectedPassword)) {
                    Buf ok = new Buf();
                    ok.reset_command(SSH_MSG_USERAUTH_SUCCESS);
                    write(ok);
                    authenticated = true;
                    return;
                }
            }
            Buf f = new Buf();
            f.reset_command(SSH_MSG_USERAUTH_FAILURE);
            f.putString("password");
            f.putByte((byte) 0);
            write(f);
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

                if (req.equals("pty-req")) {
                    ptyPedido = true;   // liga a conversao LF->CRLF (ONLCR) na saida do shell
                }
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
                    // Sessao interativa (ssh com pty) manda CR (\r) no Enter, mas o shell le de um pipe
                    // e precisa de LF (\n) pra fechar a linha. Sem traduzir, o cmd.exe/bash fica esperando
                    // o fim de linha e a sessao TRAVA. Aqui: CR e CRLF -> LF para o shell; CR/LF -> CRLF no
                    // eco (para o terminal exibir a quebra de linha certinha). Tambem some com o \r que
                    // sujava os comandos no bash (bug antigo do \r\n).
                    java.io.ByteArrayOutputStream paraShell = new java.io.ByteArrayOutputStream();
                    java.io.ByteArrayOutputStream paraEco = new java.io.ByteArrayOutputStream();
                    for (int k = 0; k < data.length; k++) {
                        int c = data[k] & 0xff;
                        if (c == 13) {                                                 // CR
                            if (k + 1 < data.length && (data[k + 1] & 0xff) == 10) k++; // colapsa CRLF
                            paraShell.write(10);
                            paraEco.write(13); paraEco.write(10);
                        } else if (c == 10) {                                          // LF
                            paraShell.write(10);
                            paraEco.write(13); paraEco.write(10);
                        } else {
                            paraShell.write(c);
                            paraEco.write(c);
                        }
                    }
                    byte[] eco = paraEco.toByteArray();
                    Buf e = new Buf();
                    e.reset_command(SSH_MSG_CHANNEL_DATA);
                    e.putInt(clientChannel);
                    e.putInt(eco.length);
                    e.putBytes(eco);
                    write(e);
                    shellInput.write(paraShell.toByteArray());
                    shellInput.flush();
                }
            } else if (msgType == SSH_MSG_CHANNEL_EOF) {
                // Cliente encerrou o stdin: fecha a entrada do shell para ele terminar de processar
                // e sair; a sessao segue ate o shell acabar (o thread de saida manda o EOF de volta).
                if (shellInput != null) { try { shellInput.close(); } catch (Exception e) {} }
            } else if (msgType == SSH_MSG_CHANNEL_CLOSE) {
                break;
            }
        }
    }

    // PID do ultimo shell aberto pelo servidor; o auto-teste compara com o PID do processo host
    // para provar que a sessao roda num processo separado. volatile: escrito aqui, lido no -test.
    static volatile long ultimoShellPid = 0;
    // Cliente pediu pty (pty-req)? Com pty, a saida do shell ganha o ONLCR que um pty de verdade
    // faria (LF -> CRLF); sem pty (ssh -T / pipes) os bytes seguem crus para nao corromper dados.
    private boolean ptyPedido = false;
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
        ultimoShellPid = shellProcess.pid();
        shellOutput = shellProcess.getInputStream();
        shellInput = shellProcess.getOutputStream();

        new Thread(() -> {
            try {
                byte[] buffer = new byte[4096];
                int len;
                boolean crAnterior = false;   // um \r\n pode quebrar entre dois reads; o estado atravessa chunks
                while (shellProcess.isAlive() && (len = shellOutput.read(buffer)) != -1) {
                    if (len > 0) {
                        byte[] envio;
                        if (ptyPedido) {
                            // ONLCR do pty que nao temos: o ssh real poe o terminal do cliente em raw e
                            // espera o servidor mandar CRLF; programa que imprime so \n (ex.: y ls) virava
                            // "escadinha". So insere o \r quando o \n nao veio de um \r\n ja correto (cmd.exe).
                            java.io.ByteArrayOutputStream conv = new java.io.ByteArrayOutputStream(len + 16);
                            for (int k = 0; k < len; k++) {
                                int c = buffer[k] & 0xff;
                                if (c == 10 && !crAnterior) conv.write(13);
                                conv.write(c);
                                crAnterior = (c == 13);
                            }
                            envio = conv.toByteArray();
                        } else {
                            envio = java.util.Arrays.copyOf(buffer, len);   // sem pty: bytes crus
                        }
                        synchronized(this) {
                            Buf b = new Buf();
                            b.reset_command(SSH_MSG_CHANNEL_DATA);
                            b.putInt(clientChannel);
                            b.putInt(envio.length);
                            b.putBytes(envio);
                            write(b);
                        }
                    }
                }
                int ec = 0;
                try { ec = shellProcess.waitFor(); } catch (Exception e) {}
                synchronized(this) {
                    // Fecha o canal como o protocolo exige: EOF + exit-status + CLOSE. Sem o exit-status
                    // e o CLOSE, o cliente OpenSSH real fica esperando e nao encerra a sessao (trava no exit).
                    Buf eof = new Buf(); eof.reset_command(SSH_MSG_CHANNEL_EOF); eof.putInt(clientChannel); write(eof);
                    Buf st = new Buf(); st.reset_command(SSH_MSG_CHANNEL_REQUEST); st.putInt(clientChannel);
                    st.putString("exit-status"); st.putByte((byte) 0); st.putInt(ec); write(st);
                    Buf cl = new Buf(); cl.reset_command(SSH_MSG_CHANNEL_CLOSE); cl.putInt(clientChannel); write(cl);
                }
            } catch (Exception e) {}
        }).start();
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
        Buf buf = new Buf();

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
            readFully(recv, 0, 32);   // era in.skip(32): skip pode pular < 32 e dessincronizar o fluxo
            if (!java.security.MessageDigest.isEqual(calc, recv))   // comparacao constant-time
                throw new Exception("MAC invalido (pacote adulterado ou fora de sincronia)");
        }
        reader_seq++;   // conta todo pacote, mesmo os de texto claro do KEX

        buf.i_get = 0;
        return buf;
    }

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

    // Host key ECDSA nistp256 REAL, estavel entre execucoes (seed fixa) p/ nao poluir o known_hosts.
    static final java.security.KeyPair HOST_KEY = gerarHostKey();
    static java.security.KeyPair gerarHostKey() {
        try {
            java.security.SecureRandom sr = java.security.SecureRandom.getInstance("SHA1PRNG");
            sr.setSeed("SSHMini-ecdsa-host-key-v1".getBytes("UTF-8"));
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
            kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"), sr);
            return kpg.generateKeyPair();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    // BigInteger -> big-endian de exatamente 'len' bytes (remove byte de sinal ou preenche com zeros)
    static byte[] mpad(java.math.BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) System.arraycopy(b, b.length - len, out, 0, len);
        else                System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }

    // Blob da host key: string "ecdsa-sha2-nistp256" | string "nistp256" | string Q (0x04||X||Y)
    private byte[] generateHostKey() throws Exception {
        java.security.interfaces.ECPublicKey pub = (java.security.interfaces.ECPublicKey) HOST_KEY.getPublic();
        byte[] x = mpad(pub.getW().getAffineX(), 32);
        byte[] y = mpad(pub.getW().getAffineY(), 32);
        byte[] q = new byte[65];
        q[0] = 4;
        System.arraycopy(x, 0, q, 1, 32);
        System.arraycopy(y, 0, q, 33, 32);
        Buf b = new Buf();
        b.putString("ecdsa-sha2-nistp256");
        b.putString("nistp256");
        b.putValue(q);
        return b.getValueAllLen();
    }

    // Assinatura ECDSA-SHA256 do hash de troca H, no formato SSH: string alg | string(mpint r|mpint s)
    private byte[] generateSignature() throws Exception {
        java.security.Signature sg = java.security.Signature.getInstance("SHA256withECDSA");
        sg.initSign(HOST_KEY.getPrivate());
        sg.update(kex.H);
        byte[] der = sg.sign();                     // DER: 30 len 02 rlen r 02 slen s
        int p = 3;
        int rlen = der[p++] & 0xff;
        byte[] r = java.util.Arrays.copyOfRange(der, p, p + rlen); p += rlen;
        p++;                                        // pula o 0x02 do segundo INTEGER
        int slen = der[p++] & 0xff;
        byte[] s = java.util.Arrays.copyOfRange(der, p, p + slen);
        Buf blob = new Buf();
        blob.putValue(r);                           // mpint r
        blob.putValue(s);                           // mpint s
        Buf out = new Buf();
        out.putString("ecdsa-sha2-nistp256");
        out.putValue(blob.getValueAllLen());
        return out.getValueAllLen();
    }
}

class ECDH {
    public byte[] K, H, Q_C, Q_S;
    private byte[] V_S, V_C, I_S, I_C;
    public java.security.MessageDigest sha = null;
    private java.security.spec.ECParameterSpec params = null;
    private javax.crypto.KeyAgreement myKeyAgree = null;

    public void init(byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        this.V_S = V_S; this.V_C = V_C; this.I_S = I_S; this.I_C = I_C;

        sha = java.security.MessageDigest.getInstance("SHA-256");
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.KeyPair kp = kpg.genKeyPair();

        java.security.interfaces.ECPublicKey pub = (java.security.interfaces.ECPublicKey) kp.getPublic();
        params = pub.getParams();
        java.security.spec.ECPoint w = pub.getW();

        byte[] x = toPaddedBytes(w.getAffineX(), 32);
        byte[] y = toPaddedBytes(w.getAffineY(), 32);
        byte[] myKey = new byte[1 + x.length + y.length];
        myKey[0] = 4;
        System.arraycopy(x, 0, myKey, 1, x.length);
        System.arraycopy(y, 0, myKey, 1 + x.length, y.length);

        this.Q_C = myKey;

        myKeyAgree = javax.crypto.KeyAgreement.getInstance("ECDH");
        myKeyAgree.init(kp.getPrivate());
    }

    public void next(byte[] remoteQC, byte[] KS) throws Exception {
        this.Q_S = this.Q_C;
        this.Q_C = remoteQC;
        calculateSharedSecret(this.Q_C);
        calculateHash(KS);
    }

    public void next(Buf buf) throws Exception {
        buf.add_i_get(6);
        byte[] KS = buf.getValue();
        byte[] remoteQS = buf.getValue();
        this.Q_S = remoteQS;
        calculateSharedSecret(this.Q_S);
        calculateHash(KS);
    }

    private void calculateSharedSecret(byte[] remoteKeyBytes) throws Exception {
        if (remoteKeyBytes[0] != 4) throw new Exception("EC Key format not supported");
        int len = (remoteKeyBytes.length - 1) / 2;
        byte[] x = new byte[len];
        byte[] y = new byte[len];
        System.arraycopy(remoteKeyBytes, 1, x, 0, len);
        System.arraycopy(remoteKeyBytes, 1 + len, y, 0, len);

        java.security.PublicKey peerKey = java.security.KeyFactory.getInstance("EC").generatePublic(
            new java.security.spec.ECPublicKeySpec(
                new java.security.spec.ECPoint(new java.math.BigInteger(1, x), new java.math.BigInteger(1, y)),
                params
            )
        );
        myKeyAgree.doPhase(peerKey, true);
        K = new java.math.BigInteger(1, myKeyAgree.generateSecret()).toByteArray();
    }

    private void calculateHash(byte[] K_S) throws Exception {
        Buf buf = new Buf();
        buf.putValue(V_C); buf.putValue(V_S);
        buf.putValue(I_C); buf.putValue(I_S);
        buf.putValue(K_S);
        buf.putValue(Q_C); buf.putValue(Q_S);
        buf.putValue(K);
        sha.update(buf.getValueAllLen());
        H = sha.digest();
    }

    private byte[] toPaddedBytes(java.math.BigInteger bi, int length) {
        byte[] bytes = bi.toByteArray();
        if (bytes.length == length) return bytes;
        if (bytes.length > length) {
            if (bytes[0] == 0 && bytes.length == length + 1) {
                byte[] res = new byte[length];
                System.arraycopy(bytes, 1, res, 0, length);
                return res;
            }
        } else if (bytes.length < length) {
            byte[] res = new byte[length];
            System.arraycopy(bytes, 0, res, length - bytes.length, bytes.length);
            return res;
        }
        return bytes;
    }
}

class Buf {
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
        return (getByte() & 0xff) << 24 | (getByte() & 0xff) << 16 | (getByte() & 0xff) << 8 | (getByte() & 0xff);
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
        return buffer[5];
    }
}

class TesteSSH {
    static final String LOCAL  = "SSHMINI_LOCAL_OK";
    static final String REMOTO = "SSHMINI_REMOTO_OK";

    // AUTO-TESTE (loopback contra o servidor local da 3004): roda uma bateria de validacoes,
    // marcando [OK]/[FALHA] em cada uma. Shell local = cmd.exe (Windows) ou bash (Linux).
    static void runAuto(String cliCmd) {
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        String shell = win ? "cmd.exe" : "/bin/bash";
        String sep   = win ? " & " : " ; ";
        StringBuilder out = new StringBuilder();
        int ok = 0, total = 0;
        try {
            Process p = new ProcessBuilder(shell).redirectErrorStream(true).start();
            Thread leitor = leitor(p, out);
            leitor.start();
            try (java.io.PrintWriter w = new java.io.PrintWriter(new java.io.OutputStreamWriter(p.getOutputStream()))) {
                // lanca o cliente; ao encerrar, o shell local roda "echo LOCAL" (mesma linha)
                enviar(w, out, cliCmd + sep + "echo " + LOCAL, 1000, 1000, 25000);
                // ---- validacoes no shell REMOTO (echo/whoami/exit funcionam em cmd e bash) ----
                total++; if (check(w, out, "echo " + REMOTO, REMOTO, "echo remoto devolve o texto")) ok++;
                total++; if (check(w, out, "whoami", System.getProperty("user.name"), "whoami traz o usuario do remoto")) ok++;
                // (o 'y help | y grep only -> -onlyDiff' e validado pela sessao do ssh real la embaixo,
                //  que nao sofre o can_print nem o falso-positivo do eco do comando)
                // sai da sessao -> cliente encerra -> shell local imprime LOCAL
                enviar(w, out, "exit", 300, 900, 15000);
            }
            p.waitFor();
            leitor.join();
            // ---- validacao: voltou ao shell LOCAL depois do exit ----
            total++;
            boolean localOk = out.toString().contains(LOCAL);
            System.out.println((localOk ? "[OK]    " : "[FALHA] ") + "voltou ao shell local apos o exit");
            if (localOk) ok++;
            // ---- validacao: PID do host != PID do shell da sessao (processo separado) ----
            total++;
            long hostPid  = ProcessHandle.current().pid();
            long shellPid = Session.ultimoShellPid;
            boolean pidOk = shellPid > 0 && shellPid != hostPid;
            System.out.println((pidOk ? "[OK]    " : "[FALHA] ") + "PID host (" + hostPid + ") difere do PID da sessao (" + shellPid + ")");
            if (pidOk) ok++;
            // ---- validacoes via cliente OpenSSH REAL (loga na 3004 e roda os testes internos) ----
            int[] rssh = checkSshReal(win);
            ok += rssh[0]; total += rssh[1];
            // ---- resumo ----
            System.out.println("---- " + ok + "/" + total + " checks OK"
                + (ok == total ? "  => AUTO-TESTE OK (" + (win ? "windows/cmd" : "linux/bash") + ")" : "  => FALHOU") + " ----");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Envia um comando ao remoto e marca [OK] se a saida nova contiver 'esperado'.
    static boolean check(java.io.PrintWriter w, StringBuilder out, String cmd, String esperado, String nome) {
        int pos; synchronized (out) { pos = out.length(); }
        enviar(w, out, cmd, 300, 900, 20000);
        String novo; synchronized (out) { novo = out.substring(Math.min(pos, out.length())); }
        boolean ok = esperado != null && !esperado.isEmpty() && novo.contains(esperado);
        System.out.println((ok ? "[OK]    " : "[FALHA] ") + nome + (ok ? "" : "  (esperava conter \"" + esperado + "\")"));
        return ok;
    }

    // Teste contra servidor EXTERNO (alvo informado): confere so o round-trip remoto -> volta ao local.
    static void run(String cliCmd) {
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        String shell = win ? "cmd.exe" : "/bin/bash";
        String sep   = win ? " & " : " ; ";
        StringBuilder out = new StringBuilder();
        try {
            Process p = new ProcessBuilder(shell).redirectErrorStream(true).start();
            Thread leitor = leitor(p, out);
            leitor.start();
            try (java.io.PrintWriter w = new java.io.PrintWriter(new java.io.OutputStreamWriter(p.getOutputStream()))) {
                enviar(w, out, cliCmd + sep + "echo " + LOCAL, 1000, 1000, 25000);
                enviar(w, out, "echo " + REMOTO, 300, 900, 25000);
                enviar(w, out, "exit", 300, 900, 15000);
            }
            p.waitFor();
            leitor.join();
            if (checkOrder(out.toString(), new String[]{ REMOTO, LOCAL })) {
                System.out.println("OK (" + (win ? "windows/cmd" : "linux/bash") + ")");
            } else {
                System.out.println("--- CONTEUDO INTEIRO ---");
                System.out.println(">>>>\n" + out + "\n<<<<");
                System.out.println("------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Thread que copia toda a saida do shell para 'out'.
    static Thread leitor(Process p, StringBuilder out) {
        return new Thread(() -> {
            try (java.io.Reader r = new java.io.InputStreamReader(p.getInputStream())) {
                char[] b = new char[4096];
                int n;
                while ((n = r.read(b)) != -1)
                    synchronized (out) { out.append(b, 0, n); }
            } catch (Exception e) {}
        });
    }

    // Envia um comando e espera a saida "assentar": aguarda aparecer saida nova e ficar quieta por
    // quietMs (respeitando minMs e teto maxMs). Independe de prompt: serve p/ cmd e bash.
    static void enviar(java.io.PrintWriter w, StringBuilder out, String cmd, long minMs, long quietMs, long maxMs) {
        int pos; synchronized (out) { pos = out.length(); }
        w.println(cmd);
        w.flush();
        long inicio = System.currentTimeMillis();
        long ultima = inicio;
        int anterior = pos;
        while (System.currentTimeMillis() - inicio < maxMs) {
            try { Thread.sleep(80); } catch (Exception e) {}
            int tam; synchronized (out) { tam = out.length(); }
            if (tam != anterior) { anterior = tam; ultima = System.currentTimeMillis(); }
            long agora = System.currentTimeMillis();
            if (tam > pos && agora - inicio >= minMs && agora - ultima >= quietMs) return;
        }
    }

    // Loga na 3004 pelo cliente OpenSSH REAL (senha via SSH_ASKPASS) e roda os MESMOS testes internos
    // pela sessao do ssh: echo, whoami, y e escadinha (todo \n do pty deve chegar como \r\n). Se a senha nao puder ser automatizada aqui (ex.: askpass
    // indisponivel no Windows), cai no fallback de validar so o handshake (BatchMode). Retorna {ok,total}.
    static int[] checkSshReal(boolean win) {
        try { Process v = new ProcessBuilder("ssh", "-V").redirectErrorStream(true).start(); v.getInputStream().readAllBytes(); v.waitFor(); }
        catch (Exception e) {
            System.out.println("[PULADO] ssh real -p 3004 (cliente 'ssh' nao encontrado)");
            return new int[]{0, 0};
        }
        int ok = 0, total = 0;
        String devnull = win ? "NUL" : "/dev/null";
        String tok = "SSHREAL_ECHO_OK";
        String yline = win
            ? "where y >nul 2>nul && (y help | y grep only) || echo SSHREAL_YNAO"
            : "command -v y >/dev/null 2>&1 && y help | y grep only || echo SSHREAL_YNAO";
        String script = "echo " + tok + "\nwhoami\n" + yline + "\nexit\n";
        String saida = "";
        java.io.File ask = null;
        try {
            ask = java.io.File.createTempFile("sshmini_askpass", win ? ".bat" : ".sh");
            java.nio.file.Files.writeString(ask.toPath(), win ? "@echo off\r\necho admin123\r\n" : "#!/bin/sh\necho admin123\n");
            ask.setExecutable(true);
            // -tt: forca a alocacao de pty mesmo com stdin em pipe. E o cenario do ssh interativo
            // real e exercita o ONLCR do servidor (LF -> CRLF), validado no check de escadinha.
            ProcessBuilder pb = new ProcessBuilder("ssh", "-tt",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=" + devnull,
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10",
                "-p", "3004", "admin@localhost");
            // stderr do PROPRIO ssh (warnings de known_hosts etc.) fica de fora: ele usa \n proprio
            // e contaminaria o check de escadinha, que mede so o que veio do canal (stdout).
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            pb.environment().put("SSH_ASKPASS", ask.getAbsolutePath());
            pb.environment().put("SSH_ASKPASS_REQUIRE", "force");
            pb.environment().put("DISPLAY", ":0");
            Process ps = pb.start();
            ps.getOutputStream().write(script.getBytes());
            ps.getOutputStream().flush(); ps.getOutputStream().close();
            StringBuilder sb = new StringBuilder();
            Thread rd = new Thread(() -> {
                try (java.io.Reader r = new java.io.InputStreamReader(ps.getInputStream())) {
                    char[] b = new char[4096]; int n;
                    while ((n = r.read(b)) != -1) sb.append(b, 0, n);
                } catch (Exception e) {}
            });
            rd.start();
            if (!ps.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) ps.destroyForcibly();
            rd.join(2000);
            saida = sb.toString();
        } catch (Exception e) { saida = "erro: " + e; }
        finally { if (ask != null) ask.delete(); }

        boolean logou = saida.contains(tok);   // o echo so ecoa/roda se conectou E autenticou
        if (logou) {
            total++; ok++; System.out.println("[OK]    ssh real: login por senha + echo (host key ECDSA aceita)");
            boolean w = saida.contains(System.getProperty("user.name"));
            total++; if (w) ok++; System.out.println((w ? "[OK]    " : "[FALHA] ") + "ssh real: whoami traz o usuario");
            if (saida.contains("-onlyDiff")) { total++; ok++; System.out.println("[OK]    ssh real: y help | y grep only -> -onlyDiff"); }
            else if (saida.contains("SSHREAL_YNAO")) System.out.println("[PULADO] ssh real: y help | y grep only ('y' nao existe)");
            else { total++; System.out.println("[FALHA] ssh real: y help | y grep only (esperava -onlyDiff)"); }
            // ---- escadinha: com pty (-tt), TODO \n do servidor deve chegar como \r\n (ONLCR). ----
            // Sem a conversao, programa que imprime so \n (ex.: y ls) desenha escadinha no ssh real.
            // Removendo os \r\n corretos, nao pode sobrar \n orfao; e \r\r acusaria conversao dupla.
            total++;
            boolean escadaOk = !saida.replace("\r\n", "").contains("\n") && !saida.contains("\r\r");
            System.out.println((escadaOk ? "[OK]    " : "[FALHA] ") + "ssh real: sem escadinha (todo \\n do pty chegou como \\r\\n)");
            if (escadaOk) ok++;
        } else {
            boolean hs = handshakeBatch(win, devnull);
            total++; if (hs) ok++;
            System.out.println((hs ? "[OK]    " : "[FALHA] ") + "ssh real: conecta + aceita host key ECDSA (handshake; senha nao automatizada neste host)");
        }
        return new int[]{ok, total};
    }

    // Fallback: valida so o handshake (BatchMode, sem senha) - host key ECDSA aceita e auth oferecida.
    static boolean handshakeBatch(boolean win, String devnull) {
        try {
            Process ps = new ProcessBuilder("ssh", "-v",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=" + devnull,
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", "3004", "admin@localhost")
                .redirectErrorStream(true).start();
            ps.getOutputStream().close();
            StringBuilder sb = new StringBuilder();
            Thread rd = new Thread(() -> {
                try (java.io.Reader r = new java.io.InputStreamReader(ps.getInputStream())) {
                    char[] b = new char[4096]; int n;
                    while ((n = r.read(b)) != -1) sb.append(b, 0, n);
                } catch (Exception e) {}
            });
            rd.start();
            if (!ps.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)) ps.destroyForcibly();
            rd.join(2000);
            String s = sb.toString();
            return s.contains("Authentications that can continue") || s.contains("Permission denied (")
                || s.contains("Server host key: ecdsa-sha2-nistp256");
        } catch (Exception e) { return false; }
    }

    // Envolve o System.out: recua 8 espacos toda linha que NAO comeca com "[" (mensagens do
    // servidor e o resumo ficam recuados; os [OK]/[FALHA]/[PULADO] ficam na margem). Linhas em
    // branco nao sao recuadas. Como cada println e atomico no PrintStream, bufferizar por linha
    // e seguro mesmo com o servidor imprimindo de outra thread.
    static java.io.PrintStream indentador(java.io.PrintStream base) {
        return new java.io.PrintStream(new java.io.OutputStream() {
            final StringBuilder linha = new StringBuilder();
            public void write(int b) {
                if (b == '\n') {
                    String s = linha.toString();
                    linha.setLength(0);
                    String t = s.trim();
                    if (!t.isEmpty() && !t.startsWith("[")) base.print("        ");
                    base.print(s);
                    base.print('\n');
                } else {
                    linha.append((char) b);
                }
            }
        }, true);
    }

    static boolean checkOrder(String text, String[] sequences) {
        int lastIndex = -1;
        for (String seq : sequences) {
            int currentIndex = text.indexOf(seq, lastIndex + 1);
            if (currentIndex == -1) {
                System.out.println("FALHA, nao foi possivel encontrar a palavra " + seq + "\n");
                return false;
            }
            lastIndex = currentIndex;
        }
        return true;
    }
}
