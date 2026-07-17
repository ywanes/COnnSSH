// Usage:
//   java SSHMini.java
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
//     --- conexao por arquivo de chave (pubkey): classico ed25519 e pos-quantico mldsa44 ---
//   java SSHMini.java -sshgen ed25519 id_ed25519                 gera 'id_ed25519' + 'id_ed25519.pub'
//   java SSHMini.java -sshgen mldsa44-ed25519 id_mldsa44_ed25519 idem, pos-quantico (hibrido)
//   java SSHMini.java -sshgen ed25519 id_ed25519 -pass "sua frase"   geracao deterministica (PBKDF2)
//   java SSHMini.java -sshgen ed25519 id_ed25519 -C "comentario1"     define o comentario (default: usuario@host; nao afeta a chave)
//   java SSHMini.java -sshgen ed25519                            so imprime a chave publica (nao grava)
//   java SSHMini.java admin@10.0.0.1 -i id_ed25519 -P 333        cliente: login por chave (senha ignorada)
//   java SSHMini.java admin@10.0.0.1 -i id_ed25519 -hostpub ssh_host_key.pub -P 333   idem + verifica/pina a host key (anti-MITM)
//   (-hostpub pode REPETIR e cada arquivo aceita varias linhas: pina ed25519 E mldsa44 juntas; casa a que o servidor apresentar)
//   java SSHMini.java -server admin,admin123@localhost -hostkey ssh_host_key -authkeys authorized_keys -P 333
//                                                                servidor: host key por arquivo + login por chave
//   (authorized_keys aceita varias linhas e tipos misturados: ed25519 e mldsa44 juntos)
//
//   ssh -p 333 user1@10.0.0.1
//   ssh -i id_ed25519 -p 333 admin@10.0.0.1                      cliente OpenSSH nativo usando a chave gerada (ed25519)
//
//     GRAALVM
//     1) javac SSHMini.java
//     2) java -agentlib:native-image-agent=config-output-dir=nic -cp . SSHMini -test   (captura a config)
//     3) native-image --no-fallback -H:ConfigurationFileDirectories=nic --initialize-at-run-time=Session -cp . SSHMini -o sshmini
//
public class SSHMini {
    public static void main(String[] args) throws Exception {
        String mode = "client";
        String access = null;
        int port = -1;
        String statusFile = null;
        String passphrase = null, identityFile = null, hostKeyFile = null, authKeysFile = null, comentario = null;
        java.util.List<String> pos = new java.util.ArrayList<String>();   // args posicionais (alvo, ou tipo/nome do -sshgen)
        java.util.List<String> hostPubFiles = new java.util.ArrayList<String>();   // -hostpub (pode repetir): host keys pinadas
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("-server")) {
                mode = "server";
            } else if (a.equals("-test")) {
                mode = "test";
            } else if (a.equals("-sshgen")) {   // gera par de chaves (ed25519 ou mldsa44-ed25519)
                mode = "sshgen";
            } else if (a.equals("-pass")) {     // passphrase p/ geracao deterministica (-sshgen)
                if (i + 1 >= args.length) { erro("-pass exige a passphrase"); return; }
                passphrase = args[++i];
            } else if (a.equals("-C")) {        // comentario da chave gerada (-sshgen), estilo ssh-keygen -C
                if (i + 1 >= args.length) { erro("-C exige o comentario"); return; }
                comentario = args[++i];
            } else if (a.equals("-i")) {        // cliente: chave privada para login por chave (conexao por file)
                if (i + 1 >= args.length) { erro("-i exige o caminho da chave privada"); return; }
                identityFile = args[++i];
            } else if (a.equals("-hostkey")) {  // servidor: host key gerada por arquivo (em vez da ECDSA fixa)
                if (i + 1 >= args.length) { erro("-hostkey exige o caminho da host key"); return; }
                hostKeyFile = args[++i];
            } else if (a.equals("-authkeys")) { // servidor: authorized_keys aceitos no login por chave
                if (i + 1 >= args.length) { erro("-authkeys exige o caminho do authorized_keys"); return; }
                authKeysFile = args[++i];
            } else if (a.equals("-hostpub")) {  // cliente: pino da host key (.pub) — pode repetir p/ aceitar varias
                if (i + 1 >= args.length) { erro("-hostpub exige o caminho do .pub da host key"); return; }
                hostPubFiles.add(args[++i]);
            } else if (a.equals("-ctrlcselftest")) {   // modo interno do auto-teste (Ctrl+C real no Windows)
                mode = "ctrlcselftest";
                if (i + 1 >= args.length) { erro("-ctrlcselftest exige o caminho do arquivo de status"); return; }
                statusFile = args[++i];
            } else if (a.equals("-rawlog")) {   // debug: grava os bytes CRUS recebidos do servidor no arquivo dado
                if (i + 1 >= args.length) { erro("-rawlog exige o caminho do arquivo"); return; }
                SSHClientMini.RAWLOG = args[++i];
            } else if (a.equals("-killlog")) {   // debug (servidor): loga o que o Ctrl+C ve/mata no cmd
                if (i + 1 >= args.length) { erro("-killlog exige o caminho do arquivo"); return; }
                Session.KILLLOG = args[++i];
            } else if (a.equals("-P")) {
                if (i + 1 >= args.length) { erro("-P exige um numero de porta"); return; }
                try {
                    port = Integer.parseInt(args[++i]);
                } catch (Exception e) {
                    erro("porta invalida: " + args[i]); return;
                }
            } else if (!a.startsWith("-")) {
                pos.add(a);
            } else {
                erro("opcao desconhecida: " + a); return;
            }
        }
        access = pos.isEmpty() ? null : pos.get(0);

        if (mode.equals("server")) {
            if (port <= 0) port = 22;                 // servidor de teste
            String user = "admin", pass = "admin123";
            String[] p = parseAccess(access);
            if (p != null) { user = p[0]; pass = p[1]; }
            // Privilege drop AUTOMATICO (sem flag): se o servidor foi iniciado via sudo, o 'sudo' define
            // SUDO_USER com o seu usuario original -> a sessao do cliente cai NELE em vez de root. Assim
            // "sudo java ... -server -P 333" mantem a porta baixa (root) mas quem conecta entra como voce,
            // NAO root. Sem sudo (rodando ja como voce), SUDO_USER nao existe e roda como voce mesmo.
            String su = System.getenv("SUDO_USER");
            if (su != null && !su.isEmpty() && !su.equals("root")) Session.shellUser = su;
            Session.authKeysFile = authKeysFile;   // login por chave: authorized_keys aceitos
            Session.hostKeyFile  = hostKeyFile;    // host key por arquivo (senao, ECDSA fixa)
            System.out.println("Sessao dos clientes cai no usuario: "
                + (Session.shellUser == null ? "(mesmo do servidor)" : Session.shellUser));
            if (authKeysFile != null) System.out.println("Login por chave habilitado (authorized_keys: " + authKeysFile + ")");
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
                TesteSSH.runAuto(caminhoFonte(args), portaAuto);
                System.exit(0);
            }
            // -test <alvo> e/ou -P -> testa um servidor EXTERNO (precisa ja estar no ar)
            if (port <= 0) port = 22;
            String alvo = resolverAcesso(access);
            if (alvo == null) return;
            String _jar = "java \"" + caminhoFonte(args) + "\" " + alvo + " -P " + port;   // caminho real do fonte: roda de qualquer dir
            TesteSSH.run(_jar);
        } else if (mode.equals("sshgen")) {
            // Gera par de chaves em caminho DINAMICO (nome/dir informado; nada hardcoded).
            //   -sshgen <tipo> <nome>   grava <nome> e <nome>.pub
            //   -sshgen <tipo>          imprime so a publica (nao grava)
            //   -pass <phrase>          torna a geracao deterministica (PBKDF2)
            //   -C "<comentario>"       comentario da chave (default: usuario@host); nao afeta a chave
            if (pos.isEmpty()) { erro("-sshgen exige o tipo: ed25519 | mldsa44-ed25519 [nome]"); return; }
            String tipo = pos.get(0);
            String nome = pos.size() > 1 ? pos.get(1) : "";
            String com = (comentario != null) ? comentario : usuarioArroba();   // comentario independente do nome
            SshKeys keys = new SshKeys();
            String[] par;
            try { par = keys.generate(tipo, passphrase, nome, com); }
            catch (Exception e) { erro(e.getMessage()); return; }
            if (nome.isEmpty()) {
                System.out.print(par[1]);              // so a publica (nao grava arquivo)
            } else {
                java.nio.file.Files.writeString(java.nio.file.Path.of(nome), par[0]);
                java.nio.file.Files.writeString(java.nio.file.Path.of(nome + ".pub"), par[1]);
                try { java.nio.file.Files.setPosixFilePermissions(java.nio.file.Path.of(nome),
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); } catch (Throwable t) {}
                System.out.println("Chave gerada (" + tipo + "):");
                System.out.println("  privada: " + java.nio.file.Path.of(nome).toAbsolutePath());
                System.out.println("  publica: " + java.nio.file.Path.of(nome + ".pub").toAbsolutePath());
                System.out.print(par[1]);
            }
        } else if (mode.equals("ctrlcselftest")) {
            if (port <= 0) port = 22;
            new SSHClientMini("localhost", "admin", port, "admin123", statusFile);   // conecta e espera o sinal real
        } else {
            if (port <= 0) port = 22;                   // cliente: porta SSH padrao
            SSHClientMini.HOSTPUB = hostPubFiles;        // pinos da host key (um ou varios), se informados
            if (identityFile != null) {
                // login por CHAVE (conexao por file): alvo = usuario@host (senha ignorada; nao pergunta)
                String alvo = (access != null) ? access : autoAccess();
                int at = alvo.lastIndexOf('@');
                if (at < 0) { erro("informe usuario@host para login por chave"); return; }
                String up = alvo.substring(0, at); int vc = up.indexOf(',');
                String user = (vc >= 0) ? up.substring(0, vc) : up;
                String host = alvo.substring(at + 1);
                try {
                    new SSHClientMini(host, user, port, identityFile, true);
                } catch (Exception e) {
                    System.err.println(e.toString().contains("UserAuth Fail") ? "UserAuth Fail!!" : e.toString());
                }
                System.exit(0);
            }
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

    // usuario@host: comentario default da chave gerada (-sshgen sem -C), estilo ssh-keygen. Robusto a falhas.
    static String usuarioArroba() {
        String u = System.getProperty("user.name", "user");
        String h;
        try { h = java.net.InetAddress.getLocalHost().getHostName(); } catch (Throwable t) { h = "localhost"; }
        if (h == null || h.isEmpty()) h = "localhost";
        return u + "@" + h;
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
    // lastCtrlC: instante do ultimo Ctrl+C (INT/BREAK). O writing_stdin usa isto p/ distinguir o read
    // abortado pelo Ctrl+C do console (Windows) de um EOF de verdade — e assim NAO sair da sessao.
    private volatile long lastCtrlC = 0;
    // Modo -ctrlcselftest (auto-teste do Ctrl+C real no Windows): o cliente conecta sozinho, roda um
    // comando que dorme, publica marcadores (PID/RUN/DONE) no statusFile e fica vivo esperando o sinal.
    private boolean selfTest = false;
    private String statusFile = null;
    // Login por chave (conexao por file): caminho do privado openssh-key-v1; null = login por senha.
    private String identityFile = null;
    private SshKeys keys = null;
    private final StringBuilder sctAcc = new StringBuilder();
    private boolean sctRun = false, sctDone = false;
    private boolean verbose = false;
    // Debug: se a variavel de ambiente SSHMINI_RAWLOG apontar um arquivo, grava os bytes CRUS recebidos
    // do servidor (antes de qualquer filtro de eco). Diagnostico do "terminal estranho": apos um Ctrl+C,
    // mostra se o servidor MANDOU a saida do comando (ai o problema e EXIBIR, lado cliente) ou NAO (lado
    // servidor), e se os bytes de acento mudaram (code page). Ex.: set SSHMINI_RAWLOG=Z:\sshcustom\raw.log
    static String RAWLOG = System.getenv("SSHMINI_RAWLOG");   // tambem setavel pela flag -rawlog (ver SSHMini.main)
    // Pinos da host key (-hostpub <arquivo.pub>, pode repetir; cada arquivo aceita varias linhas):
    // se nao-vazio, o cliente EXIGE que a host key apresentada seja UMA das pinadas E que a assinatura
    // sobre H confira. Aceitar varias permite pinar ed25519 E mldsa44 juntas (rotacao/PQ). Fecha o MITM.
    static java.util.List<String> HOSTPUB = new java.util.ArrayList<String>();
    private ECDH kex = null;
    private java.security.SecureRandom random = null;

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("uso: java SSHClientMini <host> <usuario> <porta> <senha>");
            return;
        }
        new SSHClientMini(args[0], args[1], Integer.parseInt(args[2]), args[3]);
    }

    // Marca este processo como um CLIENTE SSHMini VIVO (arquivo no temp, keyed pelo PID). O servidor usa
    // p/ saber que um comando java em foreground e um cliente ANINHADO -> repassa o Ctrl+C (0x03) pro stdin
    // dele em vez de matar (senao a sessao aninhada "escapa"). Necessario no Windows, onde o
    // ProcessHandle.commandLine() vem VAZIO (nao da p/ ver o "SSHMini" nos args). deleteOnExit limpa no exit/EOF.
    private static void marcaClienteVivo() {
        try {
            java.io.File m = new java.io.File(System.getProperty("java.io.tmpdir"), "sshmini_client_" + ProcessHandle.current().pid());
            m.createNewFile();
            m.deleteOnExit();
        } catch (Throwable t) {}
    }
    public SSHClientMini(String host, String username, int port, String password) throws Exception {
        marcaClienteVivo();   // marca este PID como cliente SSHMini vivo (servidor repassa o Ctrl+C em vez de matar)
        V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
        kex = new ECDH();
        connect_stream(host, username, port, password);
        new Thread() { public void run() {
            reading_stream();
        }}.start();
        connect_stdin();
        writing_stdin();
    }

    // Cliente com login por CHAVE (conexao por file): identityFile aponta o privado openssh-key-v1.
    // A senha nao e usada (autenticacao por assinatura). O boolean keyMode desambigua do construtor
    // de -ctrlcselftest (que tem statusFile String na mesma posicao).
    public SSHClientMini(String host, String username, int port, String identityFile, boolean keyMode) throws Exception {
        this.identityFile = identityFile;
        marcaClienteVivo();
        V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
        kex = new ECDH();
        connect_stream(host, username, port, null);
        new Thread() { public void run() {
            reading_stream();
        }}.start();
        connect_stdin();
        writing_stdin();
    }

    // Modo auto-teste do Ctrl+C real (usado pelo -test no Windows): conecta, instala os handlers de
    // sinal, publica o PID, dispara um comando que dorme e fica VIVO esperando o sinal REAL do -test.
    // NAO le stdin (o cliente e dirigido por si mesmo) para o teste independer do tipo de stdin do start /b.
    public SSHClientMini(String host, String username, int port, String password, String statusFile) throws Exception {
        marcaClienteVivo();
        this.statusFile = statusFile;
        this.selfTest = true;
        V_C = "SSH-2.0-CUSTOM".getBytes("UTF-8");
        kex = new ECDH();
        connect_stream(host, username, port, password);
        new Thread() { public void run() {
            reading_stream();
        }}.start();
        connect_stdin();
        instalaCtrlC();                                        // handlers de INT e BREAK
        sctMark("PID " + ProcessHandle.current().pid());       // o -test le o PID p/ mirar o sinal so neste grupo
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        // marca RUN, dorme ~2s e SO ENTAO marca DONE (via &&): se o sinal interromper, DONE nunca sai.
        sendLine(win ? "echo SCT_RUN& ping -n 3 127.0.0.1 >nul && echo SCT_DONE"
                     : "echo SCT_RUN; sleep 2 && echo SCT_DONE");
        try { Thread.sleep(10000); } catch (Exception e) {}    // fica vivo p/ o sinal chegar e ser tratado
        sctMark("EXIT");
        System.exit(0);
    }

    // Acrescenta uma linha ao statusFile do auto-teste (linhas curtas em append; o -test faz polling).
    private synchronized void sctMark(String linha) {
        if (statusFile == null) return;
        try {
            java.nio.file.Files.writeString(java.nio.file.Paths.get(statusFile), linha + "\n",
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {}
    }

    // Envia UMA linha de comando como CHANNEL_DATA (mesmo formato do writing_stdin, mas sem ler stdin).
    private void sendLine(String cmd) throws Exception {
        byte[] c = (cmd + "\r\n").getBytes("UTF-8");
        Buf b = new Buf(new byte[c.length + 64]);
        int off = 14;
        System.arraycopy(c, 0, b.buffer, off, c.length);
        for (int j = 0; j < off; j++) b.buffer[j] = 0;
        ecoPendente = true;
        b.reset_command(SSH_MSG_CHANNEL_DATA);
        b.putInt(0);
        b.putInt(c.length);
        b.i_put += c.length;
        write(b);
    }

    // ecoPendente e escrito pela thread principal (writing_stdin) e lido pela reading_stream.
    // Apos enviar uma linha, a primeira coisa que volta e o eco dela (do servidor no cmd.exe;
    // do proprio bash -i no linux). O terminal local ja mostrou a digitacao, entao o eco e
    // suprimido ATE O PRIMEIRO \n — por CONTEUDO, nao por pacote: o eco pode chegar colado com
    // a saida do comando no mesmo pacote (ex.: echo, builtin instantaneo do bash) e a antiga
    // supressao do pacote inteiro (can_print) engolia a saida do comando junto.
    private volatile boolean ecoPendente = false;
    private byte[] filtraEcoDoComando(byte[] a) {
        if (!ecoPendente)
            return a;
        for (int k = 0; k < a.length; k++) {
            if (a[k] == barra_n) {
                ecoPendente = false;
                return java.util.Arrays.copyOfRange(a, k + 1, a.length);
            }
        }
        return new byte[0];   // a linha do eco ainda nao terminou: continua suprimindo
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
        // Verificacao da host key (se -hostpub): a chave apresentada tem de ser a pinada E a
        // assinatura sobre H tem de conferir. So p/ os tipos suportados (ed25519/mldsa); ECDSA fixa
        // do proprio SSHMini nao e verificada aqui (fluxo legado sem pino).
        if (HOSTPUB != null && !HOSTPUB.isEmpty()) {
            if (keys == null) keys = new SshKeys();
            java.util.List<byte[]> pinos = keys.parsePubFiles(HOSTPUB);   // varios arquivos, cada um c/ varias linhas
            boolean confere = false;
            for (byte[] b : pinos) if (java.util.Arrays.equals(b, kex.hostKeyBlob)) { confere = true; break; }
            if (!confere)
                throw new Exception("host key nao confere com nenhum pino (-hostpub)");
            if (kex.hostSig == null || !keys.verifyBlob(kex.hostKeyBlob, kex.H, kex.hostSig))
                throw new Exception("assinatura da host key invalida");
        }
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

        buf = read();   // SERVICE_ACCEPT
        if (identityFile != null) {
            // ---- login por CHAVE (publickey, RFC 4252 §7) ----
            if (keys == null) keys = new SshKeys();
            SshKeys.Priv pv = keys.parsePriv(java.nio.file.Files.readString(java.nio.file.Path.of(identityFile)));
            // blob assinado: session_id ‖ 50 ‖ user ‖ "ssh-connection" ‖ "publickey" ‖ TRUE ‖ alg ‖ pubkey
            Buf sb = new Buf();
            sb.putValue(kex.H);
            sb.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
            sb.putString(username);
            sb.putString("ssh-connection");
            sb.putString("publickey");
            sb.putByte((byte) 1);
            sb.putString(pv.type);
            sb.putValue(pv.pubBlob);
            byte[] signed = java.util.Arrays.copyOfRange(sb.buffer, 0, sb.i_put);
            byte[] sig = keys.signSSH(pv.type, pv.seeds, signed);
            buf.reset_command(SSH_MSG_USERAUTH_REQUEST);
            buf.putString(username);
            buf.putString("ssh-connection");
            buf.putString("publickey");
            buf.putByte((byte) 1);
            buf.putString(pv.type);
            buf.putValue(pv.pubBlob);
            buf.putValue(sig);
            write(buf);
        } else {
            // ---- login por SENHA (existente) ----
            buf.reset_command(SSH_MSG_USERAUTH_REQUEST);
            buf.putString(username);
            buf.putString("ssh-connection");
            buf.putString("password");
            buf.putByte((byte) 0);
            buf.putString(password);
            write(buf);
        }

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
                    if (RAWLOG != null) {   // grava os bytes CRUS do servidor (diagnostico do "terminal estranho")
                        try { java.nio.file.Files.write(java.nio.file.Paths.get(RAWLOG), a,
                                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND); }
                        catch (Exception e) {}
                    }
                    if (a.length == 0)   // CHANNEL_DATA vazio nao e fim de sessao (fim e CHANNEL_EOF): ignora, nao sai
                        continue;
                    if (texto_oculto(a))
                        continue;
                    if (selfTest) {   // -ctrlcselftest: detecta por POSICAO (inicio de linha) o RUN/DONE do comando
                        sctAcc.append(new String(a, java.nio.charset.StandardCharsets.UTF_8));
                        if (!sctRun  && (sctAcc.indexOf("\nSCT_RUN")  >= 0 || sctAcc.indexOf("\rSCT_RUN")  >= 0)) { sctRun  = true; sctMark("RUN"); }
                        if (!sctDone && (sctAcc.indexOf("\nSCT_DONE") >= 0 || sctAcc.indexOf("\rSCT_DONE") >= 0)) { sctDone = true; sctMark("DONE"); }
                    }
                    byte[] visivel = filtraEcoDoComando(a);
                    if (visivel.length > 0) {
                        System.out.write(visivel);
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

    // Ctrl+C no terminal local: em vez de ENCERRAR a JVM do cliente (o SIGINT padrao mataria a
    // aplicacao), envia o byte VINTR (0x03) pelo canal. O pty do servidor gera entao o SIGINT no
    // comando remoto — como faz um ssh de verdade. Para SAIR da sessao use 'exit' ou Ctrl+D.
    private void instalaCtrlC() {
        instalaSinal("INT");     // Ctrl+C
        instalaSinal("BREAK");   // Ctrl+Break: no auto-teste do Windows o sinal REAL chega como BREAK
    }                            // (o cliente roda no proprio grupo e o -test dispara CTRL_BREAK nele)
    private void instalaSinal(String nome) {
        try {
                        // Signal com warning inevitavel para javac
            sun.misc.Signal.handle(new sun.misc.Signal(nome), s -> {
                lastCtrlC = System.currentTimeMillis();   // marca p/ o writing_stdin NAO tratar o read abortado como EOF
                try {
                    Buf b = new Buf();
                    b.reset_command(SSH_MSG_CHANNEL_DATA);
                    b.putInt(0);           // canal
                    b.putInt(1);           // 1 byte de dados
                    b.putByte((byte) 3);   // VINTR (Ctrl+C)
                    write(b);
                } catch (Exception e) {}
            });
        } catch (Throwable t) { /* VM/plataforma sem esse sinal (ex.: BREAK no linux): ignora */ }
    }
    private void writing_stdin() throws Exception {
        instalaCtrlC();   // Ctrl+C passa a interromper o comando REMOTO, sem matar o cliente
        Buf buf = new Buf(new byte[rmpsize]);
        int i = 0;
        int off = 14;
        while (true) {
            try {
                i = System.in.read(buf.buffer, off, buf.buffer.length - off - 128);
            } catch (java.io.IOException ioe) {
                i = -1;   // Windows: o Ctrl+C aborta o ReadConsole pendente (ERROR_OPERATION_ABORTED)
            }
            if (i < 0) {
                // -1 pode ser EOF real (Ctrl+Z / stdin fechado) OU o Ctrl+C do Windows abortando o read.
                // Sem isto, o Ctrl+C do console fazia o read voltar -1, o laco terminava e o CLIENTE SAIA
                // da sessao (bug). Se um Ctrl+C acabou de acontecer, o 0x03 ja seguiu pelo handler: nao e
                // EOF -> CONTINUA a sessao (recomeca a leitura). So encerra no EOF de verdade.
                try { Thread.sleep(120); } catch (Exception e) {}   // deixa o handler marcar o Ctrl+C
                if (System.currentTimeMillis() - lastCtrlC < 2000) continue;
                break;
            }
            if (i == 0)   // nada lido: nao mexe no buffer (i-2+off apontaria pro cabecalho)
                continue;
            if (i == 1 && (buf.buffer[off] & 0xff) == 3) {   // VINTR (0x03) solto no stdin (ex.: pipe / -test)
                // repassa o 0x03 CRU (mesmo pacote do instalaCtrlC), sem virar \r\n: assim um Ctrl+C que
                // chega como BYTE — e nao como sinal — tambem interrompe o comando remoto em foreground.
                Buf b = new Buf();
                b.reset_command(SSH_MSG_CHANNEL_DATA);
                b.putInt(0);           // canal
                b.putInt(1);           // 1 byte de dados
                b.putByte((byte) 3);   // VINTR (Ctrl+C)
                write(b);
                continue;
            }
            if (buf.buffer[i-2+off] != barra_r || buf.buffer[i-1+off] != barra_n) {
                i++;
                buf.buffer[i-2+off] = barra_r;
                buf.buffer[i-1+off] = barra_n;
            }
            for (int j = 0; j < off; j++)
                buf.buffer[j] = 0;
            debug(buf.buffer, off, i);
            ecoPendente = true;   // a proxima linha recebida e o eco desta: suprime ate o \n
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
        int port = 22;
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
            SSH_MSG_USERAUTH_FAILURE = 51, SSH_MSG_USERAUTH_SUCCESS = 52, SSH_MSG_USERAUTH_PK_OK = 60,
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
    // Login por chave (conexao por file): authorized_keys aceitos e host key por arquivo (setados no main).
    static String authKeysFile = null, hostKeyFile = null;
    private SshKeys sshKeys = null;                 // cripto de chave (lazy)
    private SshKeys.Priv hostKey = null;            // host key carregada de -hostkey (senao, ECDSA fixa)
    private byte[] sessionId = null;                // = kex.H do primeiro KEX (usado no blob do publickey)
    private SshKeys sshKeys() { if (sshKeys == null) sshKeys = new SshKeys(); return sshKeys; }
    // pubBlob esta autorizado? (compara byte-a-byte com as linhas do authorized_keys)
    private boolean pubKeyAutorizada(byte[] pubBlob) {
        if (authKeysFile == null) return false;
        try {
            for (String ln : java.nio.file.Files.readAllLines(java.nio.file.Path.of(authKeysFile))) {
                ln = ln.trim(); if (ln.isEmpty() || ln.startsWith("#")) continue;
                String[] p = ln.split("\\s+"); if (p.length < 2) continue;
                if (java.util.Arrays.equals(java.util.Base64.getDecoder().decode(p[1]), pubBlob)) return true;
            }
        } catch (Exception e) {}
        return false;
    }

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
        if (shellProcess != null) {
            // Encerra a ARVORE do shell (descendentes + o proprio), nao so o processo direto: no Linux
            // o shellProcess e o 'script', que roda um 'bash' dentro de um pty; um destroy() so no
            // 'script' deixa o 'bash' e o /dev/pts ORFAOS. Vazando por sessao, alguns -test esgotam os
            // ptys e o sshd do HOST para de alocar terminal (fica "inoperante"). Coleta os descendentes
            // ANTES de matar o pai (senao reparentam pra init e somem da arvore).
            java.util.List<ProcessHandle> arvore = shellProcess.descendants().toList();
            shellProcess.destroy();
            arvore.forEach(ProcessHandle::destroy);
            try { shellProcess.waitFor(2, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception e) {}
            if (shellProcess.isAlive()) shellProcess.destroyForcibly();
            arvore.forEach(h -> { if (h.isAlive()) h.destroyForcibly(); });
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

        // Host key: por arquivo (-hostkey, ed25519/mldsa) ou a ECDSA fixa. O algoritmo anunciado no
        // KEXINIT tem de casar com o tipo da chave, senao o ssh nativo rejeita a negociacao.
        String hostAlg = "ecdsa-sha2-nistp256";
        if (hostKeyFile != null) {
            if (hostKey == null) hostKey = sshKeys().parsePriv(java.nio.file.Files.readString(java.nio.file.Path.of(hostKeyFile)));
            hostAlg = hostKey.type;
        }
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXINIT);
        buf.putBytes(get_random_bytes(16)); // Cookie
        buf.putString("ecdh-sha2-nistp256");
        buf.putString(hostAlg);
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
        byte[] K_S = (hostKey != null) ? hostKey.pubBlob : generateHostKey();
        kex.next(Q_C, K_S);
        sessionId = kex.H;   // identificador de sessao (primeiro KEX) — assinado no publickey auth
        // Assinatura do hash de troca H com a host key: por arquivo (ed25519/mldsa) ou ECDSA fixa.
        byte[] hostSig = (hostKey != null) ? sshKeys().signSSH(hostKey.type, hostKey.seeds, kex.H) : generateSignature();
        buf = new Buf();
        buf.reset_command(SSH_MSG_KEXDH_REPLY);
        buf.putValue(K_S);
        buf.putValue(kex.Q_S);
        buf.putValue(hostSig);
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

        // O OpenSSH manda um probe "none" (e "publickey") antes da senha/chave. Responde FAILURE
        // (oferecendo "publickey,password") ate um metodo aceitar: senha correta OU chave autorizada.
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
            } else if (method.equals("publickey")) {
                byte hasSig = buf.getByte();                      // TRUE = vem assinatura; FALSE = so probe
                String alg = new String(buf.getValue(), "UTF-8"); // nome do algoritmo (= tipo da chave)
                byte[] pubBlob = buf.getValue();                  // string tipo ‖ string chave
                if (hasSig == 0) {   // probe: responde PK_OK ecoando alg+chave (o cliente entao manda assinado)
                    Buf pk = new Buf();
                    pk.reset_command(SSH_MSG_USERAUTH_PK_OK);
                    pk.putString(alg);
                    pk.putValue(pubBlob);
                    write(pk);
                    continue;
                }
                byte[] sig = buf.getValue();                      // assinatura SSH: string alg ‖ string sigcrua
                if (u.equals(expectedUsername) && pubKeyAutorizada(pubBlob)) {
                    // reconstroi o blob assinado (RFC 4252 §7) e verifica a assinatura
                    Buf sb = new Buf();
                    sb.putValue(sessionId);
                    sb.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
                    sb.putString(u);
                    sb.putString("ssh-connection");
                    sb.putString("publickey");
                    sb.putByte((byte) 1);
                    sb.putString(alg);
                    sb.putValue(pubBlob);
                    byte[] signed = java.util.Arrays.copyOfRange(sb.buffer, 0, sb.i_put);
                    if (sshKeys().verifyBlob(pubBlob, signed, sig)) {
                        Buf ok = new Buf();
                        ok.reset_command(SSH_MSG_USERAUTH_SUCCESS);
                        write(ok);
                        authenticated = true;
                        return;
                    }
                }
            }
            Buf f = new Buf();
            f.reset_command(SSH_MSG_USERAUTH_FAILURE);
            f.putString("publickey,password");
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
                    // payload do pty-req (RFC 4254): string TERM, depois colunas/linhas/modos
                    try { termCliente = new String(buf.getValue(), "UTF-8"); } catch (Exception e) {}
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
                    // sujava os comandos no bash (bug antigo do \r\n). Com edicaoLinha (cmd.exe), o
                    // servidor tambem monta a linha e trata o backspace — ver o campo edicaoLinha.
                    java.io.ByteArrayOutputStream paraShell = new java.io.ByteArrayOutputStream();
                    java.io.ByteArrayOutputStream paraEco = new java.io.ByteArrayOutputStream();
                    for (int k = 0; k < data.length; k++) {
                        int c = data[k] & 0xff;
                        if (c == 13 || c == 10) {                                       // Enter (CR, LF, CRLF)
                            if (c == 13 && k + 1 < data.length && (data[k + 1] & 0xff) == 10) k++; // colapsa CRLF
                            if (edicaoLinha) { paraShell.write(linha, 0, linhaLen); linhaLen = 0; }
                            paraShell.write(10);
                            paraEco.write(13); paraEco.write(10);
                        } else if (c == 3 && interrompeMatando) {                        // Ctrl+C sem pty (cmd.exe)
                            int r = classificaEInterrompeForeground();
                            linhaLen = 0;                           // descarta o que estava sendo digitado
                            if (r == 2) {                           // foreground e cliente SSH aninhado: REPASSA o 0x03 (nao mata)
                                paraShell.write(3);                 // -> stdin do cliente -> ele encaminha o Ctrl+C pro nivel de baixo
                            } else {
                                paraEco.write(13); paraEco.write(10);   // pula linha (como um terminal faz no ^C)
                                if (r == 0) paraShell.write(10);        // ocioso: Enter vazio p/ o cmd redesenhar o prompt (pwd);
                            }                                           // r==1 (matou comando normal): o cmd reexibe o prompt sozinho
                        } else if (edicaoLinha && (c == 8 || c == 127)) {               // backspace/DEL
                            if (linhaLen > 0) { linhaLen--; paraEco.write(8); paraEco.write(32); paraEco.write(8); }
                        } else if (edicaoLinha) {
                            if (linhaLen < linha.length) { linha[linhaLen++] = (byte) c; paraEco.write(c); }
                        } else {
                            paraShell.write(c);
                            paraEco.write(c);
                        }
                    }
                    if (ecoServidor) {   // so quando o shell nao ecoa sozinho (cmd.exe); ver ecoServidor
                        byte[] eco = paraEco.toByteArray();
                        if (eco.length > 0) {   // NUNCA mandar CHANNEL_DATA vazio: o cliente trata len 0 como fim e sai
                            Buf e = new Buf();
                            e.reset_command(SSH_MSG_CHANNEL_DATA);
                            e.putInt(clientChannel);
                            e.putInt(eco.length);
                            e.putBytes(eco);
                            write(e);
                        }
                    }
                    byte[] envioShell = paraShell.toByteArray();
                    if (envioShell.length > 0) { shellInput.write(envioShell); shellInput.flush(); }
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

    // PID do shell que o servidor abriu nesta sessao (setado no startShell). O auto-teste zera este
    // campo antes de cada cliente e o le em DOIS momentos — ANTES e DEPOIS do Ctrl+C — e, via
    // ProcessHandle, confere que a sessao e um processo separado e VIVO do host e que sobrevive
    // (mesmo PID, ainda vivo) ao Ctrl+C. volatile: escrito aqui, lido/zerado no -test.
    static volatile long ultimoShellPid = 0;
    // Cliente pediu pty (pty-req)? Com pty, a saida do shell ganha o ONLCR que um pty de verdade
    // faria (LF -> CRLF); sem pty (ssh -T / pipes) os bytes seguem crus para nao corromper dados.
    private boolean ptyPedido = false;
    // O shell da sessao ja ecoa sozinho? No linux o eco vem do pty (ou do bash -i no fallback);
    // somado ao eco do servidor, a digitacao saia duplicada (yy eecchhoo 11). cmd.exe nao ecoa
    // o que le do pipe, entao no windows o eco do servidor fica ligado.
    private boolean ecoServidor = true;
    // Line editing do servidor para shell SEM line discipline (cmd.exe lendo de pipe): a linha
    // e montada aqui, backspace (0x08/0x7f) apaga do buffer (e "\b \b" no eco apaga na tela) e
    // o shell so recebe a linha pronta no Enter — que e como o cmd ja le do pipe de toda forma.
    // No linux o pty do 'script' ja faz esse papel, entao fica desligado.
    private boolean edicaoLinha = false;
    private byte[] linha = new byte[8192];
    private int linhaLen = 0;
    // Ctrl+C sem pty (Windows/cmd.exe): nao ha line discipline que transforme o 0x03 em SIGINT,
    // entao o servidor intercepta o VINTR e mata o processo em foreground do shell (o comando em
    // execucao), deixando o shell vivo. No linux isso fica desligado — quem gera o SIGINT e o pty.
    private boolean interrompeMatando = false;
    // TERM anunciado pelo cliente no pty-req (ex.: xterm-256color); repassado ao shell do pty
    // para o readline/cores usarem as sequencias certas do terminal do cliente.
    private String termCliente = null;
    // 'env --default-signal' existe? (coreutils >= 8.30). Testado uma unica vez.
    private static final boolean ENV_RESET_SINAL = testaEnvReset();
    private static boolean testaEnvReset() {
        if (System.getProperty("os.name").toLowerCase().contains("win")) return false;
        try { return new ProcessBuilder("env", "--default-signal=INT", "true")
                        .redirectErrorStream(true).start().waitFor() == 0; }
        catch (Exception e) { return false; }
    }
    // Prefixa o comando do shell com 'env --default-signal=INT,QUIT' quando disponivel. Isso
    // RESTAURA para o default o SIGINT/SIGQUIT que o processo herda IGNORADO quando o servidor
    // sobe em background (ex.: "java SSHMini.java -server ... &"): nesse caso o shell — e todo
    // comando que ele roda — nasce com SIGINT ignorado, e o Ctrl+C (0x03) do cliente, mesmo
    // entregue ao pty, nao gera interrupcao. Com o reset, o 0x03 volta a interromper o comando
    // em foreground, como num ssh de verdade. Se 'env' nao suporta a flag, roda sem o prefixo.
    private static String[] comReset(String... cmd) {
        if (!ENV_RESET_SINAL) return cmd;
        String[] r = new String[cmd.length + 2];
        r[0] = "env"; r[1] = "--default-signal=INT,QUIT";
        System.arraycopy(cmd, 0, r, 2, cmd.length);
        return r;
    }
    // Usuario em que a SESSAO do cliente cai (privilege drop). null = mesmo usuario do servidor (sem drop).
    // Detectado SOZINHO: se o servidor foi iniciado via sudo, cai no usuario ORIGINAL (SUDO_USER) — ver main.
    static String shellUser = null;
    // Sobe o shell da sessao COMO shellUser via 'runuser -l' (login: HOME/PATH/cwd do usuario), sem pedir
    // senha porque o servidor roda como root. E o privilege drop que o sshd faz: o servidor segue root
    // (mantem a porta baixa), mas quem conecta cai no usuario normal. So Linux (no Windows o cmd ja roda
    // como o usuario que subiu o -server). Sem shellUser, roda como o proprio usuario do servidor.
    private static String[] comUsuario(String[] cmd) {
        if (shellUser == null) return cmd;
        return new String[] { "runuser", "-l", shellUser, "-c", String.join(" ", cmd) };
    }
    // Debug (servidor): se setado, loga o que o Ctrl+C ve/mata no cmd. Via env SSHMINI_KILLLOG ou -killlog.
    static String KILLLOG = System.getenv("SSHMINI_KILLLOG");
    // Ctrl+C no Windows (cmd.exe, sem pty): interrompe o comando em foreground, preservando o shell.
    // ANTES matava a ARVORE inteira (descendants()) — e no Windows isso pegava JUNTO o conhost/host de
    // console (um descendente), e matar o conhost deixava o cmd sem console: os PROXIMOS programas
    // externos nasciam com o stdout quebrado (executavam e ate gravavam em arquivo com '>', mas nao
    // mostravam nada na tela; builtins como 'dir' continuavam pois saem do proprio cmd). Era o
    // "terminal estranho" apos o Ctrl+C. AGORA so mexe nos FILHOS DIRETOS do cmd (o comando em foreground)
    // e NUNCA no conhost. Alem disso decide entre MATAR e REPASSAR (ver abaixo), pro SSH aninhado cascatear.
    // Retorno: 0 = OCIOSO (so conhost / nada rodando) -> o caller pede um prompt novo ao cmd.
    //          1 = MATOU um comando normal (ping, y, ...) em foreground -> interrompido, como antes.
    //          2 = REPASSAR: o foreground e um cliente SSH ANINHADO (ssh.exe ou um cliente SSHMini). NAO se
    //              mata (matar = a sessao aninhada "escapa"); o caller escreve o 0x03 no stdin dele e ELE
    //              encaminha o Ctrl+C pro nivel de baixo, onde o comando REAL e morto. Assim CASCATEIA.
    // Puro Java 21: children() + ProcessHandle.info() + destroyForcibly (sem nativo, sem ConPTY, sem FFM).
    private int classificaEInterrompeForeground() {
        try {
            if (shellProcess == null) return 0;
            java.util.List<ProcessHandle> reais = new java.util.ArrayList<ProcessHandle>();
            for (ProcessHandle h : shellProcess.children().toList())
                if (!h.info().command().orElse("").toLowerCase().contains("conhost")) reais.add(h);   // conhost: nunca
            StringBuilder log = KILLLOG != null ? new StringBuilder("Ctrl+C: " + reais.size() + " comando(s) em foreground:\n") : null;
            boolean repassa = false;
            for (ProcessHandle h : reais) {
                String cmd = h.info().command().orElse("").toLowerCase();
                String cl  = h.info().commandLine().orElse("").toLowerCase();
                boolean cliente = cmd.endsWith("ssh.exe") || cmd.endsWith("\\ssh") || cl.contains("sshmini")   // encaminha o Ctrl+C
                    || new java.io.File(System.getProperty("java.io.tmpdir"), "sshmini_client_" + h.pid()).exists();   // marca de cliente SSHMini vivo
                if (cliente) repassa = true;
                if (log != null) log.append("  pid=" + h.pid() + " cmd=" + (cmd.isEmpty() ? "?" : cmd) + (cliente ? "  [REPASSA cliente ssh]" : "  [mata]") + "\n");
            }
            int r = reais.isEmpty() ? 0 : (repassa ? 2 : 1);
            if (r == 1) for (ProcessHandle h : reais) h.destroyForcibly();   // comando(s) normal(is): interrompe matando
            if (log != null) {
                if (reais.isEmpty()) log.append("  (ocioso)\n");
                try { java.nio.file.Files.writeString(java.nio.file.Paths.get(KILLLOG), log.toString(),
                        java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND); } catch (Exception e) {}
            }
            return r;
        } catch (Exception e) { return 0; }
    }
    private void startShell() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();
        ProcessBuilder pb;

        if (os.contains("win")) {
            pb = new ProcessBuilder("cmd.exe", "/q");   // /q = ECHO OFF: sem isso o cmd reexibe cada comando lido
            edicaoLinha = true;        // do pipe (eco dobrado no terminal). O servidor ja ecoa (ecoServidor).
            interrompeMatando = true;  // Ctrl+C: mata o comando em foreground (ver handleChannel)
        } else {
            // 'script' (util-linux) roda o bash dentro de um pty DE VERDADE: line discipline
            // completa (backspace, setas, historico, ctrl+c) e eco feito pelo proprio pty.
            // Sem pty o bash le de um pipe e o backspace vira um 0x7f literal na linha.
            // O prefixo 'env --default-signal' (ver comReset) e essencial p/ o Ctrl+C: sem ele,
            // com o servidor em background, o comando remoto herda SIGINT ignorado e nao para.
            pb = new ProcessBuilder(comUsuario(comReset("script", "-qefc", "/bin/bash", "/dev/null")));
            ecoServidor = false;   // o pty (readline) ja ecoa a digitacao; ecoar aqui duplicaria
        }
        if (termCliente != null && !termCliente.isEmpty())
            pb.environment().put("TERM", termCliente);   // TERM do cliente vale dentro da sessao

        pb.redirectErrorStream(true);
        try {
            shellProcess = pb.start();
        } catch (Exception e) {
            if (os.contains("win")) throw e;
            // sem o utilitario 'script' (ex.: container minimo): bash -i direto no pipe.
            // Funciona e ecoa sozinho, mas sem line discipline (backspace nao edita a linha).
            pb = new ProcessBuilder(comUsuario(comReset("/bin/bash", "-i")));
            pb.redirectErrorStream(true);
            shellProcess = pb.start();
        }
        ultimoShellPid = shellProcess.pid();
        shellOutput = shellProcess.getInputStream();
        shellInput = shellProcess.getOutputStream();

        new Thread(() -> {
            try {
                byte[] buffer = new byte[4096];
                int len;
                boolean crAnterior = false;   // um \r\n pode quebrar entre dois reads; o estado atravessa chunks
                // Le ate o EOF do pipe (read == -1). Checar isAlive() aqui era um bug: quando o
                // shell morria rapido (ex.: exit com comandos enfileirados), o loop parava antes
                // de drenar o que restava no pipe e o cliente perdia o final da saida.
                while ((len = shellOutput.read(buffer)) != -1) {
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
    public byte[] hostKeyBlob, hostSig;   // (cliente) K_S apresentado pelo servidor e a assinatura sobre H
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
        this.hostKeyBlob = KS;                                  // p/ o cliente verificar a host key
        try { this.hostSig = buf.getValue(); } catch (Exception e) {}   // assinatura do host sobre H
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

    // AUTO-TESTE (loopback contra o servidor local da 3004): roda a MESMA bateria de validacoes
    // por DOIS clientes — o SSHClientMini ("ssh mini") e o OpenSSH de verdade ("ssh puro") — marcando
    // [OK]/[FALHA]. Shell remoto = cmd.exe (Windows) ou bash no pty (Linux). O check de PID roda por
    // cliente e em DOIS momentos, ANTES e DEPOIS do Ctrl+C: antes prova que a sessao e um processo
    // separado e vivo do host; depois prova que ela SOBREVIVE (mesmo PID, ainda vivo) ao Ctrl+C, que
    // interrompe so o comando em foreground.
    static void runAuto(String fonteJava, int porta) {
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        int ok = 0, total = 0;
        // a MESMA bateria pelos dois clientes (comandos + Ctrl+C sempre pelo stdin; inclui o check de PID)
        int[] rMini = checkCliente("ssh mini", false, win, porta, fonteJava);
        int[] rPuro = checkCliente("ssh puro", true,  win, porta, fonteJava);
        ok += rMini[0] + rPuro[0]; total += rMini[1] + rPuro[1];
        // bateria de CHAVES: sshgen + conexao por file (pubkey auth) + host key, ed25519 e mldsa44,
        // com o ssh nativo participando onde o host permite (ed25519). Tudo em dir temp dinamico.
        int[] rKeys = runAutoKeys(fonteJava, porta);
        ok += rKeys[0]; total += rKeys[1];
        // resumo
        System.out.println("---- " + ok + "/" + total + " checks OK"
            + (ok == total ? "  => AUTO-TESTE OK (" + (win ? "windows/cmd" : "linux/bash") + ")" : "  => FALHOU") + " ----");
    }

    // ===== Bateria de CHAVES (sshgen, conexao por file/pubkey, host key) — ed25519 + mldsa44 =====
    // Gera chaves em dir TEMP dinamico (sem pastas prefixadas), sobe servidores dedicados e roda:
    // sign<->verify, determinismo, interop com ssh-keygen nativo, login por chave (SSHMini e ssh nativo),
    // verificacao de host key (ed25519 e mldsa) e o negativo (pino errado recusado). Retorna {ok,total}.
    static int[] runAutoKeys(String fonteJava, int porta) {
        int ok = 0, total = 0;
        boolean temSsh = false;
        try { Process v = new ProcessBuilder("ssh", "-V").redirectErrorStream(true).start(); v.getInputStream().readAllBytes(); temSsh = (v.waitFor() == 0); } catch (Exception e) {}
        int pEd = porta + 1, pPq = porta + 2;
        java.io.File tmp = null;
        try {
            tmp = java.nio.file.Files.createTempDirectory("sshmini_keys_").toFile();
            // Compila o fonte UMA vez p/ os clientes spawnados usarem -cp (senao cada 'java <fonte>'
            // recompila o arquivo inteiro -> lento e, somado ao ML-DSA, estoura os timeouts de login).
            java.io.File classes = new java.io.File(tmp, "classes"); classes.mkdirs();
            try {
                Process jc = new ProcessBuilder("javac", "-d", classes.getAbsolutePath(), fonteJava).redirectErrorStream(true).start();
                jc.getInputStream().readAllBytes();
                spawnCp = (jc.waitFor() == 0) ? classes.getAbsolutePath() : null;
            } catch (Exception e) { spawnCp = null; }
            SshKeys keys = new SshKeys();
            String uEd = novoPar(keys, "ed25519", tmp, "user_ed");
            String uPq = novoPar(keys, "mldsa44-ed25519", tmp, "user_pq");
            String hEd = novoPar(keys, "ed25519", tmp, "host_ed");
            String hPq = novoPar(keys, "mldsa44-ed25519", tmp, "host_pq");
            java.io.File authkeys = new java.io.File(tmp, "authorized_keys");
            java.nio.file.Files.writeString(authkeys.toPath(),
                java.nio.file.Files.readString(java.nio.file.Path.of(uEd + ".pub"))
                + java.nio.file.Files.readString(java.nio.file.Path.of(uPq + ".pub")));
            System.out.println("chaves: sshgen + conexao por file (ed25519 + mldsa44 pos-quantico)  [dir temp dinamico]");

            // ---- unit: sign<->verify (aceita valida, rejeita adulterada) p/ ed25519 e mldsa ----
            byte[] msg = "sshmini-selftest".getBytes("UTF-8");
            for (String tipo : new String[]{ "ed25519", "mldsa44-ed25519" }) {
                String base = tipo.equals("ed25519") ? uEd : uPq;
                SshKeys.Priv pv = keys.parsePriv(java.nio.file.Files.readString(java.nio.file.Path.of(base)));
                String pub = java.nio.file.Files.readString(java.nio.file.Path.of(base + ".pub"));
                byte[] sig = keys.signSSH(pv.type, pv.seeds, msg);
                byte[] alt = msg.clone(); alt[0] ^= 1;
                boolean c = keys.verifySSH(pub, msg, sig) && !keys.verifySSH(pub, alt, sig);
                total++; if (c) ok++; System.out.println((c ? "[OK]    " : "[FALHA] ") + "chaves: sign<->verify " + tipo);
            }
            // ---- determinismo por passphrase (mesma frase+nome -> mesma pub) ----
            boolean det = keys.generate("mldsa44-ed25519", "seed-test-det", "det")[1].equals(keys.generate("mldsa44-ed25519", "seed-test-det", "det")[1]);
            total++; if (det) ok++; System.out.println((det ? "[OK]    " : "[FALHA] ") + "chaves: determinismo por passphrase (mldsa)");

            // ---- interop com ssh-keygen NATIVO (ed25519): -y re-deriva a pub; -l da fingerprint ----
            if (temSsh) {
                String der = execOut(new ProcessBuilder("ssh-keygen", "-y", "-f", uEd));
                String pub = java.nio.file.Files.readString(java.nio.file.Path.of(uEd + ".pub"));
                boolean c = der != null && dois(der).equals(dois(pub));
                total++; if (c) ok++; System.out.println((c ? "[OK]    " : "[FALHA] ") + "chaves: ssh-keygen NATIVO -y re-deriva a pub ed25519 (interop)");
                String fp = execOut(new ProcessBuilder("ssh-keygen", "-l", "-f", uEd + ".pub"));
                boolean c2 = fp != null && fp.contains("ED25519");
                total++; if (c2) ok++; System.out.println((c2 ? "[OK]    " : "[FALHA] ") + "chaves: ssh-keygen NATIVO -l aceita a pub ed25519 (fingerprint)");
            }

            // ---- servidor com host key ed25519 + authorized_keys (porta pEd) ----
            Session.authKeysFile = authkeys.getAbsolutePath();
            Session.hostKeyFile  = hEd;
            if (!sobeServidor(pEd)) { total++; System.out.println("[FALHA] chaves: servidor de teste nao subiu na " + pEd); }
            else {
                total++; boolean c1 = sessaoMarcador(cliMini(fonteJava, uEd, hEd + ".pub", pEd));
                if (c1) ok++; System.out.println((c1 ? "[OK]    " : "[FALHA] ") + "chaves: SSHMini cliente ed25519 (conexao por file) + verifica host key");
                total++; boolean c2 = sessaoMarcador(cliMini(fonteJava, uPq, hEd + ".pub", pEd));
                if (c2) ok++; System.out.println((c2 ? "[OK]    " : "[FALHA] ") + "chaves: SSHMini cliente mldsa44 (conexao por file, POS-QUANTICO)");
                total++; boolean c3 = !sessaoMarcador(cliMini(fonteJava, uEd, uEd + ".pub", pEd));
                if (c3) ok++; System.out.println((c3 ? "[OK]    " : "[FALHA] ") + "chaves: SSHMini RECUSA host key errada (pino -hostpub incorreto)");
                if (temSsh) {
                    java.io.File kh = new java.io.File(tmp, "known_hosts");
                    total++; boolean c4 = sessaoMarcador(cliNativo(uEd, kh.getAbsolutePath(), pEd));
                    if (c4) ok++; System.out.println((c4 ? "[OK]    " : "[FALHA] ") + "chaves: ssh NATIVO ed25519 (conexao por file) -> servidor SSHMini");
                    total++; boolean c5 = false;
                    try { c5 = kh.exists() && java.nio.file.Files.readString(kh.toPath()).contains("ssh-ed25519"); } catch (Exception e) {}
                    if (c5) ok++; System.out.println((c5 ? "[OK]    " : "[FALHA] ") + "chaves: ssh nativo aceitou a host key ed25519 do SSHMini (known_hosts)");
                }
            }
            // ---- servidor com host key MLDSA (porta pPq): SSHMini verifica host key pos-quantica ----
            Session.hostKeyFile = hPq;
            if (sobeServidor(pPq)) {
                total++; boolean c6 = sessaoMarcador(cliMini(fonteJava, uEd, hPq + ".pub", pPq));
                if (c6) ok++; System.out.println((c6 ? "[OK]    " : "[FALHA] ") + "chaves: SSHMini verifica host key mldsa44 (POS-QUANTICA) + auth");
            }
        } catch (Exception e) {
            total++; System.out.println("[FALHA] chaves: excecao na bateria: " + e);
        } finally {
            Session.hostKeyFile = null; Session.authKeysFile = null;   // nao vaza p/ o servidor de senha (3004)
            if (tmp != null) apagaDir(tmp);
        }
        return new int[]{ ok, total };
    }
    // gera <nome> e <nome>.pub no dir temp (privado 600) e devolve o caminho absoluto do privado.
    // Passphrase deterministica "seed-test-<nome>": as chaves do -test sao reproduziveis e rotuladas.
    static String novoPar(SshKeys keys, String tipo, java.io.File dir, String nome) throws Exception {
        String[] par = keys.generate(tipo, "seed-test-" + nome, nome);
        java.io.File priv = new java.io.File(dir, nome);
        java.nio.file.Files.writeString(priv.toPath(), par[0]);
        java.nio.file.Files.writeString(new java.io.File(dir, nome + ".pub").toPath(), par[1]);
        try { java.nio.file.Files.setPosixFilePermissions(priv.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); } catch (Throwable t) {}
        return priv.getAbsolutePath();
    }
    static boolean sobeServidor(int porta) {
        try (java.net.ServerSocket probe = new java.net.ServerSocket(porta)) {} catch (Exception e) { return false; }   // ocupada
        boolean[] up = { false };
        Thread t = new Thread(() -> { try { up[0] = true; new SSHServerMini(porta, "admin", "admin123"); } catch (Exception e) { up[0] = false; } });
        t.setDaemon(true); t.start();
        try { Thread.sleep(400); } catch (Exception e) {}
        return up[0];
    }
    static String spawnCp = null;   // classpath compilado uma vez p/ os clientes spawnados (senao recompila cada spawn)
    static ProcessBuilder cliMini(String fonteJava, String priv, String hostpub, int porta) {
        if (spawnCp != null)
            return new ProcessBuilder("java", "-cp", spawnCp, "SSHMini", "admin@localhost", "-i", priv, "-hostpub", hostpub, "-P", "" + porta);
        return new ProcessBuilder("java", fonteJava, "admin@localhost", "-i", priv, "-hostpub", hostpub, "-P", "" + porta);
    }
    static ProcessBuilder cliNativo(String priv, String knownHosts, int porta) {
        return new ProcessBuilder("ssh", "-tt", "-i", priv, "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=" + knownHosts, "-o", "IdentitiesOnly=yes",
            "-o", "PreferredAuthentications=publickey", "-p", "" + porta, "admin@localhost");
    }
    // Conecta, espera o prompt assentar, manda um marcador anti-eco e confere que a EXECUCAO apareceu.
    static boolean sessaoMarcador(ProcessBuilder pb) {
        final String MARK = "SSHMINIMARK";
        try {
            pb.redirectErrorStream(true);
            Process ps = pb.start();
            StringBuilder sb = new StringBuilder();
            Thread rd = new Thread(() -> { try (java.io.Reader r = new java.io.InputStreamReader(ps.getInputStream())) {
                char[] b = new char[4096]; int n; while ((n = r.read(b)) != -1) synchronized (sb) { sb.append(b, 0, n); } } catch (Exception e) {} });
            rd.start();
            java.io.OutputStream ent = ps.getOutputStream();
            esperarQuieto(sb, 800, 25000);                          // login + prompt (ML-DSA é lento; folga p/ nao virar typeahead)
            ent.write("echo SSHMINI''MARK\n".getBytes()); ent.flush();   // digitado tem aspas; execucao imprime SSHMINIMARK
            esperarConter(sb, MARK, 15000);
            esperarQuieto(sb, 400, 4000);
            try { ent.write("exit\n".getBytes()); ent.flush(); ent.close(); } catch (Exception e) {}
            if (!ps.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)) ps.destroyForcibly();
            rd.join(2000);
            synchronized (sb) { return sb.toString().contains(MARK); }
        } catch (Exception e) { return false; }
    }
    static String execOut(ProcessBuilder pb) {
        try { pb.redirectErrorStream(true); Process p = pb.start();
            String s = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            p.waitFor(); return s; } catch (Exception e) { return null; }
    }
    static String dois(String linha) { String[] p = linha.trim().split("\\s+"); return p.length >= 2 ? p[0] + " " + p[1] : linha.trim(); }
    static void apagaDir(java.io.File d) {
        java.io.File[] fs = d.listFiles(); if (fs != null) for (java.io.File f : fs) { if (f.isDirectory()) apagaDir(f); else f.delete(); }
        d.delete();
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
    // Espera a saida acumulada em 'sb' assentar: ja ter chegado algo e ficar quieta por quietMs
    // (teto maxMs). Serve para digitar so depois do prompt: o bash iniciando no pty descarta o
    // typeahead pendente no tcsetattr (ecoa mas nao executa).
    static void esperarQuieto(StringBuilder sb, long quietMs, long maxMs) {
        long inicio = System.currentTimeMillis(), ultima = inicio;
        int anterior; synchronized (sb) { anterior = sb.length(); }
        while (System.currentTimeMillis() - inicio < maxMs) {
            try { Thread.sleep(80); } catch (Exception e) {}
            int tam; synchronized (sb) { tam = sb.length(); }
            if (tam != anterior) { anterior = tam; ultima = System.currentTimeMillis(); }
            if (tam > 0 && System.currentTimeMillis() - ultima >= quietMs) return;
        }
    }

    // Espera a saida acumulada CONTER 'txt' (ou estourar maxMs). Usado no teste de Ctrl+C para
    // confirmar que o comando ja esta rodando antes de mandar o 0x03 (evita o typeahead que
    // faria o 0x03 chegar antes do comando executar).
    static boolean esperarConter(StringBuilder sb, String txt, long maxMs) {
        long inicio = System.currentTimeMillis();
        while (System.currentTimeMillis() - inicio < maxMs) {
            synchronized (sb) { if (sb.indexOf(txt) >= 0) return true; }
            try { Thread.sleep(50); } catch (Exception e) {}
        }
        return false;
    }

    // Roda a MESMA bateria de checks por UM cliente e retorna {ok,total}. 'ehSshPuro' escolhe o
    // transporte: o OpenSSH de verdade ("ssh puro", -tt + askpass) ou o SSHClientMini ("ssh mini",
    // senha embutida). A conversa e IDENTICA nos dois — comandos e o Ctrl+C (byte 0x03) sempre pelo
    // STDIN — e a validacao usa deteccao por POSICAO (marca em inicio de linha), robusta ao eco: o
    // ssh puro ecoa pelo pty, o ssh mini suprime, mas em ambos a EXECUCAO cai numa linha propria.
    static String tempo(long ms) { return "  (" + ms + " ms)"; }   // sufixo de tempo mostrado em cada check
    static int[] checkCliente(String nome, boolean ehSshPuro, boolean win, int porta, String fonteJava) {
        String devnull = win ? "NUL" : "/dev/null";
        if (ehSshPuro) {   // pre-requisito: o cliente OpenSSH precisa existir (senao e ERRO, sem "pulado")
            try { Process v = new ProcessBuilder("ssh", "-V").redirectErrorStream(true).start(); v.getInputStream().readAllBytes(); v.waitFor(); }
            catch (Exception e) {
                System.out.println("[FALHA] " + nome + ": cliente 'ssh' nao encontrado (necessario p/ validar)");
                return new int[]{0, 1};
            }
        }
        int ok = 0, total = 0;
        String tok = "MINI_ECHO_OK";
        // Sentinela MINI_YNAO escrito "quebrado" (^ no cmd, '' no bash) p/ o TEXTO DIGITADO nao conter
        // a palavra inteira: so a EXECUCAO a produz. IMPORTANTE: o where/command-v (detecta se o 'y'
        // EXISTE) fica SEPARADO do pipe, com o pipe rodando SEMPRE depois. Antes o '|| echo MINI_YNAO'
        // pegava tambem o pipe: se o 'y' existia mas o pipe saia com erro, marcava "y nao existe"
        // (falso). Agora MINI_YNAO == 'y' realmente ausente; pipe sem -onlyDiff == outro problema.
        String yline = win
            ? "(where y >nul 2>nul || echo MINI_YNA^O) & y help | y grep only"
            : "{ command -v y >/dev/null 2>&1 || echo MINI_YNA''O ; } ; y help | y grep only";
        String script = "echo " + tok + "\nwhoami";   // o 'y' e o Ctrl+C vem DEPOIS (dedicados)
        String saida = "";
        boolean terminou = false;
        // PID do shell da sessao capturado em VARIOS momentos: ANTES do Ctrl+C, DEPOIS do Ctrl+C no
        // comando em andamento e DEPOIS do Ctrl+C no prompt ocioso. Prova que a sessao roda num processo
        // separado e VIVO do host e que SOBREVIVE (mesmo PID) aos dois Ctrl+C; so o 'exit' encerra.
        long pidAntes = 0, pidDepois = 0, pidOcioso = 0;
        boolean vivoAntes = false, vivoDepois = false, vivoOcioso = false;
        boolean sessaoMorreu = false;   // apos o exit: o shell da sessao (server-side) tem de morrer tambem
        boolean sinalEntregue = false, clienteVivoAposSinal = false, sctInterrompeu = false;   // Ctrl+C por SINAL real de verdade (so mini)
        // tempos (ms) por fase da sessao, mostrados em cada check. Os checks "instantaneos" (avaliados
        // no fim a partir do texto ja capturado: escadinha e os PIDs) aparecem com 0 ms — o tempo real
        // fica nas OPERACOES (connect, whoami, cada Ctrl+C, o y, o exit). 'marco' corre pela sessao.
        long marco = 0, msConnect = 0, msWhoami = 0, msCtrlC = 0, msIdle = 0, msSinal = 0, msY = 0, msExit = 0;
        java.io.File ask = null;
        try {
            ProcessBuilder pb;
            if (ehSshPuro) {
                ask = java.io.File.createTempFile("sshmini_askpass", win ? ".bat" : ".sh");
                java.nio.file.Files.writeString(ask.toPath(), win ? "@echo off\r\necho admin123\r\n" : "#!/bin/sh\necho admin123\n");
                ask.setExecutable(true);
                // -tt: forca a alocacao de pty mesmo com stdin em pipe. E o cenario do ssh interativo
                // real e exercita o ONLCR do servidor (LF -> CRLF), validado no check de escadinha.
                pb = new ProcessBuilder("ssh", "-tt",
                    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=" + devnull,
                    "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                    "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=10",
                    "-p", "" + porta, "admin@localhost");
                pb.environment().put("SSH_ASKPASS", ask.getAbsolutePath());
                pb.environment().put("SSH_ASKPASS_REQUIRE", "force");
                pb.environment().put("DISPLAY", ":0");
            } else {
                // cliente MINI (SSHClientMini): senha embutida no alvo, sem askpass/console. Ele
                // tambem pede pty (pty-req no connect_stdin), entao o servidor faz o mesmo ONLCR.
                pb = new ProcessBuilder("java", fonteJava, "admin,admin123@localhost", "-P", "" + porta);
            }
            // stderr fica de fora: usa \n proprio e contaminaria o check de escadinha (mede so o stdout).
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Session.ultimoShellPid = 0;   // zera p/ capturar o PID do shell DESTA sessao, nao um resquicio da anterior
            marco = System.currentTimeMillis();   // t0 do CONNECT (inclui o compile do cliente + handshake + login)
            Process ps = pb.start();
            StringBuilder sb = new StringBuilder();
            Thread rd = new Thread(() -> {
                try (java.io.Reader r = new java.io.InputStreamReader(ps.getInputStream())) {
                    char[] b = new char[4096]; int n;
                    while ((n = r.read(b)) != -1) synchronized (sb) { sb.append(b, 0, n); }
                } catch (Exception e) {}
            });
            rd.start();
            // Digita como um humano: espera a saida assentar (login + prompt) antes de CADA linha.
            // Mandar tudo de uma vez NAO funciona com o pty: o que chega durante a inicializacao do
            // bash e descartado como typeahead (a linha ecoa mas nao executa). Vale p/ os dois clientes.
            java.io.OutputStream ent = ps.getOutputStream();
            for (String linha : script.split("\n")) {
                esperarQuieto(sb, 700, 10000);
                if (msConnect == 0) { msConnect = System.currentTimeMillis() - marco; marco = System.currentTimeMillis(); }   // 1a espera assentar = conectado + login pronto
                ent.write((linha + "\n").getBytes());
                ent.flush();
            }
            // PID ANTES do Ctrl+C: o shell da sessao ja esta no ar (rodou echo/whoami). Guarda o PID
            // e confere (mais abaixo) que e um processo VIVO e separado do host. Comparado ao PID
            // DEPOIS, prova que o Ctrl+C mata so o comando — a sessao (o shell) sobrevive intacta.
            esperarQuieto(sb, 700, 10000);
            msWhoami = System.currentTimeMillis() - marco; marco = System.currentTimeMillis();   // echo + whoami assentarem
            pidAntes = Session.ultimoShellPid;
            vivoAntes = pidAntes > 0 && ProcessHandle.of(pidAntes).map(ProcessHandle::isAlive).orElse(false);
            // ---- Ctrl+C: o comando imprime uma marca de INICIO, dorme ~6s e SO ENTAO a marca FINAL
            // (via '&&'). Espera a marca de INICIO — prova que o comando ESTA rodando. Isso conserta o
            // falso negativo do "ssh mini": ele SUPRIME o eco do comando, entao esperar a marca FINAL
            // (como antes) so retornava com o comando JA terminado, e o 0x03 chegava tarde. Com a marca
            // de INICIO, o 0x03 vai no MEIO do sleep nos dois clientes. Interrompido -> a marca FINAL
            // nunca sai em inicio de linha. PORTAVEL cmd+bash; nao depende de $?/aritmetica.
            String cmdCtrlC = win
                ? "echo MINI_PRECTRLC& ping -n 3 127.0.0.1 >nul && echo MINI_POSCTRLC"   // ping -n 3 ~= dorme 2s
                : "echo MINI_PRECTRLC; sleep 2 && echo MINI_POSCTRLC";
            esperarQuieto(sb, 800, 10000);
            ent.write((cmdCtrlC + "\n").getBytes()); ent.flush();
            esperarConter(sb, "MINI_PRECTRLC", 10000);          // marca de INICIO: comando em execucao (sleep rodando)
            try { Thread.sleep(500); } catch (Exception e) {}   // 0x03 logo no inicio do sleep (dorme ~2s; margem p/ o 0x03 chegar)
            ent.write(3); ent.flush();                          // <<< Ctrl+C (byte 0x03 no stdin)
            try { Thread.sleep(2500); } catch (Exception e) {}  // tempo de COMPLETAR se NAO interrompido (comando ~2s)
            msCtrlC = System.currentTimeMillis() - marco; marco = System.currentTimeMillis();   // Ctrl+C (0x03) em andamento
            // PID DEPOIS do Ctrl+C: o shell tem de continuar VIVO e com o MESMO PID (o Ctrl+C matou
            // so o comando em foreground, nao a sessao). Robusto: vale mesmo que o Ctrl+C falhe.
            pidDepois = Session.ultimoShellPid;
            vivoDepois = pidDepois > 0 && ProcessHandle.of(pidDepois).map(ProcessHandle::isAlive).orElse(false);
            // ---- Ctrl+C no prompt OCIOSO (0x03 sem comando em foreground): num ssh de verdade so
            // cancela a linha e devolve um prompt novo, NUNCA encerra a sessao. Prova: manda o 0x03 no
            // prompt vazio e, logo apos, um echo sentinela; se a sessao sobreviveu, o sentinela EXECUTA
            // (cai numa linha propria, MINI_POSIDLE). Se tivesse caido, o sentinela nao voltaria.
            esperarQuieto(sb, 800, 10000);                      // garante o prompt ocioso (nada rodando)
            ent.write(3); ent.flush();                          // <<< Ctrl+C (0x03) no prompt ocioso
            try { Thread.sleep(800); } catch (Exception e) {}   // deixa o shell cancelar a linha / redesenhar o prompt
            // sentinela em DUAS marcas numa linha so: a EXECUCAO poe POSIDLE logo apos o \n de PREIDLE,
            // entao 'POSIDLE em inicio de linha' distingue execucao de eco (robusto ao eco do mini/puro).
            String cmdIdle = win ? "echo MINI_PREIDLE& echo MINI_POSIDLE" : "echo MINI_PREIDLE; echo MINI_POSIDLE";
            ent.write((cmdIdle + "\n").getBytes()); ent.flush();
            esperarConter(sb, "MINI_POSIDLE", 10000);           // apareceu (eco ou execucao) -> a sessao respondeu
            esperarQuieto(sb, 800, 10000);
            msIdle = System.currentTimeMillis() - marco; marco = System.currentTimeMillis();   // Ctrl+C (0x03) ocioso
            pidOcioso = Session.ultimoShellPid;
            vivoOcioso = pidOcioso > 0 && ProcessHandle.of(pidOcioso).map(ProcessHandle::isAlive).orElse(false);
            // ---- Ctrl+C por SINAL REAL (so no cliente mini): um SIGINT de verdade no processo do cliente
            // deve cair no handler instalaCtrlC -> mandar o 0x03 pelo canal -> interromper o comando remoto,
            // E o cliente tem de SOBREVIVER (nao "escapar"/morrer). E o caminho REAL do Ctrl+C do mini (a
            // tecla no terminal), que o teste por 0x03-no-stdin NAO exercita. Linux: kill -INT. Windows:
            // mandar CTRL_C_EVENT a um processo so, sem matar o proprio -test, exige helper nativo.
            if (!ehSshPuro && !win) {   // Linux: SIGINT real via kill -INT. Windows e testado a parte (ver ctrlCRealWindows)
                esperarQuieto(sb, 800, 10000);
                String cmdKill = win ? "echo MINI_PREKILL& ping -n 3 127.0.0.1 >nul && echo MINI_POSKILL"
                                     : "echo MINI_PREKILL; sleep 2 && echo MINI_POSKILL";
                ent.write((cmdKill + "\n").getBytes()); ent.flush();
                esperarConter(sb, "MINI_PREKILL", 10000);           // comando em execucao (sleep rodando)
                try { Thread.sleep(500); } catch (Exception e) {}   // sinal logo no inicio do sleep (dorme ~2s)
                sinalEntregue = enviarSigintReal(ps, win);          // SIGINT de verdade no processo do cliente
                try { Thread.sleep(2500); } catch (Exception e) {}  // tempo de COMPLETAR se NAO interrompido (comando ~2s)
                clienteVivoAposSinal = ps.isAlive();                // anti-"escape": o cliente sobreviveu ao Ctrl+C?
                msSinal = System.currentTimeMillis() - marco; marco = System.currentTimeMillis();   // sinal real (linux, kill -INT)
            }
            // ---- 'y' (a pedido, DEPOIS do Ctrl+C): pipe de comandos via SSH ----
            // O 'y' e um processo JAVA (startup lento) e imprime varias linhas. Sem esperar ele
            // TERMINAR, o exit era enviado no meio e — so no mini — o envio do exit re-armava a
            // supressao de eco (ecoPendente), que engolia a saida atrasada do y. Fix: um marcador
            // MINI_YDONE ao fim e esperar por ele ANTES do exit -> a saida do y ja chegou e foi capturada.
            esperarQuieto(sb, 800, 10000);
            String fimY = win ? "& echo MINI_YDONE" : "; echo MINI_YDONE";
            ent.write((yline + " " + fimY + "\n").getBytes()); ent.flush();
            esperarConter(sb, "MINI_YDONE", 12000);   // espera o y (java) concluir antes de mandar o exit
            esperarQuieto(sb, 500, 3000);
            msY = System.currentTimeMillis() - marco; marco = System.currentTimeMillis();   // y (pipe via SSH)
            ent.write("exit\n".getBytes()); ent.flush();
            ent.close();
            terminou = ps.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!terminou) ps.destroyForcibly();
            // apos o exit, o shell da sessao (server-side) tambem tem de morrer. Poll curto p/ robustez:
            // o cliente ja terminou, mas o processo do shell pode levar um instante pra sair.
            for (int i = 0; i < 30 && pidAntes > 0 && ProcessHandle.of(pidAntes).map(ProcessHandle::isAlive).orElse(false); i++)
                try { Thread.sleep(100); } catch (Exception e) {}
            sessaoMorreu = pidAntes > 0 && !ProcessHandle.of(pidAntes).map(ProcessHandle::isAlive).orElse(false);
            msExit = System.currentTimeMillis() - marco; marco = System.currentTimeMillis();   // exit + fim da sessao
            rd.join(2000);
            synchronized (sb) { saida = sb.toString(); }
        } catch (Exception e) { saida = "erro: " + e; }
        finally { if (ask != null) ask.delete(); }

        // Windows: o Ctrl+C REAL nao pode ser injetado no cliente da sessao acima sem atingir o proprio
        // -test (mesmo console). Entao sobe um cliente DEDICADO no proprio grupo de processos e dispara
        // CTRL_BREAK so nele (ver ctrlCRealWindows). Isolado: nao afeta o JVM de teste nem o shell do servidor.
        if (!ehSshPuro && win) {
            long ts = System.currentTimeMillis();
            boolean[] r = ctrlCRealWindows(fonteJava, porta);
            msSinal = System.currentTimeMillis() - ts;
            sinalEntregue = r[0]; sctInterrompeu = r[1]; clienteVivoAposSinal = r[2];
        }

        boolean logou = saida.contains(tok);   // o echo so ecoa/roda se conectou E autenticou
        if (logou) {
            long hostPid = ProcessHandle.current().pid();
            // PID host: referencia (o PID do JVM de teste). Contexto p/ contrastar com a "PID
            // connectada" (o shell da sessao, um processo separado e vivo). Nao conta como check.
            System.out.println(nome + ": PID host(" + hostPid + ")");
            total++; ok++;
            System.out.println("[OK]    " + nome + ": conecta + login" + (ehSshPuro ? " + host key ECDSA aceita" : "") + " (echo)" + tempo(msConnect));
            total++;
            boolean w = saida.contains(System.getProperty("user.name"));
            if (w) ok++; System.out.println((w ? "[OK]    " : "[FALHA] ") + nome + ": whoami traz o usuario" + tempo(msWhoami));
            // ---- escadinha: com pty, TODO \n do servidor deve chegar como \r\n (ONLCR). Sem a
            // conversao, quem imprime so \n desenha escadinha. Removidos os \r\n corretos, nao pode
            // sobrar \n orfao; e \r\r acusaria conversao dupla. ----
            total++;
            boolean escadaOk = !saida.replace("\r\n", "").contains("\n") && !saida.contains("\r\r");
            if (escadaOk) ok++; System.out.println((escadaOk ? "[OK]    " : "[FALHA] ") + nome + ": sem escadinha (todo \\n chegou como \\r\\n)" + tempo(0));
            // ---- PID ANTES do Ctrl+C: a sessao roda num PROCESSO SEPARADO do host e VIVO (o shell
            // do servidor tem PID proprio, != do JVM de teste). ----
            total++;
            boolean pidAntesOk = vivoAntes && pidAntes != hostPid;
            if (pidAntesOk) ok++; System.out.println((pidAntesOk ? "[OK]    " : "[FALHA] ") + nome + ": PID connectada(" + pidAntes + ")" + tempo(0));
            // ---- Ctrl+C: a EXECUCAO do echo imprime a marca FINAL SOZINHA no inicio de uma linha; o
            // ECO do comando a mostra sempre precedida de "echo ". Detectar por POSICAO e robusto ao
            // numero de ecos (o ssh puro ecoa pelo pty; o ssh mini suprime). ----
            total++;
            boolean cmdCompletou = saida.contains("\nMINI_POSCTRLC") || saida.contains("\rMINI_POSCTRLC");
            if (cmdCompletou)   // terminou apos o 0x03 => 0x03 nao chegou OU o kill do foreground falhou
                System.out.println("        (diag: a marca saiu em inicio de linha -> o comando remoto COMPLETOU apos o Ctrl+C)");
            if (!cmdCompletou) ok++; System.out.println((!cmdCompletou ? "[OK]    " : "[FALHA] ") + nome + ": Ctrl+C (0x03) interrompe o comando remoto em andamento" + tempo(msCtrlC));
            // ---- PID DEPOIS do Ctrl+C: a sessao SOBREVIVEU — mesmo PID de antes e ainda vivo. Prova
            // que o Ctrl+C interrompeu so o comando em foreground, nao o shell/a sessao. ----
            total++;
            boolean pidDepoisOk = vivoDepois && pidDepois == pidAntes;
            if (pidDepoisOk) ok++; System.out.println((pidDepoisOk ? "[OK]    " : "[FALHA] ") + nome + ": PID connectada(" + pidDepois + ") - continuo na sessao" + tempo(0));
            // ---- Ctrl+C no prompt OCIOSO: num ssh de verdade so cancela a linha e devolve um prompt
            // novo, sem encerrar a sessao. Prova: o echo sentinela mandado APOS o 0x03 executa (cai
            // numa linha propria). Se a sessao tivesse caido, MINI_POSIDLE nao teria voltado. ----
            total++;
            boolean idleOk = saida.contains("\nMINI_POSIDLE") || saida.contains("\rMINI_POSIDLE");
            if (idleOk) ok++; System.out.println((idleOk ? "[OK]    " : "[FALHA] ") + nome + ": Ctrl+C (0x03) sem comando em execucao" + tempo(msIdle));
            // ---- PID connectada DEPOIS do Ctrl+C ocioso: a sessao continua a mesma e viva. ----
            total++;
            boolean pidOciosoOk = vivoOcioso && pidOcioso == pidAntes;
            if (pidOciosoOk) ok++; System.out.println((pidOciosoOk ? "[OK]    " : "[FALHA] ") + nome + ": PID connectada(" + pidOcioso + ") - continuo na sessao" + tempo(0));
            // ---- Ctrl+C por SINAL REAL (so mini): o caminho de verdade do Ctrl+C do mini (SIGINT/BREAK ->
            // instalaCtrlC -> 0x03). (1) interrompeu o comando? (2) o cliente SOBREVIVEU (nao escapou)?
            // Linux: kill -INT no cliente da sessao (interrupcao lida em 'saida'). Windows: cliente dedicado
            // no proprio grupo + CTRL_BREAK (interrupcao lida do statusFile via ctrlCRealWindows -> sctInterrompeu). ----
            if (!ehSshPuro && sinalEntregue) {   // sinal real (so mini, e so quando foi de fato entregue)
                total++;
                boolean sinalInterrompeu = win ? sctInterrompeu
                                               : !(saida.contains("\nMINI_POSKILL") || saida.contains("\rMINI_POSKILL"));
                if (sinalInterrompeu) ok++; System.out.println((sinalInterrompeu ? "[OK]    " : "[FALHA] ") + nome + ": Ctrl+C (sinal real) interrompe o comando via instalaCtrlC" + tempo(msSinal));
                total++;
                if (clienteVivoAposSinal) ok++; System.out.println((clienteVivoAposSinal ? "[OK]    " : "[FALHA] ") + nome + ": cliente SOBREVIVE ao Ctrl+C real (nao escapou)" + tempo(0));
            }
            // ---- 'y' (a pedido, DEPOIS do Ctrl+C): pipe 'y help | y grep only' deve devolver
            // "-onlyDiff". O 'y' e um utilitario do usuario que DEVE existir no ambiente; se faltar,
            // e ERRO (sem estado "pulado"). ----
            total++;
            if (saida.contains("-onlyDiff")) { ok++; System.out.println("[OK]    " + nome + ": y help | y grep only (esperava -onlyDiff)" + tempo(msY)); }
            else if (saida.contains("MINI_YNAO")) System.out.println("[FALHA] " + nome + ": y help | y grep only ('y' nao existe no ambiente)" + tempo(msY));
            else {
                // 'y' existe (where/command-v achou) mas o pipe nao devolveu -onlyDiff: mostra a saida crua
                // p/ diagnosticar (pipe do cmd.exe sem ConPTY, exit code do y.bat, etc.). \\r e \\n visiveis.
                System.out.println("[FALHA] " + nome + ": y help | y grep only ('y' existe mas o pipe nao devolveu -onlyDiff)" + tempo(msY));
                String d = saida.length() > 500 ? saida.substring(saida.length() - 500) : saida;
                System.out.println("        (diag) ultimos 500 chars da saida: <<<" + d.replace("\r", "\\r").replace("\n", "\\n") + ">>>");
            }
            // ---- exit encerra a sessao: o processo do cliente termina sozinho (equivale ao antigo
            // "voltou ao shell local" — a sessao devolve o controle ao chamador). ----
            total++;
            if (terminou) ok++; System.out.println((terminou ? "[OK]    " : "[FALHA] ") + nome + ": exit encerra a sessao (processo do cliente termina)" + tempo(msExit));
            // ---- de volta ao host: apos o exit, o shell da sessao (PID connectada) tem de estar MORTO.
            // Junto ao check acima (cliente terminou), prova que a sessao acabou de ponta a ponta. ----
            total++;
            if (sessaoMorreu) ok++; System.out.println((sessaoMorreu ? "[OK]    " : "[FALHA] ") + nome + ": PID host(" + hostPid + ") - sessao (" + pidAntes + ") encerrada apos o exit" + tempo(0));
        } else if (ehSshPuro) {
            boolean hs = handshakeBatch(win, devnull, porta);
            total++; if (hs) ok++;
            System.out.println((hs ? "[OK]    " : "[FALHA] ") + nome + ": conecta + aceita host key ECDSA (handshake; senha nao automatizada neste host)");
        } else {
            total++;
            System.out.println("[FALHA] " + nome + ": nao conectou/autenticou (o echo nao voltou)");
        }
        return new int[]{ok, total};
    }

    // Manda um Ctrl+C/SIGINT REAL ao processo do cliente da sessao (nao um 0x03 no stdin). Linux: kill
    // -INT <pid> -> o JVM do cliente cai no handler do instalaCtrlC e converte em 0x03 no canal. No
    // Windows retorna false: la o Ctrl+C real e testado a parte por ctrlCRealWindows (cliente dedicado
    // no proprio grupo + CTRL_BREAK), pois injetar no cliente da sessao atingiria o proprio -test.
    static boolean enviarSigintReal(Process ps, boolean win) {
        if (win) return false;
        try {
            Process k = new ProcessBuilder("kill", "-INT", Long.toString(ps.pid())).start();
            return k.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && k.exitValue() == 0;
        } catch (Exception e) { return false; }
    }

    // Windows: testa o Ctrl+C REAL de forma ISOLADA do -test. Sobe um cliente DEDICADO no PROPRIO grupo
    // de processos (cmd 'start /b' => CREATE_NEW_PROCESS_GROUP; java vira lider, PID == id do grupo),
    // espera o comando remoto (ping) estar rodando (marca RUN no statusFile) e dispara CTRL_BREAK SO
    // nesse grupo via PowerShell (GenerateConsoleCtrlEvent). O cliente converte o sinal em 0x03
    // (instalaCtrlC trata INT e BREAK) e deve: (1) interromper o comando (DONE nunca sai) e (2)
    // SOBREVIVER (o processo segue vivo). CTRL_BREAK e mirado num grupo especifico -> NAO atinge o JVM
    // de teste nem o shell do servidor. Retorna {entregue, interrompeu, vivo}; entregue=false degrada
    // p/ a linha informativa. (O caminho do console-abort de um Ctrl+C real no teclado, so o teste
    // MANUAL cobre a fundo; aqui exercitamos o handler -> 0x03 -> interrompe -> cliente vivo.)
    static boolean[] ctrlCRealWindows(String fonteJava, int porta) {
        java.io.File status = null, ps1 = null;
        long pid = 0;
        boolean entregue = false, interrompeu = false, vivo = false;
        try {
            status = java.io.File.createTempFile("sshmini_sct", ".txt");
            java.nio.file.Files.writeString(status.toPath(), "");
            // cliente dedicado NO PROPRIO grupo de processos (start /b). O "" e o titulo vazio do 'start'.
            new ProcessBuilder("cmd", "/c", "start", "", "/b", "java", fonteJava,
                    "-ctrlcselftest", status.getAbsolutePath(), "-P", "" + porta)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .redirectInput(ProcessBuilder.Redirect.INHERIT)   // DISCARD e INVALIDO p/ stdin; o cliente self-test nao le stdin
                .start();
            // espera o cliente publicar o PID e o comando remoto comecar (marca RUN) — ate ~25s
            String s = "";
            for (int i = 0; i < 250 && !(s.contains("PID ") && s.contains("RUN")); i++) {
                try { Thread.sleep(100); } catch (Exception e) {}
                try { s = java.nio.file.Files.readString(status.toPath()); } catch (Exception e) {}
            }
            for (String ln : s.split("\\R"))
                if (ln.startsWith("PID ")) { try { pid = Long.parseLong(ln.substring(4).trim()); } catch (Exception e) {} }
            if (pid <= 0 || !s.contains("RUN")) return new boolean[]{false, false, false};   // cliente nao subiu/conectou
            try { Thread.sleep(500); } catch (Exception e) {}    // sinal logo no inicio do ping (dorme ~2s)
            // dispara CTRL_BREAK (evento 1) SO no grupo do cliente, via PowerShell + GenerateConsoleCtrlEvent
            ps1 = java.io.File.createTempFile("sshmini_break", ".ps1");
            java.nio.file.Files.writeString(ps1.toPath(),
                "param([int]$TargetPid)\n" +
                "$src = 'using System;using System.Runtime.InteropServices;public static class K{[DllImport(\"kernel32.dll\",SetLastError=true)]public static extern bool GenerateConsoleCtrlEvent(uint e,uint p);}'\n" +
                "Add-Type -TypeDefinition $src\n" +
                "if ([K]::GenerateConsoleCtrlEvent(1,[uint32]$TargetPid)) { 'BREAK_SENT' } else { 'BREAK_FAIL ' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() }\n");
            Process pw = new ProcessBuilder("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-File", ps1.getAbsolutePath(), "" + pid)
                .redirectErrorStream(true).start();
            String pwout = new String(pw.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            pw.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
            entregue = pwout.contains("BREAK_SENT");
            try { Thread.sleep(2500); } catch (Exception e) {}   // tempo do ping COMPLETAR (marcar DONE) se NAO interrompido (~2s)
            String s2 = "";
            try { s2 = java.nio.file.Files.readString(status.toPath()); } catch (Exception e) {}
            interrompeu = !s2.contains("DONE");                                        // ping nao terminou => interrompido
            vivo = ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);    // cliente sobreviveu ao sinal
            if (!entregue) { System.out.println("        (diag) Ctrl+C real: PowerShell nao confirmou o envio: " + pwout.trim()); return new boolean[]{false, false, false}; }
            return new boolean[]{true, interrompeu, vivo};
        } catch (Exception e) {
            System.out.println("        (diag) Ctrl+C real (windows) falhou: " + e);
            return new boolean[]{false, false, false};
        } finally {
            if (pid > 0) { final long fp = pid; ProcessHandle.of(fp).ifPresent(h -> { h.descendants().forEach(ProcessHandle::destroyForcibly); h.destroyForcibly(); }); }
            if (status != null) status.delete();
            if (ps1 != null) ps1.delete();
        }
    }

    // Fallback: valida so o handshake (BatchMode, sem senha) - host key ECDSA aceita e auth oferecida.
    static boolean handshakeBatch(boolean win, String devnull, int porta) {
        try {
            Process ps = new ProcessBuilder("ssh", "-v",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=" + devnull,
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", "" + porta, "admin@localhost")
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
    // servidor e o resumo ficam recuados; os [OK]/[FALHA] ficam na margem). Linhas em
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

// =====================================================================
// CRIPTO (portada de ~/claude/mldsa_ssh/DeriveSSHKey.java) — ML-DSA-44 (FIPS 204),
// Ed25519 e SHAKE do zero. O DeriveSSHKey tinha keygen+verify; aqui foi ADICIONADA a
// assinatura (ML-DSA Sign, Alg.7; Ed25519 Sign, RFC 8032). verify validado byte-a-byte
// vs NIST ACVP; sign validado por sign<->verify e (ed25519) contra o ssh nativo.
// =====================================================================

// Keccak-f[1600] + SHAKE-128/256 (XOF) com squeeze incremental.
class Shake {
    final long[] RC = {
        0x0000000000000001L,0x0000000000008082L,0x800000000000808aL,0x8000000080008000L,
        0x000000000000808bL,0x0000000080000001L,0x8000000080008081L,0x8000000000008009L,
        0x000000000000008aL,0x0000000000000088L,0x0000000080008009L,0x000000008000000aL,
        0x000000008000808bL,0x800000000000008bL,0x8000000000008089L,0x8000000000008003L,
        0x8000000000008002L,0x8000000000000080L,0x000000000000800aL,0x800000008000000aL,
        0x8000000080008081L,0x8000000000008080L,0x0000000080000001L,0x8000000080008008L };
    final int[] ROTC = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
    final int[] PILN = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
    final long[] s = new long[25];
    final int rate;
    final byte[] queued; int qlen;
    boolean squeezing;
    final byte[] block; int blkPos;

    Shake(int bits) { rate = (bits == 128) ? 168 : 136; queued = new byte[rate]; block = new byte[rate]; }

    Shake update(byte[] in) { return update(in, 0, in.length); }
    Shake update(byte[] in, int off, int len) {
        for (int i = 0; i < len; i++) { queued[qlen++] = in[off + i]; if (qlen == rate) { absorb(queued); qlen = 0; } }
        return this;
    }
    void absorb(byte[] blk) { for (int i = 0; i < rate/8; i++) s[i] ^= le64(blk, 8*i); keccak(); }
    void finishAbsorb() {
        byte[] pad = new byte[rate];
        System.arraycopy(queued, 0, pad, 0, qlen);
        pad[qlen] ^= 0x1F; pad[rate-1] ^= (byte)0x80;
        for (int i = 0; i < rate/8; i++) s[i] ^= le64(pad, 8*i);
        keccak(); squeezing = true; fill();
    }
    void fill() { for (int i = 0; i < rate/8; i++) putLe64(block, 8*i, s[i]); blkPos = 0; }
    byte[] squeeze(int n) {
        if (!squeezing) finishAbsorb();
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) { if (blkPos == rate) { keccak(); fill(); } out[i] = block[blkPos++]; }
        return out;
    }
    void keccak() {
        long[] a = s, bc = new long[5];
        for (int r = 0; r < 24; r++) {
            for (int i = 0; i < 5; i++) bc[i] = a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20];
            for (int i = 0; i < 5; i++) { long t = bc[(i+4)%5] ^ java.lang.Long.rotateLeft(bc[(i+1)%5],1); for (int j = 0; j < 25; j += 5) a[j+i] ^= t; }
            long t = a[1];
            for (int i = 0; i < 24; i++) { int j = PILN[i]; long tmp = a[j]; a[j] = java.lang.Long.rotateLeft(t, ROTC[i]); t = tmp; }
            for (int j = 0; j < 25; j += 5) { for (int i = 0; i < 5; i++) bc[i] = a[j+i]; for (int i = 0; i < 5; i++) a[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5]; }
            a[0] ^= RC[r];
        }
    }
    long le64(byte[] b, int o) { long r = 0; for (int i = 0; i < 8; i++) r |= (b[o+i]&0xFFL) << (8*i); return r; }
    void putLe64(byte[] b, int o, long v) { for (int i = 0; i < 8; i++) b[o+i] = (byte)(v >>> (8*i)); }
}

// ML-DSA-44 (FIPS 204): KeyGen (pública), Verify e Sign (Alg.7, determinístico).
class MlDsa {
    final int Q = 8380417, N = 256, D = 13, K = 4, L = 4, ETA = 2, TAU = 39, BETA = 78, OMEGA = 80;
    final int GAMMA1 = 1 << 17;
    final int GAMMA2 = (Q - 1) / 88;
    final int CTILDE = 32, SIGLEN = 2420, PKLEN = 1312;
    final int[] zetas = new int[N];
    final long NINV;

    MlDsa() { for (int i = 0; i < N; i++) zetas[i] = (int) modpow(1753, brv8(i), Q); NINV = modpow(N, Q - 2, Q); }

    long modpow(long b, long e, long m) { long r = 1; b %= m; while (e > 0) { if ((e&1)==1) r = r*b%m; b = b*b%m; e >>= 1; } return r; }
    int brv8(int x) { int r = 0; for (int i = 0; i < 8; i++) r = (r<<1)|((x>>i)&1); return r; }
    int modq(int x) { x %= Q; if (x < 0) x += Q; return x; }
    int cen(int x) { x %= Q; if (x < 0) x += Q; if (x > Q/2) x -= Q; return x; }
    int[] toModQ(int[] c) { int[] r = new int[N]; for (int i = 0; i < N; i++) r[i] = modq(c[i]); return r; }
    int[] nttOf(int[] a) { int[] c = toModQ(a); ntt(c); return c; }

    void ntt(int[] a) {
        int k = 0;
        for (int len = 128; len > 0; len >>= 1)
            for (int start = 0; start < N; start += 2*len) {
                long z = zetas[++k];
                for (int j = start; j < start+len; j++) {
                    long t = (z * a[j+len]) % Q; int u = a[j];
                    a[j+len] = (int)(((u - t) % Q + Q) % Q); a[j] = (int)((u + t) % Q);
                }
            }
    }
    void invntt(int[] a) {
        int k = N;
        for (int len = 1; len < N; len <<= 1)
            for (int start = 0; start < N; start += 2*len) {
                long z = Q - zetas[--k];
                for (int j = start; j < start+len; j++) {
                    int u = a[j], v = a[j+len];
                    a[j] = (int)(((long)u + v) % Q);
                    int diff = (int)(((u - v) % Q + Q) % Q);
                    a[j+len] = (int)((z * diff) % Q);
                }
            }
        for (int j = 0; j < N; j++) a[j] = (int)((NINV * a[j]) % Q);
    }
    int[] pointwise(int[] a, int[] b) { int[] c = new int[N]; for (int i = 0; i < N; i++) c[i] = (int)(((long)a[i]*b[i]) % Q); return c; }

    byte[] shake(int bits, int outLen, byte[]... parts) { Shake s = new Shake(bits); for (byte[] p : parts) s.update(p); return s.squeeze(outLen); }

    int[][][] expandA(byte[] rho) {
        int[][][] A = new int[K][L][];
        for (int r = 0; r < K; r++) for (int c = 0; c < L; c++) {
            Shake x = new Shake(128); x.update(rho); x.update(new byte[]{ (byte)c, (byte)r });
            int[] a = new int[N]; int ctr = 0;
            while (ctr < N) { byte[] b = x.squeeze(3); int d = (b[0]&0xFF)|((b[1]&0xFF)<<8)|((b[2]&0x7F)<<16); if (d < Q) a[ctr++] = d; }
            A[r][c] = a;
        }
        return A;
    }
    int[] rejBounded(byte[] rhoprime, int nonce) {
        Shake x = new Shake(256); x.update(rhoprime); x.update(new byte[]{ (byte)(nonce&0xFF), (byte)((nonce>>8)&0xFF) });
        int[] a = new int[N]; int ctr = 0;
        while (ctr < N) { int b = x.squeeze(1)[0]&0xFF; int z0 = b&0x0F, z1 = b>>4;
            if (z0 < 15) { a[ctr++] = 2 - (z0 % 5); if (ctr == N) break; }
            if (z1 < 15) { a[ctr++] = 2 - (z1 % 5); } }
        return a;
    }
    int[] expandMask(byte[] rhopp, int nonce) {
        Shake x = new Shake(256); x.update(rhopp); x.update(new byte[]{ (byte)(nonce&0xFF), (byte)((nonce>>8)&0xFF) });
        byte[] buf = x.squeeze(N*18/8);
        int[] v = unpack(buf, 0, 18); int[] y = new int[N];
        for (int j = 0; j < N; j++) y[j] = GAMMA1 - v[j];
        return y;
    }

    /** KeyGen_internal(ξ) → apenas a chave pública. */
    byte[] keyGenPk(byte[] xi) {
        byte[] H = shake(256, 128, xi, new byte[]{ (byte)K }, new byte[]{ (byte)L });
        byte[] rho = java.util.Arrays.copyOfRange(H, 0, 32);
        byte[] rhoprime = java.util.Arrays.copyOfRange(H, 32, 96);
        int[][][] A = expandA(rho);
        int[][] s1 = new int[L][], s2 = new int[K][];
        for (int i = 0; i < L; i++) s1[i] = rejBounded(rhoprime, i);
        for (int i = 0; i < K; i++) s2[i] = rejBounded(rhoprime, L + i);
        int[][] s1hat = new int[L][]; for (int i = 0; i < L; i++) s1hat[i] = nttOf(s1[i]);
        int[][] t1 = new int[K][N];
        for (int r = 0; r < K; r++) {
            int[] acc = new int[N];
            for (int c = 0; c < L; c++) { int[] p = pointwise(A[r][c], s1hat[c]); for (int j = 0; j < N; j++) acc[j] = (int)(((long)acc[j]+p[j])%Q); }
            invntt(acc);
            for (int j = 0; j < N; j++) { int v = modq(acc[j] + s2[r][j]); int a1 = (v + (1<<(D-1)) - 1) >> D; t1[r][j] = a1; }
        }
        byte[] pk = new byte[PKLEN];
        System.arraycopy(rho, 0, pk, 0, 32);
        for (int r = 0; r < K; r++) pack(pk, 32 + r*(N*10/8), t1[r], 10);
        return pk;
    }

    /** Sign_internal(sk=ξ, M, ctx) → assinatura de SIGLEN bytes. Determinístico (rnd = 0^256). */
    byte[] sign(byte[] xi, byte[] msg, byte[] ctx) {
        byte[] H = shake(256, 128, xi, new byte[]{ (byte)K }, new byte[]{ (byte)L });
        byte[] rho = java.util.Arrays.copyOfRange(H, 0, 32);
        byte[] rhoprime = java.util.Arrays.copyOfRange(H, 32, 96);
        byte[] Kk = java.util.Arrays.copyOfRange(H, 96, 128);
        int[][][] A = expandA(rho);
        int[][] s1 = new int[L][], s2 = new int[K][];
        for (int i = 0; i < L; i++) s1[i] = rejBounded(rhoprime, i);
        for (int i = 0; i < K; i++) s2[i] = rejBounded(rhoprime, L + i);
        int[][] s1hat = new int[L][]; for (int i = 0; i < L; i++) s1hat[i] = nttOf(s1[i]);
        int[][] t0 = new int[K][N], t1 = new int[K][N];
        for (int r = 0; r < K; r++) {
            int[] acc = new int[N];
            for (int c = 0; c < L; c++) { int[] p = pointwise(A[r][c], s1hat[c]); for (int j = 0; j < N; j++) acc[j] = (int)(((long)acc[j]+p[j])%Q); }
            invntt(acc);
            for (int j = 0; j < N; j++) { int v = modq(acc[j] + s2[r][j]); int a1 = (v + (1<<(D-1)) - 1) >> D; t1[r][j] = a1; t0[r][j] = v - (a1 << D); }
        }
        byte[] pk = new byte[PKLEN];
        System.arraycopy(rho, 0, pk, 0, 32);
        for (int r = 0; r < K; r++) pack(pk, 32 + r*(N*10/8), t1[r], 10);
        byte[] tr = shake(256, 64, pk);
        Shake sm = new Shake(256); sm.update(tr); sm.update(new byte[]{ 0, (byte)ctx.length }); sm.update(ctx); sm.update(msg);
        byte[] mu = sm.squeeze(64);
        byte[] rhopp = shake(256, 64, Kk, new byte[32], mu);
        int[][] s2hat = new int[K][]; for (int r = 0; r < K; r++) s2hat[r] = nttOf(s2[r]);
        int[][] t0hat = new int[K][]; for (int r = 0; r < K; r++) t0hat[r] = nttOf(t0[r]);
        int kappa = 0;
        while (true) {
            int[][] y = new int[L][]; for (int i = 0; i < L; i++) y[i] = expandMask(rhopp, kappa + i);
            int[][] yhat = new int[L][]; for (int i = 0; i < L; i++) yhat[i] = nttOf(y[i]);
            int[][] w = new int[K][N];
            for (int r = 0; r < K; r++) {
                int[] acc = new int[N];
                for (int c = 0; c < L; c++) { int[] p = pointwise(A[r][c], yhat[c]); for (int j = 0; j < N; j++) acc[j] = (int)(((long)acc[j]+p[j])%Q); }
                invntt(acc);
                for (int j = 0; j < N; j++) w[r][j] = modq(acc[j]);
            }
            int[][] w1 = new int[K][N];
            for (int r = 0; r < K; r++) for (int j = 0; j < N; j++) w1[r][j] = decompose(w[r][j])[0];
            byte[] w1enc = new byte[K*(N*6/8)];
            for (int r = 0; r < K; r++) pack(w1enc, r*(N*6/8), w1[r], 6);
            byte[] ctilde = shake(256, CTILDE, mu, w1enc);
            int[] chat = toModQ(sampleInBall(ctilde)); ntt(chat);
            // z = y + c*s1
            int[][] z = new int[L][N]; int zmax = 0;
            for (int i = 0; i < L; i++) { int[] cs1 = pointwise(chat, s1hat[i]); invntt(cs1);
                for (int j = 0; j < N; j++) { int zc = cen(y[i][j] + cs1[j]); z[i][j] = zc; int a = zc<0?-zc:zc; if (a > zmax) zmax = a; } }
            if (zmax >= GAMMA1 - BETA) { kappa += L; continue; }
            // r0 = LowBits(w - c*s2)
            int[][] wmcs2 = new int[K][N]; int r0max = 0;
            for (int r = 0; r < K; r++) { int[] cs2 = pointwise(chat, s2hat[r]); invntt(cs2);
                for (int j = 0; j < N; j++) { int val = modq(w[r][j] - cs2[j]); wmcs2[r][j] = val; int r0 = decompose(val)[1]; int a = r0<0?-r0:r0; if (a > r0max) r0max = a; } }
            if (r0max >= GAMMA2 - BETA) { kappa += L; continue; }
            // ct0 = c*t0
            int[][] ct0 = new int[K][N]; int ct0max = 0;
            for (int r = 0; r < K; r++) { int[] cc = pointwise(chat, t0hat[r]); invntt(cc);
                for (int j = 0; j < N; j++) { int v = cen(cc[j]); ct0[r][j] = v; int a = v<0?-v:v; if (a > ct0max) ct0max = a; } }
            if (ct0max >= GAMMA2) { kappa += L; continue; }
            // h = MakeHint(-ct0, w - c*s2 + ct0)
            int[][] h = new int[K][N]; int hw = 0;
            for (int r = 0; r < K; r++) for (int j = 0; j < N; j++) {
                int rr = modq(wmcs2[r][j] + ct0[r][j]);
                int hb = (decompose(rr)[0] != decompose(wmcs2[r][j])[0]) ? 1 : 0;
                h[r][j] = hb; hw += hb;
            }
            if (hw > OMEGA) { kappa += L; continue; }
            return sigEncode(ctilde, z, h);
        }
    }
    byte[] sigEncode(byte[] ctilde, int[][] z, int[][] h) {
        byte[] sig = new byte[SIGLEN];
        System.arraycopy(ctilde, 0, sig, 0, CTILDE);
        for (int i = 0; i < L; i++) { int[] enc = new int[N]; for (int j = 0; j < N; j++) enc[j] = GAMMA1 - z[i][j]; pack(sig, CTILDE + i*(N*18/8), enc, 18); }
        int off = CTILDE + L*(N*18/8); int idx = 0;
        for (int r = 0; r < K; r++) { for (int j = 0; j < N; j++) if (h[r][j] == 1) { sig[off + idx] = (byte)j; idx++; } sig[off + OMEGA + r] = (byte)idx; }
        return sig;
    }

    boolean verify(byte[] pk, byte[] msg, byte[] ctx, byte[] sig) {
        if (sig.length != SIGLEN || pk.length != PKLEN) return false;
        byte[] rho = java.util.Arrays.copyOfRange(pk, 0, 32);
        int[][] t1 = new int[K][];
        for (int r = 0; r < K; r++) t1[r] = unpack(pk, 32 + r*(N*10/8), 10);

        byte[] ctilde = java.util.Arrays.copyOfRange(sig, 0, CTILDE);
        int[][] z = new int[L][];
        for (int i = 0; i < L; i++) { int[] v = unpack(sig, CTILDE + i*(N*18/8), 18); int[] zi = new int[N]; for (int j = 0; j < N; j++) zi[j] = GAMMA1 - v[j]; z[i] = zi; }
        int[][] h = hintUnpack(sig, CTILDE + L*(N*18/8));
        if (h == null) return false;
        for (int i = 0; i < L; i++) for (int j = 0; j < N; j++) { int a = z[i][j]; if (a < 0) a = -a; if (a >= GAMMA1 - BETA) return false; }

        int[][][] A = expandA(rho);
        byte[] tr = shake(256, 64, pk);
        Shake sm = new Shake(256); sm.update(tr); sm.update(new byte[]{ 0, (byte)ctx.length }); sm.update(ctx); sm.update(msg);
        byte[] mu = sm.squeeze(64);

        int[] chat = toModQ(sampleInBall(ctilde)); ntt(chat);
        int[][] zhat = new int[L][]; for (int i = 0; i < L; i++) { zhat[i] = toModQ(z[i]); ntt(zhat[i]); }

        int[][] w1 = new int[K][N];
        for (int r = 0; r < K; r++) {
            int[] acc = new int[N];
            for (int c = 0; c < L; c++) { int[] p = pointwise(A[r][c], zhat[c]); for (int j = 0; j < N; j++) acc[j] = (int)(((long)acc[j]+p[j])%Q); }
            int[] t1x = new int[N]; for (int j = 0; j < N; j++) t1x[j] = (int)(((long)t1[r][j] << D) % Q); ntt(t1x);
            int[] ct1 = pointwise(chat, t1x);
            for (int j = 0; j < N; j++) { int v = (int)(((long)acc[j] - ct1[j]) % Q); if (v < 0) v += Q; acc[j] = v; }
            invntt(acc);
            for (int j = 0; j < N; j++) w1[r][j] = useHint(h[r][j], acc[j]);
        }
        byte[] w1enc = new byte[K*(N*6/8)];
        for (int r = 0; r < K; r++) pack(w1enc, r*(N*6/8), w1[r], 6);
        byte[] ct2 = shake(256, CTILDE, mu, w1enc);
        return java.util.Arrays.equals(ctilde, ct2);
    }

    int[] sampleInBall(byte[] ctilde) {
        Shake s = new Shake(256); s.update(ctilde);
        byte[] buf = s.squeeze(8);
        long signs = 0; for (int i = 0; i < 8; i++) signs |= (buf[i]&0xFFL) << (8*i);
        int[] c = new int[N];
        for (int i = N - TAU; i < N; i++) {
            int j; do { j = s.squeeze(1)[0] & 0xFF; } while (j > i);
            c[i] = c[j]; c[j] = 1 - 2*(int)(signs & 1); signs >>= 1;
        }
        return c;
    }
    int[] decompose(int r) {
        r = modq(r);
        int r0 = r % (2*GAMMA2); if (r0 > GAMMA2) r0 -= 2*GAMMA2;
        int r1;
        if (r - r0 == Q - 1) { r1 = 0; r0 = r0 - 1; } else r1 = (r - r0) / (2*GAMMA2);
        return new int[]{ r1, r0 };
    }
    int useHint(int hbit, int r) {
        int m = (Q - 1) / (2*GAMMA2);
        int[] d = decompose(r); int r1 = d[0], r0 = d[1];
        if (hbit == 1) { if (r0 > 0) r1 = (r1 + 1) % m; else { r1 = (r1 - 1) % m; if (r1 < 0) r1 += m; } }
        return r1;
    }
    int[][] hintUnpack(byte[] sig, int off) {
        int[][] h = new int[K][N]; int idx = 0;
        for (int i = 0; i < K; i++) {
            int cnt = sig[off + OMEGA + i] & 0xFF;
            if (cnt < idx || cnt > OMEGA) return null;
            int first = idx;
            while (idx < cnt) {
                int pos = sig[off + idx] & 0xFF;
                if (idx > first) { int prev = sig[off + idx - 1] & 0xFF; if (prev >= pos) return null; }
                h[i][pos] = 1; idx++;
            }
        }
        for (int i = idx; i < OMEGA; i++) if (sig[off + i] != 0) return null;
        return h;
    }
    void pack(byte[] out, int off, int[] vals, int bits) {
        int acc = 0, nb = 0, o = off, mask = (1<<bits)-1;
        for (int i = 0; i < N; i++) { acc |= (vals[i]&mask) << nb; nb += bits; while (nb >= 8) { out[o++] = (byte)acc; acc >>>= 8; nb -= 8; } }
    }
    int[] unpack(byte[] in, int off, int bits) {
        int[] out = new int[N]; int acc = 0, nb = 0, o = off, mask = (1<<bits)-1;
        for (int i = 0; i < N; i++) { while (nb < bits) { acc |= (in[o++]&0xFF) << nb; nb += 8; } out[i] = acc & mask; acc >>>= bits; nb -= bits; }
        return out;
    }
}

// Ed25519 (RFC 8032) do zero via BigInteger: pública a partir da seed, Sign e Verify.
class Ed {
    final java.math.BigInteger P, D, SQRT_M1, ORDER;
    final java.math.BigInteger[] BASE;

    Ed() {
        P = java.math.BigInteger.TWO.pow(255).subtract(java.math.BigInteger.valueOf(19));
        D = modInv(java.math.BigInteger.valueOf(121666)).multiply(java.math.BigInteger.valueOf(-121665).mod(P)).mod(P);
        SQRT_M1 = java.math.BigInteger.TWO.modPow(P.subtract(java.math.BigInteger.ONE).divide(java.math.BigInteger.valueOf(4)), P);
        java.math.BigInteger gy = modInv(java.math.BigInteger.valueOf(5)).multiply(java.math.BigInteger.valueOf(4)).mod(P);
        BASE = new java.math.BigInteger[]{ recoverX(gy, 0), gy };
        ORDER = java.math.BigInteger.TWO.pow(252).add(new java.math.BigInteger("27742317777372353535851937790883648493"));
    }

    byte[] cat(byte[] x, byte[] y) { byte[] r = new byte[x.length + y.length]; System.arraycopy(x,0,r,0,x.length); System.arraycopy(y,0,r,x.length,y.length); return r; }

    byte[] publicFromSeed(byte[] seed) throws java.lang.Exception {
        byte[] h = sha512(seed); h[0] &= 248; h[31] &= 127; h[31] |= 64;
        return encodePoint(scalarMul(BASE, fromLE(h, 0, 32)));
    }
    byte[] sign(byte[] seed, byte[] msg) throws java.lang.Exception {
        byte[] h = sha512(seed);
        byte[] a = java.util.Arrays.copyOfRange(h, 0, 32); a[0] &= 248; a[31] &= 127; a[31] |= 64;
        java.math.BigInteger s = fromLE(a, 0, 32);
        byte[] prefix = java.util.Arrays.copyOfRange(h, 32, 64);
        byte[] A = encodePoint(scalarMul(BASE, s));
        java.math.BigInteger r = fromLE(sha512(cat(prefix, msg)), 0, 64).mod(ORDER);
        byte[] R = encodePoint(scalarMulId(BASE, r));
        java.math.BigInteger k = fromLE(sha512(cat(cat(R, A), msg)), 0, 64).mod(ORDER);
        java.math.BigInteger S = r.add(k.multiply(s)).mod(ORDER);
        byte[] out = new byte[64]; System.arraycopy(R, 0, out, 0, 32); System.arraycopy(toLE32(S), 0, out, 32, 32);
        return out;
    }
    boolean verify(byte[] pk, byte[] msg, byte[] sig) throws java.lang.Exception {
        if (pk.length != 32 || sig.length != 64) return false;
        java.math.BigInteger[] A = decodePoint(pk); if (A == null) return false;
        java.math.BigInteger[] R = decodePoint(java.util.Arrays.copyOfRange(sig, 0, 32)); if (R == null) return false;
        java.math.BigInteger S = fromLE(sig, 32, 32); if (S.compareTo(ORDER) >= 0) return false;
        byte[] rab = new byte[32 + 32 + msg.length];
        System.arraycopy(sig, 0, rab, 0, 32); System.arraycopy(pk, 0, rab, 32, 32); System.arraycopy(msg, 0, rab, 64, msg.length);
        java.math.BigInteger k = fromLE(sha512(rab), 0, 64).mod(ORDER);
        java.math.BigInteger[] lhs = scalarMulId(BASE, S);
        java.math.BigInteger[] rhs = pointAdd(R, scalarMulId(A, k));
        return java.util.Arrays.equals(encodePoint(lhs), encodePoint(rhs));
    }
    java.math.BigInteger[] decodePoint(byte[] e) {
        byte[] le = e.clone(); int sign = (le[31] >> 7) & 1; le[31] &= 0x7f;
        java.math.BigInteger y = fromLE(le, 0, 32); if (y.compareTo(P) >= 0) return null;
        return new java.math.BigInteger[]{ recoverX(y, sign), y };
    }
    java.math.BigInteger modInv(java.math.BigInteger x) { return x.modPow(P.subtract(java.math.BigInteger.TWO), P); }
    java.math.BigInteger recoverX(java.math.BigInteger y, int xSign) {
        java.math.BigInteger y2 = y.multiply(y).mod(P);
        java.math.BigInteger u = y2.subtract(java.math.BigInteger.ONE).mod(P);
        java.math.BigInteger v = D.multiply(y2).add(java.math.BigInteger.ONE).mod(P);
        java.math.BigInteger x2 = u.multiply(modInv(v)).mod(P);
        if (x2.equals(java.math.BigInteger.ZERO)) return java.math.BigInteger.ZERO;
        java.math.BigInteger exp = P.add(java.math.BigInteger.valueOf(3)).divide(java.math.BigInteger.valueOf(8));
        java.math.BigInteger x = x2.modPow(exp, P);
        if (!x.multiply(x).mod(P).equals(x2)) x = x.multiply(SQRT_M1).mod(P);
        if (x.testBit(0) != (xSign == 1)) x = P.subtract(x);
        return x;
    }
    java.math.BigInteger[] pointAdd(java.math.BigInteger[] A, java.math.BigInteger[] B) {
        java.math.BigInteger x1 = A[0], y1 = A[1], x2 = B[0], y2 = B[1];
        java.math.BigInteger dxy = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(P);
        java.math.BigInteger x3 = x1.multiply(y2).add(y1.multiply(x2)).multiply(modInv(java.math.BigInteger.ONE.add(dxy))).mod(P);
        java.math.BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2)).multiply(modInv(java.math.BigInteger.ONE.subtract(dxy).mod(P))).mod(P);
        return new java.math.BigInteger[]{ x3, y3 };
    }
    java.math.BigInteger[] scalarMul(java.math.BigInteger[] point, java.math.BigInteger scalar) {
        java.math.BigInteger[] result = null, cur = point;
        while (scalar.signum() > 0) {
            if (scalar.testBit(0)) result = (result == null) ? cur : pointAdd(result, cur);
            cur = pointAdd(cur, cur); scalar = scalar.shiftRight(1);
        }
        return result;
    }
    java.math.BigInteger[] scalarMulId(java.math.BigInteger[] point, java.math.BigInteger scalar) {
        java.math.BigInteger[] r = scalarMul(point, scalar);
        return (r == null) ? new java.math.BigInteger[]{ java.math.BigInteger.ZERO, java.math.BigInteger.ONE } : r;
    }
    byte[] encodePoint(java.math.BigInteger[] pt) { byte[] out = toLE32(pt[1]); if (pt[0].testBit(0)) out[31] |= (byte)0x80; return out; }
    byte[] sha512(byte[] d) throws java.lang.Exception { return java.security.MessageDigest.getInstance("SHA-512").digest(d); }
    java.math.BigInteger fromLE(byte[] b, int off, int len) {
        byte[] le = java.util.Arrays.copyOfRange(b, off, off + len);
        for (int i = 0, j = le.length - 1; i < j; i++, j--) { byte t = le[i]; le[i] = le[j]; le[j] = t; }
        return new java.math.BigInteger(1, le);
    }
    byte[] toLE32(java.math.BigInteger n) {
        byte[] be = n.toByteArray(); int off = (be.length > 32 && be[0] == 0) ? 1 : 0; int len = be.length - off;
        byte[] out = new byte[32]; for (int i = 0; i < len && i < 32; i++) out[i] = be[off + len - 1 - i]; return out;
    }
}

// Facade: geração/assinatura/verificação/parse de chaves SSH (ed25519 e mldsa44-ed25519).
class SshKeys {
    final int ITERATIONS = 400_000;
    final java.security.SecureRandom RNG = new java.security.SecureRandom();
    final Ed ed = new Ed();
    final MlDsa mldsa = new MlDsa();
    final String MLDSA_TYPE = "ssh-mldsa44-ed25519@openssh.com";
    final String ED_TYPE    = "ssh-ed25519";
    final byte[] COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    final byte[] COMPOSITE_LABEL  = "COMPSIG-MLDSA44-Ed25519-SHA512".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    boolean isPqType(String t) { return t.equals("mldsa44-ed25519") || t.equals(MLDSA_TYPE); }
    boolean isEdType(String t) { return t.equals("ed25519") || t.equals(ED_TYPE); }

    // { privadaPEM(openssh-key-v1), publicaLine(authorized_keys) }
    // Comentario = nome (comportamento padrao; usado pelos testes internos).
    String[] generate(String tipo, String passphrase, String nome) throws java.lang.Exception {
        return generate(tipo, passphrase, nome, nome);
    }
    // 'nome' define o nome de arquivo e o salt do PBKDF2 (determinismo); 'comment' e so o rotulo da
    // .pub/privada e NAO afeta a chave (igual ao ssh-keygen -C).
    String[] generate(String tipo, String passphrase, String nome, String comment) throws java.lang.Exception {
        if (nome == null) nome = "";
        if (comment == null) comment = nome;
        boolean pq = isPqType(tipo), ec = isEdType(tipo);
        if (!pq && !ec) throw new java.lang.IllegalArgumentException("tipo desconhecido: " + tipo);
        String saltBase = nome.isEmpty() ? "sshmini" : nome;   // evita salt vazio no PBKDF2
        String priv, pub;
        if (pq) {
            byte[] mldsaSeed, edSeed;
            if (passphrase == null) { mldsaSeed = rand(32); edSeed = rand(32); }
            else { mldsaSeed = pbkdf2(passphrase, saltBase + " mldsa44", 32); edSeed = pbkdf2(passphrase, saltBase + " ed25519", 32); }
            byte[] mldsaPk = mldsa.keyGenPk(mldsaSeed);
            byte[] edPk    = ed.publicFromSeed(edSeed);
            priv = compositePrivatePem(mldsaPk, edPk, mldsaSeed, edSeed, comment);
            pub  = compositePublicLine(mldsaPk, edPk, comment);
        } else {
            byte[] seed = (passphrase == null) ? rand(32) : pbkdf2(passphrase, saltBase, 32);
            byte[] edPk = ed.publicFromSeed(seed);
            priv = ed25519PrivatePem(seed, edPk, comment);
            pub  = ed25519PublicLine(edPk, comment);
        }
        return new String[]{ priv, pub };
    }

    // assina 'message' produzindo a assinatura no formato SSH (string tipo ‖ string sig)
    byte[] signSSH(String type, byte[][] seeds, byte[] message) throws java.lang.Exception {
        if (isEdType(type)) return blob(ED_TYPE, ed.sign(seeds[0], message));
        if (isPqType(type)) {
            byte[] mp = constructMPrime(message);
            byte[] ms = mldsa.sign(seeds[0], mp, COMPOSITE_LABEL);
            byte[] es = ed.sign(seeds[1], mp);
            return blob(MLDSA_TYPE, cat(ms, es));
        }
        throw new java.lang.IllegalArgumentException("tipo desconhecido: " + type);
    }

    boolean verifySSH(String publicaLine, byte[] mensagem, byte[] assinaturaSSH) throws java.lang.Exception {
        String[] parts = publicaLine.trim().split("\\s+");
        if (parts.length < 2) return false;
        return verifyBlob(java.util.Base64.getDecoder().decode(parts[1]), mensagem, assinaturaSSH);
    }
    boolean verifyBlob(byte[] pubBlob, byte[] mensagem, byte[] assinaturaSSH) throws java.lang.Exception {
        Reader pr = new Reader(pubBlob); String ptype = pr.str();
        Reader sr = new Reader(assinaturaSSH); String stype = sr.str(); byte[] sigRaw = sr.bytes();
        if (!ptype.equals(stype)) return false;
        if (ptype.equals(MLDSA_TYPE)) {
            byte[] comp = pr.bytes();
            if (comp.length != 1344 || sigRaw.length != 2484) return false;
            byte[] mldsaPk  = java.util.Arrays.copyOfRange(comp, 0, 1312);
            byte[] edPk     = java.util.Arrays.copyOfRange(comp, 1312, 1344);
            byte[] mldsaSig = java.util.Arrays.copyOfRange(sigRaw, 0, 2420);
            byte[] edSig    = java.util.Arrays.copyOfRange(sigRaw, 2420, 2484);
            byte[] mp = constructMPrime(mensagem);
            return mldsa.verify(mldsaPk, mp, COMPOSITE_LABEL, mldsaSig) && ed.verify(edPk, mp, edSig);
        } else if (ptype.equals(ED_TYPE)) {
            byte[] edPk = pr.bytes();
            if (edPk.length != 32 || sigRaw.length != 64) return false;
            return ed.verify(edPk, mensagem, sigRaw);
        }
        return false;
    }

    // Privado openssh-key-v1 -> { tipo, seeds, pubBlob, comentario }
    Priv parsePriv(String pem) throws java.lang.Exception {
        StringBuilder b64 = new StringBuilder();
        for (String ln : pem.split("\\R")) { if (ln.startsWith("-----") || ln.isBlank()) continue; b64.append(ln.trim()); }
        byte[] outer = java.util.Base64.getDecoder().decode(b64.toString());
        Reader r = new Reader(outer);
        r.skip(15);          // "openssh-key-v1\0"
        r.str(); r.str();    // cipher, kdf ("none")
        r.bytes();           // kdfoptions
        r.u32();             // numkeys
        byte[] pubBlob = r.bytes();
        byte[] privSection = r.bytes();
        Reader pr = new Reader(privSection);
        pr.u32(); pr.u32();  // check1, check2
        String type = pr.str();
        Priv out = new Priv(); out.type = type; out.pubBlob = pubBlob;
        if (type.equals(ED_TYPE)) {
            pr.bytes();                       // pub
            byte[] priv64 = pr.bytes();       // seed(32)‖pub(32)
            out.comment = pr.str();
            out.seeds = new byte[][]{ java.util.Arrays.copyOfRange(priv64, 0, 32) };
        } else if (type.equals(MLDSA_TYPE)) {
            pr.bytes();                       // compPub
            byte[] compPriv = pr.bytes();     // mldsaSeed(32)‖edSeed(32)
            out.comment = pr.str();
            out.seeds = new byte[][]{ java.util.Arrays.copyOfRange(compPriv, 0, 32), java.util.Arrays.copyOfRange(compPriv, 32, 64) };
        } else throw new java.lang.Exception("tipo de chave privada desconhecido: " + type);
        return out;
    }
    // linha authorized_keys -> pubBlob (string tipo ‖ string chave)
    byte[] parsePub(String publicaLine) { String[] p = publicaLine.trim().split("\\s+"); return java.util.Base64.getDecoder().decode(p[1]); }
    // Le varios arquivos de pubs (cada um pode ter varias linhas, estilo known_hosts/authorized_keys)
    // e devolve todos os blobs (string tipo ‖ string chave). Pula vazias, comentarios e linhas invalidas.
    java.util.List<byte[]> parsePubFiles(java.util.List<String> arquivos) throws java.lang.Exception {
        java.util.List<byte[]> out = new java.util.ArrayList<byte[]>();
        for (String f : arquivos)
            for (String ln : java.nio.file.Files.readAllLines(java.nio.file.Path.of(f))) {
                ln = ln.trim(); if (ln.isEmpty() || ln.startsWith("#")) continue;
                String[] p = ln.split("\\s+"); if (p.length < 2) continue;
                try { out.add(java.util.Base64.getDecoder().decode(p[1])); } catch (Exception e) {}
            }
        return out;
    }
    String typeOfBlob(byte[] pubBlob) { return new Reader(pubBlob).str(); }
    String pubLineFromBlob(byte[] pubBlob, String comment) {
        String type = typeOfBlob(pubBlob);
        return type + " " + java.util.Base64.getEncoder().encodeToString(pubBlob) + (comment == null || comment.isEmpty() ? "" : " " + comment);
    }

    static class Priv { String type; byte[][] seeds; byte[] pubBlob; String comment; }

    // ---- apoio ----
    byte[] constructMPrime(byte[] msg) throws java.lang.Exception {
        byte[] h = sha512(msg);
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        b.write(COMPOSITE_PREFIX); b.write(COMPOSITE_LABEL); b.write(0); b.write(h);
        return b.toByteArray();
    }
    byte[] sha512(byte[] d) throws java.lang.Exception { return java.security.MessageDigest.getInstance("SHA-512").digest(d); }
    byte[] pbkdf2(String pass, String salt, int nbytes) throws java.lang.Exception {
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                pass.toCharArray(), salt.getBytes(java.nio.charset.StandardCharsets.UTF_8), ITERATIONS, nbytes * 8);
        return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).getEncoded();
    }
    byte[] rand(int n) { byte[] b = new byte[n]; RNG.nextBytes(b); return b; }
    byte[] utf8(String s) { return s.getBytes(java.nio.charset.StandardCharsets.UTF_8); }
    byte[] cat(byte[] a, byte[] b) { byte[] r = new byte[a.length + b.length]; System.arraycopy(a,0,r,0,a.length); System.arraycopy(b,0,r,a.length,b.length); return r; }
    byte[] blob(String type, byte[] raw) throws java.lang.Exception {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream(); wstr(o, utf8(type)); wstr(o, raw); return o.toByteArray();
    }
    void wu32(java.io.ByteArrayOutputStream os, int v) { os.write((v>>>24)&0xFF); os.write((v>>>16)&0xFF); os.write((v>>>8)&0xFF); os.write(v&0xFF); }
    void wstr(java.io.ByteArrayOutputStream os, byte[] d) throws java.io.IOException { wu32(os, d.length); os.write(d); }

    String compositePublicLine(byte[] mldsaPk, byte[] edPk, String comment) throws java.io.IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        wstr(buf, utf8(MLDSA_TYPE)); wstr(buf, cat(mldsaPk, edPk));
        return MLDSA_TYPE + " " + java.util.Base64.getEncoder().encodeToString(buf.toByteArray()) + (comment.isEmpty() ? "" : " " + comment) + "\n";
    }
    String ed25519PublicLine(byte[] edPk, String comment) throws java.io.IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        wstr(buf, utf8(ED_TYPE)); wstr(buf, edPk);
        return ED_TYPE + " " + java.util.Base64.getEncoder().encodeToString(buf.toByteArray()) + (comment.isEmpty() ? "" : " " + comment) + "\n";
    }
    String compositePrivatePem(byte[] mldsaPk, byte[] edPk, byte[] mldsaSeed, byte[] edSeed, String comment) throws java.io.IOException {
        byte[] compPub = cat(mldsaPk, edPk), compPriv = cat(mldsaSeed, edSeed);
        java.io.ByteArrayOutputStream pubBlob = new java.io.ByteArrayOutputStream();
        wstr(pubBlob, utf8(MLDSA_TYPE)); wstr(pubBlob, compPub);
        java.io.ByteArrayOutputStream block = new java.io.ByteArrayOutputStream();
        wu32(block, 0x12345678); wu32(block, 0x12345678);
        wstr(block, utf8(MLDSA_TYPE)); wstr(block, compPub); wstr(block, compPriv); wstr(block, utf8(comment));
        return wrapOpenssh(pubBlob.toByteArray(), block.toByteArray());
    }
    String ed25519PrivatePem(byte[] seed, byte[] edPk, String comment) throws java.io.IOException {
        byte[] priv64 = cat(seed, edPk);
        java.io.ByteArrayOutputStream pubBlob = new java.io.ByteArrayOutputStream();
        wstr(pubBlob, utf8(ED_TYPE)); wstr(pubBlob, edPk);
        java.io.ByteArrayOutputStream block = new java.io.ByteArrayOutputStream();
        wu32(block, 0x12345678); wu32(block, 0x12345678);
        wstr(block, utf8(ED_TYPE)); wstr(block, edPk); wstr(block, priv64); wstr(block, utf8(comment));
        return wrapOpenssh(pubBlob.toByteArray(), block.toByteArray());
    }
    String wrapOpenssh(byte[] pubBlob, byte[] block) throws java.io.IOException {
        int padLen = (8 - (block.length % 8)) % 8;
        byte[] padded = java.util.Arrays.copyOf(block, block.length + padLen);
        for (int i = 0; i < padLen; i++) padded[block.length + i] = (byte)(i + 1);
        java.io.ByteArrayOutputStream outer = new java.io.ByteArrayOutputStream();
        outer.write("openssh-key-v1\0".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        wstr(outer, utf8("none")); wstr(outer, utf8("none")); wstr(outer, new byte[0]);
        wu32(outer, 1); wstr(outer, pubBlob); wstr(outer, padded);
        String b64 = java.util.Base64.getMimeEncoder(70, new byte[]{'\n'}).encodeToString(outer.toByteArray());
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + b64 + "\n-----END OPENSSH PRIVATE KEY-----\n";
    }

    // leitor de campos SSH (uint32-len ‖ bytes)
    static class Reader {
        final byte[] b; int p;
        Reader(byte[] b) { this.b = b; this.p = 0; }
        void skip(int n) { p += n; }
        int u32() { int v = ((b[p]&0xFF)<<24)|((b[p+1]&0xFF)<<16)|((b[p+2]&0xFF)<<8)|(b[p+3]&0xFF); p += 4; return v; }
        byte[] bytes() { int n = u32(); byte[] r = java.util.Arrays.copyOfRange(b, p, p + n); p += n; return r; }
        String str() { return new String(bytes(), java.nio.charset.StandardCharsets.UTF_8); }
    }
}