public class TesteSSH{
    public static void main(String[] args){
        // teste com o clientmini
        // compilar jar e depois rodar abaixo
        // java D:\DADOSSSSS\Desktopsss\desktop\COnnSSH\COnnSSH\src\TesteSSH.java
        String _jar="java -jar \"D:\\DADOSSSSS\\Desktopsss\\desktop\\COnnSSH\\COnnSSH\\dist\\COnnSSH.jar\"";
        if ( args.length == 1 && args[0].equals("2") ){
            // teste com o servermini e clientmini
            // compilar jar e depois rodar abaixo
            // run SSHServerMini.java no netbeans
            // java D:\DADOSSSSS\Desktopsss\desktop\COnnSSH\COnnSSH\src\TesteSSH.java 2
            _jar="java -jar \"D:\\DADOSSSSS\\Desktopsss\\desktop\\COnnSSH\\COnnSSH\\dist\\COnnSSH.jar\" admin,admin123@localhost";
        }
        String commands = """
            c:
            cd C:\\
            [JAR]
            c:
            cd C:\\tmp\\tmp
            cd C:\\windows              
            y help | y grep onlyDiff
            exit
            echo %CD%
            """.replace("[JAR]",_jar);
        StringBuilder fullOutput = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd.exe");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            Thread outputReader = new Thread(() -> {
                try (java.io.Reader reader = new java.io.InputStreamReader(process.getInputStream())) {
                    char[] buf = new char[4096];
                    int n;
                    while ((n = reader.read(buf)) != -1) {
                        synchronized (fullOutput) {
                            fullOutput.append(buf, 0, n);
                        }
                    }
                } catch (Exception e){}
            });
            outputReader.start();
            try (java.io.PrintWriter writer = new java.io.PrintWriter(new java.io.OutputStreamWriter(process.getOutputStream()))) {
                for (String cmd : commands.split("\n")) {
                    int posAntes;
                    synchronized (fullOutput) { posAntes = fullOutput.length(); }
                    writer.println(cmd);
                    writer.flush();
                    aguardarPrompt(fullOutput, posAntes, 30_000);
                }
            }
            process.waitFor();
            outputReader.join();
            String result = fullOutput.toString();
            String[] expectedOrder = {
                "C:\\>",
                "Microsoft Corporation. Todos os direitos reservados",
                "C:\\tmp\\tmp>",
                "-onlyDiff",
                "C:\\>"
            };
            if (checkOrder(result, expectedOrder)) {
                System.out.println("OK");
            } else {
                System.out.println("--- CONTEÚDO INTEIRO ---");
                System.out.println(result);
                System.out.println("------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static void aguardarPrompt(StringBuilder out, int posAntes, long timeoutMs) throws InterruptedException {
        long inicio = System.currentTimeMillis();
        int tamanhoAnterior = posAntes;
        long ultimaMudanca = System.currentTimeMillis();
        while (System.currentTimeMillis() - inicio < timeoutMs) {
            Thread.sleep(100);
            int tamanho;
            boolean terminaComPrompt;
            synchronized (out) {
                tamanho = out.length();
                String fim = out.substring(Math.max(0, tamanho - 2), tamanho).trim();
                terminaComPrompt = fim.endsWith(">");
            }
            if (tamanho != tamanhoAnterior) {
                tamanhoAnterior = tamanho;
                ultimaMudanca = System.currentTimeMillis();
            } else if (tamanho > posAntes && terminaComPrompt
                       && System.currentTimeMillis() - ultimaMudanca >= 300) {
                return;
            }
        }
    }
    private static boolean checkOrder(String text, String[] sequences) {
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