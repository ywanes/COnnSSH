import java.io.*;

public class TesteSSH{
    public static void main(String[] args) {
        String _jar="java -jar \"D:\\DADOSSSSS\\Desktopsss\\desktop\\COnnSSH\\COnnSSH\\dist\\COnnSSH.jar\"";
        if ( args.length == 1 && args[1].equals("2") ){
            _jar="java -jar \"D:\\DADOSSSSS\\Desktopsss\\desktop\\COnnSSH\\COnnSSH\\dist\\COnnSSH.jar\" admin,admin123@localhost";
        }
        String commands = """
            c:
            cd C:\\
            [JAR]
            c:
            cd C:\\tmp\\tmp
            y help | y grep onlyDiff
            exit
            echo %CD%
            """.replace("[JAR]",_jar);

        StringBuilder fullOutput = new StringBuilder();
        
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd.exe");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Thread para capturar o output
            Thread outputReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        synchronized (fullOutput) {
                            fullOutput.append(line).append(System.lineSeparator());
                        }
                    }
                } catch (IOException e) {
                    // Fim do stream
                }
            });
            outputReader.start();

            // Envio dos comandos
            try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(process.getOutputStream()))) {
                for (String cmd : commands.split("\n")) {
                    writer.println(cmd);
                    writer.flush();
                    Thread.sleep(500); // Pausa para garantir o sequenciamento no console
                }
            }

            process.waitFor();
            outputReader.join();

            // Validação das linhas na ordem específica
            String result = fullOutput.toString();
            String[] expectedOrder = {
                "C:\\>",
                "YWANES-PC",
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

    private static boolean checkOrder(String text, String[] sequences) {
        int lastIndex = -1;
        for (String seq : sequences) {
            int currentIndex = text.indexOf(seq, lastIndex + 1);
            if (currentIndex == -1) {
                System.out.println("FALHA, nao foi possivel encontrar a palavra " + seq + "\n");
                return false; // Sequência não encontrada ou fora de ordem
            }
            lastIndex = currentIndex;
        }
        return true;
    }
}