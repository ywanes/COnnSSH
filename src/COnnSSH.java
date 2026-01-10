public class COnnSSH{
    public static void main(String[] args){
        new COnnSSH().go(args);
    }
    public void go(String [] args){
        // java -jar "D:\DADOSSSSS\Desktopsss\desktop\COnnSSH\COnnSSH\dist\COnnSSH.jar"
        // ssh -o HostKeyAlgorithms=ecdsa-sha2-nistp256 ywanes@192.168.0.100
        // cd C:\tmp\tmp_teste && xcopy "D:\DADOSSSSS\Desktopsss\desktop\COnnSSH\COnnSSH\src" . /h /i /c /k /e /r /y && y cls && javac COnnSSH.java && native-image COnnSSH --no-fallback && connssh
        String access = "ywanes@192.168.0.100";
        if ( args.length > 0 )
            access=args[0];
        else{
            java.io.File f = new java.io.File("D:\\DADOSSSSS\\Desktopsss\\desktop\\COnnSSH\\key.txt");
            if ( f.exists() && f.isFile() )
                access = lendo_arquivo_ofuscado(f.getAbsolutePath()) + "@192.168.0.100";
        }
        ssh(new String[] {
            "ssh",
            access
        });
    }
    private void ssh(String[] args) {
        // créditos
        // https://github.com/is/jsch/tree/master/examples
        //int port = 22;
        int port = 2223; // java -jar "D:\DADOSSSSS\Desktopsss\desktop\COnnSSH\COnnSSH\dist\COnnSSH.jar" admin,admin123@localhost
        if (args.length != 2 && args.length != 3) {
            comando_invalido(args);
            return;
        }
        if (!args[1].contains("@")) {
            comando_invalido(args);
            return;
        }
        if (args.length == 3) {
            try {
                port = Integer.parseInt(args[2]);
            } catch (Exception e) {
                comando_invalido(args);
                return;
            }
        }
        String[] senha = new String[]{""};
        tryTakePassword(args, senha);
        ssh(args[1], senha[0], port);
        System.exit(0);
    }

    void ssh(String arg0, String password, int port) {
        if (!arg0.contains("@"))
            System.err.println("Error parameter.. example:user,pass@remotehost");
        String user = arg0.split("@")[0];
        String host = arg0.split("@")[1];  
        try{
            new SSHClientMini(host, user, port, password);                
        }catch(Exception e){
            System.err.println(e.toString().contains("UserAuth Fail")?"UserAuth Fail!!":e.toString());                
        }            
    }

    public void comando_invalido(String[] args) {
        //Comando inválido
        System.err.print("Invalid command: [y");
        for (int i = 0; i < args.length; i++)
            System.err.print(" " + args[i]);
        System.err.println("]");
    }

    public void tryTakePassword(String[] args, String[] senha) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].contains("@")) {
                if (args[i].startsWith("@") || args[i].endsWith("@")) {
                    System.out.println("Error command");
                    System.exit(1);
                }
                if (args[i].contains(",")) {
                    int p_virgula = args[i].indexOf(",");
                    int p_ultima_arroba = args[i].lastIndexOf("@");
                    String user = args[i].substring(0, p_virgula);
                    String host = args[i].substring(p_ultima_arroba + 1, args[i].length());
                    senha[0] = args[i].substring(p_virgula + 1, p_ultima_arroba);
                    args[i] = user + "@" + host;
                } else {
                    java.io.Console console = System.console();
                    if (console == null) {
                        System.out.println("Error, input not suport in netbeans...");
                        System.exit(1);
                    }

                    String user_server_print = args[i];
                    if (user_server_print.contains(":"))
                        user_server_print = user_server_print.split(":")[0];

                    String password = null;
                    char[] passChar = System.console().readPassword(user_server_print + "'s password: ");
                    if (passChar != null)
                        password = new String(passChar);

                    if (password == null || password.trim().equals("")) {
                        System.out.println("Error, not input found");
                        System.exit(1);
                    }
                    senha[0] = password;
                }
                break;
            }
        }
    }
    public String lendo_arquivo_ofuscado(String caminho) {
        String result = "";
        try {            
            java.util.List<String> lines=java.nio.file.Files.readAllLines(java.nio.file.Paths.get(caminho), java.nio.charset.StandardCharsets.UTF_8);            
            for ( int i=0;i<lines.size();i++ )
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
}
