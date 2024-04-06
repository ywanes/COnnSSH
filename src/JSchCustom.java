
class JSchCustom {
    void ssh(String arg0, String password, int port) {
        Ssh.custom(arg0, password, port);
    }
}

class Ssh {
    public static void custom(String arg0, String password, int port) {
        Channel channel = null;
        try {
            JSch jsch = new JSch();
            if ( !arg0.contains("@") ) {
                System.err.println("usage: y ssh user,pass@remotehost");
                System.exit(-1);
            }
            String user = arg0.split("@")[0];
            String host = arg0.split("@")[1];
            Session session = jsch.getSession(user, host, port);
            session.setPassword(password);
            session.connect(30000);
            channel = session.openChannel("shell");
            channel.setInputStream(System.in);
            channel.setOutputStream(System.out);
            channel.connect(3 * 1000);
        } catch (Exception e) {
            System.out.println(e);
        }
        while (channel != null && !channel.isEOF()) {}
    }
}



