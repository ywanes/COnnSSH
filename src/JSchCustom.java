import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

class JSchCustom {
    void scpFrom(String[] args, String password, int port) {
        ScpFrom.custom(args, password, port);
    }
    void scpTo(String[] args, String password, int port) {
        ScpTo.custom(args, password, port);
    }
    void execSsh(String[] args, String password, int port) {
        ExecSsh.custom(args, password, port);
    }
    void ssh(String arg0, String password, int port) {
        Ssh.custom(arg0, password, port);
    }
}

class ScpFrom {
    public static void custom(String[] arg, String password, int port) {
        if (arg.length != 2 || !arg[0].contains("@")) {
            System.err.println("usage: y scp user,pass@remotehost:file1 file2");
            System.exit(-1);
        }
        FileOutputStream fos = null;
        try {
            String user = arg[0].substring(0, arg[0].indexOf('@'));
            arg[0] = arg[0].substring(arg[0].indexOf('@') + 1);
            String host = arg[0].substring(0, arg[0].indexOf(':'));
            String rfile = arg[0].substring(arg[0].indexOf(':') + 1);
            String lfile = arg[1];
            String prefix = null;
            if (new File(lfile).isDirectory()) {
                prefix = lfile + File.separator;
            }
            JSch jsch = new JSch();
            Session session = jsch.getSession(user, host, port);
            UserInfo ui = new MyUserInfo(password);
            session.setUserInfo(ui);
            session.connect();
            String command = "scp -f " + rfile;
            Channel channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(command);
            OutputStream out = channel.getOutputStream();
            InputStream in = channel.getInputStream();
            channel.connect();
            byte[] buf = new byte[1024];
            buf[0] = 0;
            out.write(buf, 0, 1);
            out.flush();
            while (true) {
                int c = checkAck( in );
                if (c != 'C') {
                    break;
                } in .read(buf, 0, 5);
                long filesize = 0L;
                while (true) {
                    if ( in .read(buf, 0, 1) < 0) {
                        break;
                    }
                    if (buf[0] == ' ') break;
                    filesize = filesize * 10L + (long)(buf[0] - '0');
                }
                String file = null;
                for (int i = 0;; i++) { in .read(buf, i, 1);
                    if (buf[i] == (byte) 0x0a) {
                        file = new String(buf, 0, i);
                        break;
                    }
                }
                buf[0] = 0;
                out.write(buf, 0, 1);
                out.flush();
                fos = new FileOutputStream(prefix == null ? lfile : prefix + file);
                int foo;
                while (true) {
                    if (buf.length < filesize) foo = buf.length;
                    else foo = (int) filesize;
                    foo = in .read(buf, 0, foo);
                    if (foo < 0) {
                        break;
                    }
                    fos.write(buf, 0, foo);
                    filesize -= foo;
                    if (filesize == 0L) break;
                }
                fos.close();
                fos = null;
                if (checkAck( in ) != 0) {
                    System.exit(0);
                }
                buf[0] = 0;
                out.write(buf, 0, 1);
                out.flush();
            }
            session.disconnect();
            System.exit(0);
        } catch (Exception e) {
            System.out.println(e);
            try {
                if (fos != null) fos.close();
            } catch (Exception ee) {}
        }
    }
    static int checkAck(InputStream in ) throws IOException {
        int b = in .read();
        if (b == 0) return b;
        if (b == -1) return b;
        if (b == 1 || b == 2) {
            StringBuffer sb = new StringBuffer();
            int c;
            do {
                c = in .read();
                sb.append((char) c);
            } while (c != '\n');
            if (b == 1) {
                System.out.print(sb.toString());
            }
            if (b == 2) {
                System.out.print(sb.toString());
            }
        }
        return b;
    }
    public static class MyUserInfo implements UserInfo, UIKeyboardInteractive {
        String passwd;
        String password;
        private MyUserInfo(String password) {
            this.password = password;
        }
        public String getPassword() {
            return passwd;
        }
        public boolean promptYesNo(String str) {
            return true;
        }
        JTextField passwordField = (JTextField) new JPasswordField(20);
        public String getPassphrase() {
            return null;
        }
        public boolean promptPassphrase(String message) {
            return true;
        }
        public boolean promptPassword(String message) {
            passwd = password;
            return true;
        }
        public void showMessage(String message) {
            System.err.println("nao implementado! cod 1");
            System.exit(1);
        }
        final GridBagConstraints gbc = new GridBagConstraints(0, 0, 1, 1, 1, 1, GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0);
        private Container panel;
        public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
            return null;
        }
    }
}
class ScpTo {
    public static void custom(String[] arg, String password, int port) {
        if (arg.length != 2 || !arg[1].contains("@")) {
            System.err.println("usage: y scp file1 user,pass@remotehost:file2");
            System.exit(-1);
        }
        FileInputStream fis = null;
        try {
            String lfile = arg[0];
            String user = arg[1].substring(0, arg[1].indexOf('@'));
            arg[1] = arg[1].substring(arg[1].indexOf('@') + 1);
            String host = arg[1].substring(0, arg[1].indexOf(':'));
            String rfile = arg[1].substring(arg[1].indexOf(':') + 1);
            JSch jsch = new JSch();
            Session session = jsch.getSession(user, host, 22);
            UserInfo ui = new MyUserInfo(password);
            session.setUserInfo(ui);
            session.connect();
            boolean ptimestamp = true;
            String command = "scp " + (ptimestamp ? "-p" : "") + " -t " + rfile;
            Channel channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(command);
            OutputStream out = channel.getOutputStream();
            InputStream in = channel.getInputStream();
            channel.connect();
            if (checkAck( in ) != 0) {
                System.exit(0);
            }
            File _lfile = new File(lfile);
            if (ptimestamp) {
                command = "T" + (_lfile.lastModified() / 1000) + " 0";
                command += (" " + (_lfile.lastModified() / 1000) + " 0\n");
                out.write(command.getBytes());
                out.flush();
                if (checkAck( in ) != 0) {
                    System.exit(0);
                }
            }
            long filesize = _lfile.length();
            command = "C0644 " + filesize + " ";
            if (lfile.lastIndexOf('/') > 0) {
                command += lfile.substring(lfile.lastIndexOf('/') + 1);
            } else {
                command += lfile;
            }
            command += "\n";
            out.write(command.getBytes());
            out.flush();
            if (checkAck( in ) != 0) {
                System.exit(0);
            }
            fis = new FileInputStream(lfile);
            byte[] buf = new byte[1024];
            while (true) {
                int len = fis.read(buf, 0, buf.length);
                if (len <= 0) break;
                out.write(buf, 0, len);
            }
            fis.close();
            fis = null;
            buf[0] = 0;
            out.write(buf, 0, 1);
            out.flush();
            if (checkAck( in ) != 0) {
                System.exit(0);
            }
            out.close();
            channel.disconnect();
            session.disconnect();
            System.exit(0);
        } catch (Exception e) {
            System.out.println(e);
            try {
                if (fis != null) fis.close();
            } catch (Exception ee) {}
        }
    }
    static int checkAck(InputStream in ) throws IOException {
        int b = in .read();
        if (b == 0) return b;
        if (b == -1) return b;
        if (b == 1 || b == 2) {
            StringBuffer sb = new StringBuffer();
            int c;
            do {
                c = in .read();
                sb.append((char) c);
            } while (c != '\n');
            if (b == 1) {
                System.out.print(sb.toString());
            }
            if (b == 2) {
                System.out.print(sb.toString());
            }
        }
        return b;
    }
    public static class MyUserInfo implements UserInfo, UIKeyboardInteractive {
        String passwd;
        String password;
        private MyUserInfo(String password) {
            this.password = password;
        }
        public String getPassword() {
            return passwd;
        }
        public boolean promptYesNo(String str) {
            return true;
        }
        JTextField passwordField = (JTextField) new JPasswordField(20);
        public String getPassphrase() {
            return null;
        }
        public boolean promptPassphrase(String message) {
            return true;
        }
        public boolean promptPassword(String message) {
            passwd = password;
            return true;
        }
        public void showMessage(String message) {
            System.err.println("nao implementado! cod 3");
            System.exit(1);
        }
        final GridBagConstraints gbc = new GridBagConstraints(0, 0, 1, 1, 1, 1, GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0);
        private Container panel;
        public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
            return null;
        }
    }
}
class ExecSsh {
    public static void custom(String[] arg, String password, int port) {
        try {
            JSch jsch = new JSch();
            if (arg.length != 2 || !arg[0].contains("@")) {
                System.err.println("usage: y execSsh user,pass@remotehost command");
                System.exit(-1);
            }
            String user = arg[0].split("@")[0];
            String host = arg[0].split("@")[1];
            String command = arg[1];
            Session session = jsch.getSession(user, host, port);
            UserInfo ui = new MyUserInfo(password);
            session.setUserInfo(ui);
            session.connect();
            Channel channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(command);
            channel.setInputStream(null);
            ((ChannelExec) channel).setErrStream(System.err);
            InputStream in = channel.getInputStream();
            channel.connect();
            byte[] tmp = new byte[1024];
            while (true) {
                while ( in .available() > 0) {
                    int i = in .read(tmp, 0, 1024);
                    if (i < 0) break;
                    System.out.print(new String(tmp, 0, i));
                }
                if (channel.isClosed()) {
                    if ( in .available() > 0) continue;
                    break;
                }
                try {
                    Thread.sleep(1000);
                } catch (Exception ee) {}
            }
            channel.disconnect();
            session.disconnect();
        } catch (Exception e) {
            System.out.println(e);
        }
    }
    public static class MyUserInfo implements UserInfo, UIKeyboardInteractive {
        String passwd;
        String password;
        private MyUserInfo(String password) {
            this.password = password;
        }
        public String getPassword() {
            return passwd;
        }
        public boolean promptYesNo(String str) {
            return true;
        }
        JTextField passwordField = (JTextField) new JPasswordField(20);
        public String getPassphrase() {
            return null;
        }
        public boolean promptPassphrase(String message) {
            return true;
        }
        public boolean promptPassword(String message) {
            passwd = password;
            return true;
        }
        public void showMessage(String message) {
            System.err.println("nao implementado! cod 5");
            System.exit(1);
        }
        final GridBagConstraints gbc = new GridBagConstraints(0, 0, 1, 1, 1, 1, GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0);
        private Container panel;
        public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
            return null;
        }
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
            UserInfo ui = new MyUserInfo() {
                public void showMessage(String message) {
                    JOptionPane.showMessageDialog(null, message);
                }
                public boolean promptYesNo(String message) {
                    return true;
                }
            };
            session.setUserInfo(ui);
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
    public static abstract class MyUserInfo implements UserInfo, UIKeyboardInteractive {
        public String getPassword() {
            return null;
        }
        public boolean promptYesNo(String str) {
            return false;
        }
        public String getPassphrase() {
            return null;
        }
        public boolean promptPassphrase(String message) {
            return false;
        }
        public boolean promptPassword(String message) {
            return false;
        }
        public void showMessage(String message) {}
        public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
            return null;
        }
    }
}



