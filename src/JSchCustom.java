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
import javax.swing.ProgressMonitor;

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
    void sftp(String arg0, String password, int port) {
        Sftp.custom(arg0, password, port);
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
class Sftp {
    public static void custom(String arg0, String password, int port) {
        try {
            JSch jsch = new JSch();
            if ( !arg0.contains("@") ){
                System.err.println("usage: y sftp user,pass@remotehost");
                System.exit(-1);
            }
            String user = arg0.split("@")[0];
            String host = arg0.split("@")[1];
            Session session = jsch.getSession(user, host, port);
            UserInfo ui = new MyUserInfo(password);
            session.setUserInfo(ui);
            session.connect();
            Channel channel = session.openChannel("sftp");
            channel.connect();
            ChannelSftp c = (ChannelSftp) channel;
            java.io.InputStream in = System.in;
            java.io.PrintStream out = System.out;
            java.util.Vector cmds = new java.util.Vector();
            byte[] buf = new byte[1024];
            int i;
            String str;
            int level = 0;
            while (true) {
                out.print("sftp> ");
                cmds.removeAllElements();
                i = in .read(buf, 0, 1024);
                if (i <= 0) break;
                i--;
                if (i > 0 && buf[i - 1] == 0x0d) i--;
                int s = 0;
                for (int ii = 0; ii < i; ii++) {
                    if (buf[ii] == ' ') {
                        if (ii - s > 0) {
                            cmds.addElement(new String(buf, s, ii - s));
                        }
                        while (ii < i) {
                            if (buf[ii] != ' ') break;
                            ii++;
                        }
                        s = ii;
                    }
                }
                if (s < i) {
                    cmds.addElement(new String(buf, s, i - s));
                }
                if (cmds.size() == 0) continue;
                String cmd = (String) cmds.elementAt(0);
                if (cmd.equals("quit")) {
                    c.quit();
                    break;
                }
                if (cmd.equals("exit")) {
                    c.exit();
                    break;
                }
                if (cmd.equals("rekey")) {
                    session.rekey();
                    continue;
                }
                if (cmd.equals("compression")) {
                    if (cmds.size() < 2) {
                        out.println("compression level: " + level);
                        continue;
                    }
                    try {
                        level = Integer.parseInt((String) cmds.elementAt(1));
                        if (level == 0) {
                            session.setConfig("compression.s2c", "none");
                            session.setConfig("compression.c2s", "none");
                        } else {
                            session.setConfig("compression.s2c", "zlib@openssh.com,zlib,none");
                            session.setConfig("compression.c2s", "zlib@openssh.com,zlib,none");
                        }
                    } catch (Exception e) {}
                    session.rekey();
                    continue;
                }
                if (cmd.equals("cd") || cmd.equals("lcd")) {
                    if (cmds.size() < 2) continue;
                    String path = (String) cmds.elementAt(1);
                    try {
                        if (cmd.equals("cd")) c.cd(path);
                        else c.lcd(path);
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("rm") || cmd.equals("rmdir") || cmd.equals("mkdir")) {
                    if (cmds.size() < 2) continue;
                    String path = (String) cmds.elementAt(1);
                    try {
                        if (cmd.equals("rm")) c.rm(path);
                        else if (cmd.equals("rmdir")) c.rmdir(path);
                        else c.mkdir(path);
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("chgrp") || cmd.equals("chown") || cmd.equals("chmod")) {
                    if (cmds.size() != 3) continue;
                    String path = (String) cmds.elementAt(2);
                    int foo = 0;
                    if (cmd.equals("chmod")) {
                        byte[] bar = ((String) cmds.elementAt(1)).getBytes();
                        int k;
                        for (int j = 0; j < bar.length; j++) {
                            k = bar[j];
                            if (k < '0' || k > '7') {
                                foo = -1;
                                break;
                            }
                            foo <<= 3;
                            foo |= (k - '0');
                        }
                        if (foo == -1) continue;
                    } else {
                        try {
                            foo = Integer.parseInt((String) cmds.elementAt(1));
                        } catch (Exception e) {
                            continue;
                        }
                    }
                    try {
                        if (cmd.equals("chgrp")) {
                            c.chgrp(foo, path);
                        } else if (cmd.equals("chown")) {
                            c.chown(foo, path);
                        } else if (cmd.equals("chmod")) {
                            c.chmod(foo, path);
                        }
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("pwd") || cmd.equals("lpwd")) {
                    str = (cmd.equals("pwd") ? "Remote" : "Local");
                    str += " working directory: ";
                    if (cmd.equals("pwd")) str += c.pwd();
                    else str += c.lpwd();
                    out.println(str);
                    continue;
                }
                if (cmd.equals("ls") || cmd.equals("dir")) {
                    String path = ".";
                    if (cmds.size() == 2) path = (String) cmds.elementAt(1);
                    try {
                        java.util.Vector vv = c.ls(path);
                        if (vv != null) {
                            for (int ii = 0; ii < vv.size(); ii++) {
                                Object obj = vv.elementAt(ii);
                                if (obj instanceof ChannelSftp.LsEntry) {
                                    out.println(((ChannelSftp.LsEntry) obj).getLongname());
                                }
                            }
                        }
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("lls") || cmd.equals("ldir")) {
                    String path = ".";
                    if (cmds.size() == 2) path = (String) cmds.elementAt(1);
                    try {
                        java.io.File file = new java.io.File(path);
                        if (!file.exists()) {
                            out.println(path + ": No such file or directory");
                            continue;
                        }
                        if (file.isDirectory()) {
                            String[] list = file.list();
                            for (int ii = 0; ii < list.length; ii++) {
                                out.println(list[ii]);
                            }
                            continue;
                        }
                        out.println(path);
                    } catch (Exception e) {
                        System.out.println(e);
                    }
                    continue;
                }
                if (cmd.equals("get") || cmd.equals("get-resume") || cmd.equals("get-append") || cmd.equals("put") || cmd.equals("put-resume") || cmd.equals("put-append")) {
                    if (cmds.size() != 2 && cmds.size() != 3) continue;
                    String p1 = (String) cmds.elementAt(1);
                    String p2 = ".";
                    if (cmds.size() == 3) p2 = (String) cmds.elementAt(2);
                    try {
                        SftpProgressMonitor monitor = new MyProgressMonitor();
                        if (cmd.startsWith("get")) {
                            int mode = ChannelSftp.OVERWRITE;
                            if (cmd.equals("get-resume")) {
                                mode = ChannelSftp.RESUME;
                            } else if (cmd.equals("get-append")) {
                                mode = ChannelSftp.APPEND;
                            }
                            c.get(p1, p2, monitor, mode);
                        } else {
                            int mode = ChannelSftp.OVERWRITE;
                            if (cmd.equals("put-resume")) {
                                mode = ChannelSftp.RESUME;
                            } else if (cmd.equals("put-append")) {
                                mode = ChannelSftp.APPEND;
                            }
                            c.put(p1, p2, monitor, mode);
                        }
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("ln") || cmd.equals("symlink") || cmd.equals("rename") || cmd.equals("hardlink")) {
                    if (cmds.size() != 3) continue;
                    String p1 = (String) cmds.elementAt(1);
                    String p2 = (String) cmds.elementAt(2);
                    try {
                        if (cmd.equals("hardlink")) {
                            c.hardlink(p1, p2);
                        } else if (cmd.equals("rename")) c.rename(p1, p2);
                        else c.symlink(p1, p2);
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("df")) {
                    if (cmds.size() > 2) continue;
                    String p1 = cmds.size() == 1 ? "." : (String) cmds.elementAt(1);
                    SftpStatVFS stat = c.statVFS(p1);
                    long size = stat.getSize();
                    long used = stat.getUsed();
                    long avail = stat.getAvailForNonRoot();
                    long root_avail = stat.getAvail();
                    long capacity = stat.getCapacity();
                    System.out.println("Size: " + size);
                    System.out.println("Used: " + used);
                    System.out.println("Avail: " + avail);
                    System.out.println("(root): " + root_avail);
                    System.out.println("%Capacity: " + capacity);
                    continue;
                }
                if (cmd.equals("stat") || cmd.equals("lstat")) {
                    if (cmds.size() != 2) continue;
                    String p1 = (String) cmds.elementAt(1);
                    SftpATTRS attrs = null;
                    try {
                        if (cmd.equals("stat")) attrs = c.stat(p1);
                        else attrs = c.lstat(p1);
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    if (attrs != null) {
                        out.println(attrs);
                    } else {}
                    continue;
                }
                if (cmd.equals("readlink")) {
                    if (cmds.size() != 2) continue;
                    String p1 = (String) cmds.elementAt(1);
                    String filename = null;
                    try {
                        filename = c.readlink(p1);
                        out.println(filename);
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("realpath")) {
                    if (cmds.size() != 2) continue;
                    String p1 = (String) cmds.elementAt(1);
                    String filename = null;
                    try {
                        filename = c.realpath(p1);
                        out.println(filename);
                    } catch (SftpException e) {
                        System.out.println(e.toString());
                    }
                    continue;
                }
                if (cmd.equals("version")) {
                    out.println("SFTP protocol version " + c.version());
                    continue;
                }
                if (cmd.equals("help") || cmd.equals("?")) {
                    out.println(help);
                    continue;
                }
                out.println("unimplemented command: " + cmd);
            }
            session.disconnect();
        } catch (Exception e) {
            System.out.println(e);
        }
        System.exit(0);
    }
    private static String help = 
            "      Available commands:\n" + 
            "      * means unimplemented command.\n" + 
            "cd path                       Change remote directory to 'path'\n" + 
            "lcd path                      Change local directory to 'path'\n" + 
            "chgrp grp path                Change group of file 'path' to 'grp'\n" + 
            "chmod mode path               Change permissions of file 'path' to 'mode'\n" + 
            "chown own path                Change owner of file 'path' to 'own'\n" + 
            "df [path]                     Display statistics for current directory or\n" + 
            "                              filesystem containing 'path'\n" + 
            "help                          Display this help text\n" + 
            "get remote-path [local-path]  Download file\n" + 
            "get-resume remote-path [local-path]  Resume to download file.\n" + 
            "get-append remote-path [local-path]  Append remote file to local file\n" + 
            "hardlink oldpath newpath      Hardlink remote file\n" + 
            "*lls [ls-options [path]]      Display local directory listing\n" + 
            "ln oldpath newpath            Symlink remote file\n" + 
            "*lmkdir path                  Create local directory\n" + 
            "lpwd                          Print local working directory\n" + 
            "ls [path]                     Display remote directory listing\n" + 
            "*lumask umask                 Set local umask to 'umask'\n" + 
            "mkdir path                    Create remote directory\n" + 
            "put local-path [remote-path]  Upload file\n" + 
            "put-resume local-path [remote-path]  Resume to upload file\n" + 
            "put-append local-path [remote-path]  Append local file to remote file.\n" + 
            "pwd                           Display remote working directory\n" + 
            "stat path                     Display info about path\n" + 
            "exit                          Quit sftp\n" + 
            "quit                          Quit sftp\n" + 
            "rename oldpath newpath        Rename remote file\n" + 
            "rmdir path                    Remove remote directory\n" + 
            "rm path                       Delete remote file\n" + 
            "symlink oldpath newpath       Symlink remote file\n" + 
            "readlink path                 Check the target of a symbolic link\n" + 
            "realpath path                 Canonicalize the path\n" + 
            "rekey                         Key re-exchanging\n" + 
            "compression level             Packet compression will be enabled\n" + 
            "version                       Show SFTP version\n" + 
            "?                             Synonym for help";
    
    public static class MyProgressMonitor implements SftpProgressMonitor {
        ProgressMonitor monitor;
        long count = 0;
        long max = 0;
        public void init(int op, String src, String dest, long max) {
            this.max = max;
            monitor = new ProgressMonitor(null, ((op == SftpProgressMonitor.PUT) ? "put" : "get") + ": " + src, "", 0, (int) max);
            count = 0;
            percent = -1;
            monitor.setProgress((int) this.count);
            monitor.setMillisToDecideToPopup(1000);
        }
        private long percent = -1;
        public boolean count(long count) {
            this.count += count;
            if (percent >= this.count * 100 / max) {
                return true;
            }
            percent = this.count * 100 / max;
            monitor.setNote("Completed " + this.count + "(" + percent + "%) out of " + max + ".");
            monitor.setProgress((int) this.count);
            return !(monitor.isCanceled());
        }
        public void end() {
            monitor.close();
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
            System.err.println("not implementation! cod 7");
            System.exit(1);
        }
        final GridBagConstraints gbc = new GridBagConstraints(0, 0, 1, 1, 1, 1, GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0);
        private Container panel;
        public String[] promptKeyboardInteractive(String destination, String name, String instruction, String[] prompt, boolean[] echo) {
            return null;
        }
    }
}
