import java.io.InputStream;
public class JSch{  
  private KnownHosts known_hosts=null;
  public Session getSession(String host) throws JSchException {
    return getSession(null, host, 22);
  }
  public Session getSession(String username, String host) throws JSchException {
    return getSession(username, host, 22);
  }
  public Session getSession(String username, String host, int port) throws JSchException {
    if(host==null)
      throw new JSchException("host must not be null.");
    Session s = new Session(this, username, host, port); 
    return s;
  }
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
}
