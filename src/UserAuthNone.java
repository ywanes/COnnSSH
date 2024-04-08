class UserAuthNone extends UserAuth{
  private static final int SSH_MSG_SERVICE_ACCEPT=                  6;
  private String methods=null;
  public boolean start(Session session) throws Exception{
    super.start(session);    
    packet.reset();
    buf.putByte((byte)Session.SSH_MSG_SERVICE_REQUEST);
    buf.putString(str2byte("ssh-userauth"));
    session.write(packet);    
    session.read(buf);
    return false;
  }
  String getMethods(){
    return methods;
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
