public class UserAuthPassword extends UserAuth{
    
  private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ=60;
  
  public void start(Session session) throws Exception{
    super.start(session);
    if(session.password == null)
      throw new Exception("Error AuthCancel - not found password");      
    if(session.auth_failures >= session.max_auth_tries)
      return;
    packet.reset();
    buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
    buf.putString(str2byte(username));
    buf.putString(str2byte("ssh-connection"));
    buf.putString(str2byte("password"));
    buf.putByte((byte)0);
    buf.putString(session.password);
    session.write(packet);
    buf=session.read(buf);
    int command=buf.getCommand()&0xff;
    if(command==SSH_MSG_USERAUTH_SUCCESS)
      return;
    if(command==SSH_MSG_USERAUTH_BANNER)
      throw new Exception("USERAUTH_BANNER");
    if(command==SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
      throw new Exception("Stop - USERAUTH_PASSWD_CHANGEREQ");
    if(command==SSH_MSG_USERAUTH_FAILURE)
      throw new Exception("UserAuth Fail!");
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
