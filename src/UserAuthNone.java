class UserAuthNone extends UserAuth{
  private static final int SSH_MSG_SERVICE_ACCEPT=                  6;
  private String methods=null;
  public boolean start(Session session) throws Exception{
    super.start(session);
    packet.reset();
    buf.putByte((byte)Session.SSH_MSG_SERVICE_REQUEST);
    buf.putString(str2byte("ssh-userauth"));
    session.write(packet);
    buf=session.read(buf);
    int command=buf.getCommand();
    boolean result=(command==SSH_MSG_SERVICE_ACCEPT);
    if(!result)
      return false;
    byte[] _username=null;
    _username=str2byte(username);
    packet.reset();
    buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
    buf.putString(_username);
    buf.putString(str2byte("ssh-connection"));
    buf.putString(str2byte("none"));
    session.write(packet);
    loop:
    while(true){
      buf=session.read(buf);
      command=buf.getCommand()&0xff;
      if(command==SSH_MSG_USERAUTH_SUCCESS)
	return true;
      if(command==SSH_MSG_USERAUTH_BANNER){
	buf.getInt(); buf.getByte(); buf.getByte();
	byte[] _message=buf.getString();
	byte[] lang=buf.getString();
	String message=byte2str(_message);
	continue loop;
      }
      if(command==SSH_MSG_USERAUTH_FAILURE){
	buf.getInt(); buf.getByte(); buf.getByte(); 
	byte[] foo=buf.getString();
	int partial_success=buf.getByte();
	methods=byte2str(foo);
        break;
      }
      throw new JSchException("USERAUTH fail ("+command+")");
    }
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
