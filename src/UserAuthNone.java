class UserAuthNone extends UserAuth{
  public void start(Session session) throws Exception{
    super.start(session);    
    packet.reset();
    buf.putByte((byte)Session.SSH_MSG_SERVICE_REQUEST);
    buf.putString(str2byte("ssh-userauth"));
    session.write(packet);    
    session.read(buf);
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
