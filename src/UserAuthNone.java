class UserAuthNone extends UserAuth{
  private static final int SSH_MSG_SERVICE_ACCEPT=                  6;
  private String methods=null;
  public boolean start(Session session) throws Exception{
    super.start(session);
    packet.reset();
    buf.putByte((byte)Session.SSH_MSG_SERVICE_REQUEST);
    buf.putString(Util.str2byte("ssh-userauth"));
    session.write(packet);
    if(JSch.getLogger().isEnabled(Logger.INFO)){
      JSch.getLogger().log(Logger.INFO, 
                           "SSH_MSG_SERVICE_REQUEST sent");
    }

    buf=session.read(buf);
    int command=buf.getCommand();

    boolean result=(command==SSH_MSG_SERVICE_ACCEPT);

    if(JSch.getLogger().isEnabled(Logger.INFO)){
      JSch.getLogger().log(Logger.INFO, 
                           "SSH_MSG_SERVICE_ACCEPT received");
    }
    if(!result)
      return false;

    byte[] _username=null;
    _username=Util.str2byte(username);

    // send
    // byte      SSH_MSG_USERAUTH_REQUEST(50)
    // string    user name
    // string    service name ("ssh-connection")
    // string    "none"
    packet.reset();
    buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
    buf.putString(_username);
    buf.putString(Util.str2byte("ssh-connection"));
    buf.putString(Util.str2byte("none"));
    session.write(packet);

    loop:
    while(true){
      buf=session.read(buf);
      command=buf.getCommand()&0xff;

      if(command==SSH_MSG_USERAUTH_SUCCESS){
	return true;
      }
      if(command==SSH_MSG_USERAUTH_BANNER){
	buf.getInt(); buf.getByte(); buf.getByte();
	byte[] _message=buf.getString();
	byte[] lang=buf.getString();
	String message=Util.byte2str(_message);
	if(userinfo!=null){
          try{
            userinfo.showMessage(message);
          }
          catch(RuntimeException ee){
          }
	}
	continue loop;
      }
      if(command==SSH_MSG_USERAUTH_FAILURE){
	buf.getInt(); buf.getByte(); buf.getByte(); 
	byte[] foo=buf.getString();
	int partial_success=buf.getByte();
	methods=Util.byte2str(foo);
        break;
      }
      else{
	throw new JSchException("USERAUTH fail ("+command+")");
      }
    }
    return false;
  }
  String getMethods(){
    return methods;
  }
}
