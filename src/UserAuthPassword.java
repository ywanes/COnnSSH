class UserAuthPassword extends UserAuth{
  private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ=60;
  public boolean start(Session session) throws Exception{
    super.start(session);
    byte[] password=session.password;
    String dest=username+"@"+session.host;
    if(session.port!=22){
      dest+=(":"+session.port);
    }
    try{
    while(true){
      if(session.auth_failures >= session.max_auth_tries){
        return false;
      }
      if(password==null){
	if(userinfo==null){
	  return false;
	}
	if(!userinfo.promptPassword("Password for "+dest)){
	  throw new JSchAuthCancelException("password");
	}

	String _password=userinfo.getPassword();
	if(_password==null){
	  throw new JSchAuthCancelException("password");
	}
        password=str2byte(_password);
      }

      byte[] _username=null;
      _username=str2byte(username);
      packet.reset();
      buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
      buf.putString(_username);
      buf.putString(str2byte("ssh-connection"));
      buf.putString(str2byte("password"));
      buf.putByte((byte)0);
      buf.putString(password);
      session.write(packet);

      loop:
      while(true){
	buf=session.read(buf);
        int command=buf.getCommand()&0xff;

	if(command==SSH_MSG_USERAUTH_SUCCESS){
	  return true;
	}
	if(command==SSH_MSG_USERAUTH_BANNER){
	  buf.getInt(); buf.getByte(); buf.getByte();
	  byte[] _message=buf.getString();
	  byte[] lang=buf.getString();
          String message=byte2str(_message);
	  if(userinfo!=null){
	    userinfo.showMessage(message);
	  }
	  continue loop;
	}
	if(command==SSH_MSG_USERAUTH_PASSWD_CHANGEREQ){
	  buf.getInt(); buf.getByte(); buf.getByte(); 
	  byte[] instruction=buf.getString();
	  byte[] tag=buf.getString();
	  if(userinfo==null || 
             !(userinfo instanceof UIKeyboardInteractive)){
            if(userinfo!=null){
              userinfo.showMessage("Password must be changed.");
            }
            return false;
          }

          UIKeyboardInteractive kbi=(UIKeyboardInteractive)userinfo;
          String[] response;
          String name="Password Change Required";
          String[] prompt={"New Password: "};
          boolean[] echo={false};
          response=kbi.promptKeyboardInteractive(dest,
                                                 name,
                                                 byte2str(instruction),
                                                 prompt,
                                                 echo);
          if(response==null){
            throw new JSchAuthCancelException("password");
          }
	  continue loop;
        }
	if(command==SSH_MSG_USERAUTH_FAILURE){
	  buf.getInt(); buf.getByte(); buf.getByte(); 
	  byte[] foo=buf.getString();
	  int partial_success=buf.getByte();
	  if(partial_success!=0){
	    throw new JSchPartialAuthException(byte2str(foo));
	  }
          session.auth_failures++;
	  break;
	}
	else{
	  return false;
	}
      }
    }
    }finally{}
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
