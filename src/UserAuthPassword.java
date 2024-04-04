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
        password=Util.str2byte(_password);
      }

      byte[] _username=null;
      _username=Util.str2byte(username);
      packet.reset();
      buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
      buf.putString(_username);
      buf.putString(Util.str2byte("ssh-connection"));
      buf.putString(Util.str2byte("password"));
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
          String message=Util.byte2str(_message);
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
                                                 Util.byte2str(instruction),
                                                 prompt,
                                                 echo);
          if(response==null){
            throw new JSchAuthCancelException("password");
          }

          byte[] newpassword=Util.str2byte(response[0]);
          packet.reset();
          buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
          buf.putString(_username);
          buf.putString(Util.str2byte("ssh-connection"));
          buf.putString(Util.str2byte("password"));
          buf.putByte((byte)1);
          buf.putString(password);
          buf.putString(newpassword);
          Util.bzero(newpassword);
          response=null;
          session.write(packet);
	  continue loop;
        }
	if(command==SSH_MSG_USERAUTH_FAILURE){
	  buf.getInt(); buf.getByte(); buf.getByte(); 
	  byte[] foo=buf.getString();
	  int partial_success=buf.getByte();
	  if(partial_success!=0){
	    throw new JSchPartialAuthException(Util.byte2str(foo));
	  }
          session.auth_failures++;
	  break;
	}
	else{
	  return false;
	}
      }

      if(password!=null){
        Util.bzero(password);
        password=null;
      }
    }
    }finally{
      if(password!=null){
        Util.bzero(password);
        password=null;
      }
    }
  }
}
