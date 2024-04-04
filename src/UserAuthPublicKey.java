import java.util.Vector;

class UserAuthPublicKey extends UserAuth{

  public boolean start(Session session) throws Exception{
    super.start(session);

    Vector identities=session.getIdentityRepository().getIdentities();

    byte[] passphrase=null;
    byte[] _username=null;

    int command;

    synchronized(identities){
      if(identities.size()<=0){
        return false;
      }

      _username=Util.str2byte(username);

      for(int i=0; i<identities.size(); i++){

        if(session.auth_failures >= session.max_auth_tries){
          return false;
        }

        Identity identity=(Identity)(identities.elementAt(i));
        byte[] pubkeyblob=identity.getPublicKeyBlob();

        if(pubkeyblob!=null){
          // send
          // byte      SSH_MSG_USERAUTH_REQUEST(50)
          // string    user name
          // string    service name ("ssh-connection")
          // string    "publickey"
          // boolen    FALSE
          // string    public key algorithm name
          // string    public key blob
          packet.reset();
          buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
          buf.putString(_username);
          buf.putString(Util.str2byte("ssh-connection"));
          buf.putString(Util.str2byte("publickey"));
          buf.putByte((byte)0);
          buf.putString(Util.str2byte(identity.getAlgName()));
          buf.putString(pubkeyblob);
          session.write(packet);

          loop1:
          while(true){
            buf=session.read(buf);
            command=buf.getCommand()&0xff;

            if(command==SSH_MSG_USERAUTH_PK_OK){
              break;
            }
            else if(command==SSH_MSG_USERAUTH_FAILURE){
              break;
            }
            else if(command==SSH_MSG_USERAUTH_BANNER){
              buf.getInt(); buf.getByte(); buf.getByte();
              byte[] _message=buf.getString();
              byte[] lang=buf.getString();
              String message=Util.byte2str(_message);
              if(userinfo!=null){
                userinfo.showMessage(message);
              }
              continue loop1;
            }
            else{
	    //System.err.println("USERAUTH fail ("+command+")");
	    //throw new JSchException("USERAUTH fail ("+command+")");
              break;
            }
          }

          if(command!=SSH_MSG_USERAUTH_PK_OK){
            continue;
          }
        }

//System.err.println("UserAuthPublicKey: identity.isEncrypted()="+identity.isEncrypted());

        int count=5;
        while(true){
          if((identity.isEncrypted() && passphrase==null)){
            if(userinfo==null) throw new JSchException("USERAUTH fail");
            if(identity.isEncrypted() &&
               !userinfo.promptPassphrase("Passphrase for "+identity.getName())){
              throw new JSchAuthCancelException("publickey");
              //throw new JSchException("USERAUTH cancel");
              //break;
            }
            String _passphrase=userinfo.getPassphrase();
            if(_passphrase!=null){
              passphrase=Util.str2byte(_passphrase);
            }
          }

          if(!identity.isEncrypted() || passphrase!=null){
            if(identity.setPassphrase(passphrase)){
              if(passphrase!=null &&
                 (session.getIdentityRepository() instanceof IdentityRepository.Wrapper)){
                ((IdentityRepository.Wrapper)session.getIdentityRepository()).check();
              }
              break;
            }
          }
          Util.bzero(passphrase);
          passphrase=null;
          count--;
          if(count==0)break;
        }

        Util.bzero(passphrase);
        passphrase=null;
//System.err.println("UserAuthPublicKey: identity.isEncrypted()="+identity.isEncrypted());

        if(identity.isEncrypted()) continue;
        if(pubkeyblob==null) pubkeyblob=identity.getPublicKeyBlob();

//System.err.println("UserAuthPublicKey: pubkeyblob="+pubkeyblob);

        if(pubkeyblob==null) continue;

        // send
        // byte      SSH_MSG_USERAUTH_REQUEST(50)
        // string    user name
        // string    service name ("ssh-connection")
        // string    "publickey"
        // boolen    TRUE
        // string    public key algorithm name
        // string    public key blob
        // string    signature
        packet.reset();
        buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
        buf.putString(_username);
        buf.putString(Util.str2byte("ssh-connection"));
        buf.putString(Util.str2byte("publickey"));
        buf.putByte((byte)1);
        buf.putString(Util.str2byte(identity.getAlgName()));
        buf.putString(pubkeyblob);

//      byte[] tmp=new byte[buf.index-5];
//      System.arraycopy(buf.buffer, 5, tmp, 0, tmp.length);
//      buf.putString(signature);

        byte[] sid=session.getSessionId();
        int sidlen=sid.length;
        byte[] tmp=new byte[4+sidlen+buf.index-5];
        tmp[0]=(byte)(sidlen>>>24);
        tmp[1]=(byte)(sidlen>>>16);
        tmp[2]=(byte)(sidlen>>>8);
        tmp[3]=(byte)(sidlen);
        System.arraycopy(sid, 0, tmp, 4, sidlen);
        System.arraycopy(buf.buffer, 5, tmp, 4+sidlen, buf.index-5);
        byte[] signature=identity.getSignature(tmp);
        if(signature==null){  // for example, too long key length.
          break;
        }
        buf.putString(signature);
        session.write(packet);

        loop2:
        while(true){
          buf=session.read(buf);
          command=buf.getCommand()&0xff;

          if(command==SSH_MSG_USERAUTH_SUCCESS){
            return true;
          }
          else if(command==SSH_MSG_USERAUTH_BANNER){
            buf.getInt(); buf.getByte(); buf.getByte();
            byte[] _message=buf.getString();
            byte[] lang=buf.getString();
            String message=Util.byte2str(_message);
            if(userinfo!=null){
              userinfo.showMessage(message);
            }
            continue loop2;
          }
          else if(command==SSH_MSG_USERAUTH_FAILURE){
            buf.getInt(); buf.getByte(); buf.getByte(); 
            byte[] foo=buf.getString();
            int partial_success=buf.getByte();
	  //System.err.println(new String(foo)+
	  //                   " partial_success:"+(partial_success!=0));
            if(partial_success!=0){
              throw new JSchPartialAuthException(Util.byte2str(foo));
            }
            session.auth_failures++;
            break;
          }
          //System.err.println("USERAUTH fail ("+command+")");
          //throw new JSchException("USERAUTH fail ("+command+")");
          break;
        }
      }
    }
    return false;
  }
}
