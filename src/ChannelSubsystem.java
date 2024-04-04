public class ChannelSubsystem extends ChannelSession{
  boolean xforwading=false;
  boolean pty=false;
  boolean want_reply=true;
  String subsystem="";
  public void setXForwarding(boolean foo){ xforwading=foo; }
  public void setPty(boolean foo){ pty=foo; }
  public void setWantReply(boolean foo){ want_reply=foo; }
  public void setSubsystem(String foo){ subsystem=foo; }
  public void start() throws JSchException{
    Session _session=getSession();
    try{
      Request request;
      if(xforwading){
        request=new RequestX11();
        request.request(_session, this);
      }
      if(pty){
	request=new RequestPtyReq();
	request.request(_session, this);
      }
      request=new RequestSubsystem();
      ((RequestSubsystem)request).request(_session, this, subsystem, want_reply);
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_62");
      if(e instanceof JSchException){ throw (JSchException)e; }
      if(e instanceof Throwable)
        throw new JSchException("ChannelSubsystem", (Throwable)e);
      throw new JSchException("ChannelSubsystem");
    }
    if(io.in!=null){
      thread=new Thread(this);
      thread.setName("Subsystem for "+_session.host);
      if(_session.daemon_thread){
        thread.setDaemon(_session.daemon_thread);
      }
      thread.start();
    }
  }

  void init() throws JSchException {
    io.setInputStream(getSession().in);
    io.setOutputStream(getSession().out);
  }

  public void setErrStream(java.io.OutputStream out){
    setExtOutputStream(out);
  }
  public java.io.InputStream getErrStream() throws java.io.IOException {
    return getExtInputStream();
  }
}
