public class ChannelShell extends ChannelSession{

  ChannelShell(){
    super();
    pty=true;
  }

  public void start() throws ExceptionC{
    Session _session=getSession();
    try{
      sendRequests();
      Request request=new RequestShell();
      request.request(_session, this);
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_61");
      if(e instanceof ExceptionC) throw (ExceptionC)e;
      if(e instanceof Throwable)
        throw new ExceptionC("ChannelShell", (Throwable)e);
      throw new ExceptionC("ChannelShell");
    }

    if(in!=null){
      thread=new Thread(this);
      thread.setName("Shell for "+_session.host);
      if(_session.daemon_thread){
        thread.setDaemon(_session.daemon_thread);
      }
      thread.start();
    }
  }

  void init() throws ExceptionC {
    setInputStream(getSession().in);
    setOutputStream(getSession().out);
  }
}
