
public class ChannelShell extends ChannelSession{

  ChannelShell(){
    super();
    pty=true;
  }

  public void start() throws ExceptionCOnn{
    Session _session=getSession();
    try{
      sendRequests();
      Request request=new RequestShell();
      request.request(_session, this);
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_61");
      if(e instanceof ExceptionCOnn) throw (ExceptionCOnn)e;
      if(e instanceof Throwable)
        throw new ExceptionCOnn("ChannelShell", (Throwable)e);
      throw new ExceptionCOnn("ChannelShell");
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

  void init() throws ExceptionCOnn {
    setInputStream(getSession().in);
    setOutputStream(getSession().out);
  }
}
