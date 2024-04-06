public class ChannelSessionShell extends ChannelSession{
  ChannelSessionShell(){
    super();
    pty=true;
  }
  public void start() throws ExceptionC{
    Session _session=getSession();
    try{
      sendRequests();
      Request request=new RequestShell();
      request.request(_session, this);
    }catch(Exception e){
      throw new ExceptionC("ChannelShell");
    }
    thread=new Thread(this);
    thread.setName("Shell for "+_session.host);
    if(_session.daemon_thread)
      thread.setDaemon(_session.daemon_thread);
    thread.start();
  }

  void init() throws ExceptionC {
    setInputStream(getSession().in);
    setOutputStream(getSession().out);
  }
}
