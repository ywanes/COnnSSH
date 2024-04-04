import java.util.*;

public class ChannelShell extends ChannelSession{

  ChannelShell(){
    super();
    pty=true;
  }

  public void start() throws JSchException{
    Session _session=getSession();
    try{
      sendRequests();

      Request request=new RequestShell();
      request.request(_session, this);
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_61");
      if(e instanceof JSchException) throw (JSchException)e;
      if(e instanceof Throwable)
        throw new JSchException("ChannelShell", (Throwable)e);
      throw new JSchException("ChannelShell");
    }

    if(io.in!=null){
      thread=new Thread(this);
      thread.setName("Shell for "+_session.host);
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
}
