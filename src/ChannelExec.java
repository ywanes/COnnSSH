import java.util.*;

public class ChannelExec extends ChannelSession{

  byte[] command=new byte[0];

  public void start() throws JSchException{
    Session _session=getSession();
    try{
      sendRequests();
      Request request=new RequestExec(command);
      request.request(_session, this);
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_15");
      if(e instanceof JSchException) throw (JSchException)e;
      if(e instanceof Throwable)
        throw new JSchException("ChannelExec", (Throwable)e);
      throw new JSchException("ChannelExec");
    }

    if(io.in!=null){
      thread=new Thread(this);
      thread.setName("Exec thread "+_session.getHost());
      if(_session.daemon_thread){
        thread.setDaemon(_session.daemon_thread);
      }
      thread.start();
    }
  }

  public void setCommand(String command){ 
    this.command=Util.str2byte(command);
  }
  public void setCommand(byte[] command){ 
    this.command=command;
  }

  void init() throws JSchException {
    io.setInputStream(getSession().in);
    io.setOutputStream(getSession().out);
  }

  public void setErrStream(java.io.OutputStream out){
    setExtOutputStream(out);
  }
  public void setErrStream(java.io.OutputStream out, boolean dontclose){
    setExtOutputStream(out, dontclose);
  }
  public java.io.InputStream getErrStream() throws java.io.IOException {
    return getExtInputStream();
  }
}
