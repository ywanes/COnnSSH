public class ChannelSessionShell extends ChannelSession{
  ChannelSessionShell(){
    super();
  }
  public void start() throws ExceptionC{
    Session _session=getSession();
    try{
      terminal_mode=(byte[])str2byte("");
      String ttype="vt100";
      int tcol=80;
      int trow=24;
      int twp=640;
      int thp=480;      
      Buffer buf=new Buffer();
      Packet packet=new Packet(buf);
      packet.reset();
      buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
      buf.putInt(getRecipient());
      buf.putString(str2byte("pty-req"));
      buf.putByte((byte)0);
      buf.putString(str2byte(ttype));
      buf.putInt(tcol);
      buf.putInt(trow);
      buf.putInt(twp);
      buf.putInt(thp);
      buf.putString(terminal_mode);
      _session.write(packet);
      
      buf=new Buffer();
      packet=new Packet(buf);
      packet.reset();
      buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
      buf.putInt(getRecipient());
      buf.putString(str2byte("shell"));
      buf.putByte((byte)0);
      _session.write(packet);
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
