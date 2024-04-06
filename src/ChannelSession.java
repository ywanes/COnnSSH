import java.util.*;

class ChannelSession extends Channel{
  private static byte[] _session=str2byte("session");
  protected boolean agent_forwarding=false;
  protected boolean xforwading=false;
  protected Hashtable env=null;
  protected boolean pty=false;
  protected String ttype="vt100";
  protected int tcol=80;
  protected int trow=24;
  protected int twp=640;
  protected int thp=480;
  protected byte[] terminal_mode=null;

  ChannelSession(){
    super();
    type=_session;
  }

  public void setAgentForwarding(boolean enable){ 
    agent_forwarding=enable;
  }

  public void setXForwarding(boolean enable){
    xforwading=enable; 
  }

  public void setEnv(String name, String value){
    setEnv(str2byte(name), str2byte(value));
  }

  public void setEnv(byte[] name, byte[] value){
    synchronized(this){
      getEnv().put(name, value);
    }
  }

  private Hashtable getEnv(){
    if(env==null)
      env=new Hashtable();
    return env;
  }

  public void setPty(boolean enable){ 
    pty=enable; 
  }

  public void setTerminalMode(byte[] terminal_mode){
    this.terminal_mode=terminal_mode;
  }

  public void setPtySize(int col, int row, int wp, int hp){
    setPtyType(this.ttype, col, row, wp, hp);
  }

  public void setPtyType(String ttype){
    setPtyType(ttype, 80, 24, 640, 480);
  }

  public void setPtyType(String ttype, int col, int row, int wp, int hp){
    this.ttype=ttype;
    this.tcol=col;
    this.trow=row;
    this.twp=wp;
    this.thp=hp;
  }

  protected void sendRequests() throws Exception{
    if(pty){
      Session _session=getSession();
      Request request=new RequestPtyReq();
      ((RequestPtyReq)request).setTType(ttype);
      ((RequestPtyReq)request).setTSize(tcol, trow, twp, thp);
      if(terminal_mode!=null)
        ((RequestPtyReq)request).setTerminalMode(terminal_mode);
      request.request(_session, this);
    }
  }

  public void run(){
    Buffer buf=new Buffer(rmpsize);
    Packet packet=new Packet(buf);
    int i=-1;
    try{
      while(isConnected() &&thread!=null && in!=null){
        i=in.read(buf.buffer, 14,    buf.buffer.length-14-Session.buffer_margin);
	if(i==0)continue;
	if(i==-1)
	  break;
	if(close)break;
        packet.reset();
        buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
        buf.putInt(recipient);
        buf.putInt(i);
        buf.skip(i);
	getSession().write(packet, this, i);
      }
    }catch(Exception e){
      AConfig.DebugPrintException("ex_20");
    }
    Thread _thread=thread; 
    if(_thread!=null)
      synchronized(_thread){ 
        _thread.notifyAll(); 
      }
    thread=null;
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}

