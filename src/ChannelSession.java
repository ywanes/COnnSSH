import java.util.*;

class ChannelSession extends Channel{
  private static byte[] _session=Util.str2byte("session");

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
    io=new IO();
  }

  /**
   * Enable the agent forwarding.
   *
   * @param enable
   */
  public void setAgentForwarding(boolean enable){ 
    agent_forwarding=enable;
  }

  /**
   * Enable the X11 forwarding.
   * Refer to RFC4254 6.3.1. Requesting X11 Forwarding.
   *
   * @param enable
   */
  public void setXForwarding(boolean enable){
    xforwading=enable; 
  }


  /**
   * Set the environment variable. 
   * If <code>name</code> and <code>value</code> are needed to be passed 
   * to the remote in your favorite encoding,
   * use {@link #setEnv(byte[], byte[])}.
   * Refer to RFC4254 6.4 Environment Variable Passing.
   *
   * @param name A name for environment variable.
   * @param value A value for environment variable.
   */
  public void setEnv(String name, String value){
    setEnv(Util.str2byte(name), Util.str2byte(value));
  }

  /**
   * Set the environment variable.
   * Refer to RFC4254 6.4 Environment Variable Passing.
   *
   * @param name A name of environment variable.
   * @param value A value of environment variable.
   * @see #setEnv(String, String)
   */
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

  /**
   * Allocate a Pseudo-Terminal.
   * Refer to RFC4254 6.2. Requesting a Pseudo-Terminal.
   *
   * @param enable
   */
  public void setPty(boolean enable){ 
    pty=enable; 
  }

  /**
   * Set the terminal mode.
   * 
   * @param terminal_mode
   */
  public void setTerminalMode(byte[] terminal_mode){
    this.terminal_mode=terminal_mode;
  }

  /**
   * Change the window dimension interactively.
   * Refer to RFC4254 6.7. Window Dimension Change Message.
   *
   * @param col terminal width, columns
   * @param row terminal height, rows
   * @param wp terminal width, pixels
   * @param hp terminal height, pixels
   */
  public void setPtySize(int col, int row, int wp, int hp){
    setPtyType(this.ttype, col, row, wp, hp);
    if(!pty || !isConnected()){
      return;
    }
    try{
      RequestWindowChange request=new RequestWindowChange();
      request.setSize(col, row, wp, hp);
      request.request(getSession(), this);
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_19");
    }
  }

  /**
   * Set the terminal type.
   * This method is not effective after Channel#connect().
   *
   * @param ttype terminal type(for example, "vt100")
   * @see #setPtyType(String, int, int, int, int)
   */
  public void setPtyType(String ttype){
    setPtyType(ttype, 80, 24, 640, 480);
  }

  /**
   * Set the terminal type.
   * This method is not effective after Channel#connect().
   *
   * @param ttype terminal type(for example, "vt100")
   * @param col terminal width, columns
   * @param row terminal height, rows
   * @param wp terminal width, pixels
   * @param hp terminal height, pixels
   */
  public void setPtyType(String ttype, int col, int row, int wp, int hp){
    this.ttype=ttype;
    this.tcol=col;
    this.trow=row;
    this.twp=wp;
    this.thp=hp;
  }

  protected void sendRequests() throws Exception{
    Session _session=getSession();
    Request request;
    if(agent_forwarding){
      request=new RequestAgentForwarding();
      request.request(_session, this);
    }

    if(xforwading){
      request=new RequestX11();
      request.request(_session, this);
    }

    if(pty){
      request=new RequestPtyReq();
      ((RequestPtyReq)request).setTType(ttype);
      ((RequestPtyReq)request).setTSize(tcol, trow, twp, thp);
      if(terminal_mode!=null){
        ((RequestPtyReq)request).setTerminalMode(terminal_mode);
      }
      request.request(_session, this);
    }

    if(env!=null){
      for(Enumeration _env=env.keys(); _env.hasMoreElements();){
        Object name=_env.nextElement();
        Object value=env.get(name);
        request=new RequestEnv();
        ((RequestEnv)request).setEnv(toByteArray(name), 
                                     toByteArray(value));
        request.request(_session, this);
      }
    }
  }

  private byte[] toByteArray(Object o){
    if(o instanceof String){
      return Util.str2byte((String)o);
    }
    return (byte[])o;
  }

  public void run(){
    //System.err.println(this+":run >");

    Buffer buf=new Buffer(rmpsize);
    Packet packet=new Packet(buf);
    int i=-1;
    try{
      while(isConnected() &&
	    thread!=null && 
            io!=null && 
            io.in!=null){
        i=io.in.read(buf.buffer, 
                     14,    
                     buf.buffer.length-14
                     -Session.buffer_margin
		     );
	if(i==0)continue;
	if(i==-1){
	  eof();
	  break;
	}
	if(close)break;
        //System.out.println("write: "+i);
        packet.reset();
        buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
        buf.putInt(recipient);
        buf.putInt(i);
        buf.skip(i);
	getSession().write(packet, this, i);
      }
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_20");
    }
    Thread _thread=thread; 
    if(_thread!=null){
      synchronized(_thread){ _thread.notifyAll(); }
    }
    thread=null;
    //System.err.println(this+":run <");
  }
}
