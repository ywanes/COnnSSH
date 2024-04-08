import java.util.*;

class ChannelSession extends Channel{
  protected boolean agent_forwarding=false;
  protected boolean xforwading=false;
  protected Hashtable env=null;
  protected byte[] terminal_mode=null;

  ChannelSession(){
    super();
  }

  protected void sendRequests() throws Exception{
      Session _session=getSession();
      Request request=new RequestPtyReq();
      if(terminal_mode!=null)
        ((RequestPtyReq)request).setTerminalMode(terminal_mode);
      request.request(_session, this);
  }

  public void run(){
    // ponto critico!!
    Buffer buf=new Buffer(rmpsize);
    Packet packet=new Packet(buf);
    try{
      while(isConnected() &&thread!=null && in!=null){
        int i=in.read(buf.buffer, 14,    buf.buffer.length-14-Session.buffer_margin);
	if(i==0)
          continue;
	if(i==-1)
	  break;
	if(close)
          break;
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
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}

