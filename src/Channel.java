import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public class Channel implements Runnable{
  public static Channel channel=null;
  InputStream in=System.in;
  OutputStream out=System.out;
  OutputStream out_ext=null;

  Channel(Session session){
    try{
      this.session=session;
      this.channel=this;
      connect();
      while (!isEOF()) {}      
    }catch(Exception e){
      System.err.println(e.toString());
      System.exit(1);
    }
  }
  static Channel getChannel(int id, Session session){
    return channel;
  }
  volatile int recipient=-1;
  volatile long rwsize=0;
  volatile int rmpsize=0;
  volatile boolean eof_local=false;
  volatile boolean eof_remote=false;
  volatile boolean close=false;
  volatile boolean connected=false;
  volatile int exitstatus2=-1;
  volatile int reply=0; 
  volatile int connectTimeout=30000;
  private Session session;
  int notifyme=0; 

  synchronized void setRecipient(int foo){
    this.recipient=foo;
    if(notifyme>0)
      notifyAll();
  }
  public void connect() throws ExceptionC, Exception{
    sendChannelOpen();
    byte[] terminal_mode=(byte[])str2byte("");
    String ttype="vt100";
    int tcol=80;
    int trow=24;
    int twp=640;
    int thp=480;      
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(recipient);
    buf.putString(str2byte("pty-req"));
    buf.putByte((byte)0);
    buf.putString(str2byte(ttype));
    buf.putInt(tcol);
    buf.putInt(trow);
    buf.putInt(twp);
    buf.putInt(thp);
    buf.putString(terminal_mode);
    session.write(packet);
    buf=new Buffer();
    packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(recipient);
    buf.putString(str2byte("shell"));
    buf.putByte((byte)0);
    session.write(packet);
    new Thread(this).start();
  }
  public boolean isEOF() {return eof_remote;}
  synchronized void setRemoteWindowSize(long foo){ this.rwsize=foo; }
  synchronized void addRemoteWindowSize(long foo){ 
    this.rwsize+=foo; 
    if(notifyme>0)
      notifyAll();
  }
  void setRemotePacketSize(int foo){ 
    this.rmpsize=foo; 
  }
  void put(byte[] array, int begin, int length) throws IOException {
    out.write(array, begin, length);
    out.flush();
  }
  void put_ext(byte[] array, int begin, int length) throws IOException {
    out_ext.write(array, begin, length);
    out_ext.flush();
  }
  public boolean isConnected(){
    Session _session=this.session;
    if(_session!=null)
      return _session.isConnected() && connected;
    return false;
  }
  protected void sendChannelOpen() throws Exception {
    if(!session.isConnected())
      throw new ExceptionC("session is down");
    Buffer buf=new Buffer(100);
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)90);
    buf.putString(str2byte("session"));
    buf.putInt(0);
    buf.putInt(0x100000);
    buf.putInt(0x4000);
    session.write(packet);
    int retry=2000;
    long timeout=connectTimeout;
    if(timeout!=0L) retry = 1;
    synchronized(this){
      if(recipient==-1 && session.isConnected() && retry>0){
        try{
          long t = timeout==0L ? 10L : timeout;
          this.notifyme=1;
          wait(t);
        }catch(java.lang.InterruptedException e){
        }finally{
          this.notifyme=0;
        }
        retry--;
      }
    }
    if(!session.isConnected())
      throw new ExceptionC("session is down");
    if(recipient==-1)
      throw new ExceptionC("channel is not opened.");
    connected=true;
  }

  public void run(){
    // ponto critico!!
    Buffer buf=new Buffer(rmpsize);
    Packet packet=new Packet(buf);
    try{
      while(isConnected()){
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
	session.write(packet, this, i);
      }
    }catch(Exception e){
      System.out.println("ex_20");
    }
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
}
