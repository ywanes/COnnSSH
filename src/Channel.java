import java.io.PipedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public class Channel implements Runnable{
  InputStream in=System.in;
  OutputStream out=System.out;
  OutputStream out_ext=null;

  Channel(Session _session) throws ExceptionC{
    this.session=_session;
    synchronized(pool){
      id=index++;
      pool.addElement(this);
    }
    setInputStream(System.in);
    setOutputStream(System.out);
    connect(3000);
    while (!isEOF()) {}
  }
    
  
  private boolean out_dontclose=false;
  static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION=      91;
  static final int SSH_MSG_CHANNEL_OPEN_FAILURE=           92;
  static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED=    1;
  static int index=0; 
  private static java.util.Vector pool=new java.util.Vector();
  static Channel getChannel(int id, Session session){
    synchronized(pool){
      for(int i=0; i<pool.size(); i++){
        Channel c=(Channel)(pool.elementAt(i));
        if(c.id==id && c.session==session)
          return c;
      }
    }
    return null;
  }
  static void del(Channel c){
    synchronized(pool){
      pool.removeElement(c);
    }
  }

  int id;
  volatile int recipient=-1;
  protected byte[] type=str2byte("session");
  volatile int lwsize_max=0x100000;
  volatile int lwsize=lwsize_max;
  volatile int lmpsize=0x4000;
  volatile long rwsize=0;
  volatile int rmpsize=0;
  volatile boolean eof_local=false;
  volatile boolean eof_remote=false;
  volatile boolean close=false;
  volatile boolean connected=false;
  volatile boolean open_confirmation=false;
  volatile int exitstatus=-1;
  volatile int reply=0; 
  volatile int connectTimeout=0;
  private Session session;
  int notifyme=0; 

  synchronized void setRecipient(int foo){
    this.recipient=foo;
    if(notifyme>0)
      notifyAll();
  }
  int getRecipient(){
    return recipient;
  }

  public void connect() throws ExceptionC{
    connect(0);
  }

  public void connect(int connectTimeout) throws ExceptionC{
    this.connectTimeout=connectTimeout;
    try{
        sendChannelOpen();
        Session _session=getSession();
        try{
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
        new Thread(this).start();
    }catch(Exception e){
      AConfig.DebugPrintException("ex_2");
      connected=false;
      disconnect();
      if(e instanceof ExceptionC) 
        throw (ExceptionC)e;
      throw new ExceptionC(e.toString(), e);
    }
  }
  public void setXForwarding(boolean foo){}
  public boolean isEOF() {return eof_remote;}
  void getData(Buffer buf){
    setRecipient(buf.getInt());
    setRemoteWindowSize(buf.getUInt());
    setRemotePacketSize(buf.getInt());
  }
  
  public void setInputStream(InputStream in){
    this.in=in;
  }
  public void setInputStream(InputStream in, boolean dontclose){
    this.in=in;
  }
  public void setOutputStream(OutputStream out){
    this.out=out;
  }
  public void setOutputStream(OutputStream out, boolean dontclose){
    this.out=out;
    this.out_dontclose=dontclose;
  }
  public void setExtOutputStream(OutputStream out){
    this.out_ext=out;
  }
  public void setExtOutputStream(OutputStream out, boolean dontclose){
    this.out_ext=out;
    this.out_dontclose=dontclose;
  }
  public OutputStream getOutputStream() throws IOException {
    return null;
  }

  class MyPipedInputStream extends PipedInputStream{
    private int BUFFER_SIZE = 1024;
    private int max_buffer_size = BUFFER_SIZE;

    public synchronized void updateReadSide() throws IOException {
      if(available() != 0)
        return;
      in = 0;
      out = 0;
      buffer[in++] = 0;
      read();
    }
    private int freeSpace(){
      int size = 0;
      if(out < in){
        size = buffer.length-in;
      }else if(in < out){
        if(in == -1)
          size = buffer.length;
        else
          size = out - in;
      }
      return size;
    } 
    synchronized void checkSpace(int len) throws IOException {
      int size = freeSpace();
      if(size<len){
        int datasize=buffer.length-size;
        int foo = buffer.length;
        while((foo - datasize) < len)
          foo*=2;
        if(foo > max_buffer_size)
          foo = max_buffer_size;
        if((foo - datasize) < len) 
          return;
        byte[] tmp = new byte[foo];
        if(out < in){
          System.arraycopy(buffer, 0, tmp, 0, buffer.length);
        }else if(in < out){
          if(in != -1) {
            System.arraycopy(buffer, 0, tmp, 0, in);
            System.arraycopy(buffer, out, tmp, tmp.length-(buffer.length-out),(buffer.length-out));
            out = tmp.length-(buffer.length-out);
          }
        }else if(in == out){
          System.arraycopy(buffer, 0, tmp, 0, buffer.length);
          in=buffer.length;
        }
        buffer=tmp;
      }else if(buffer.length == size && size > BUFFER_SIZE) { 
        int  i = size/2;
        if(i<BUFFER_SIZE) 
          i = BUFFER_SIZE;
        byte[] tmp = new byte[i];
        buffer=tmp;
      }
    }
  }
  void setLocalWindowSize(int foo){ this.lwsize=foo; }
  synchronized void setRemoteWindowSize(long foo){ this.rwsize=foo; }
  synchronized void addRemoteWindowSize(long foo){ 
    this.rwsize+=foo; 
    if(notifyme>0)
      notifyAll();
  }
  void setRemotePacketSize(int foo){ this.rmpsize=foo; }
  public void put(Packet p) throws IOException, java.net.SocketException {
    out.write(p.buffer.buffer, 0, p.buffer.index);
    out.flush();
  }
  void put(byte[] array, int begin, int length) throws IOException {
    out.write(array, begin, length);
    out.flush();
  }
  void put_ext(byte[] array, int begin, int length) throws IOException {
    out_ext.write(array, begin, length);
    out_ext.flush();
  }
  
  void eof_remote(){
    eof_remote=true;
    try{
      out_close();
    }catch(NullPointerException e){}
  }

  void out_close(){
    try{
      if(out!=null && !out_dontclose) out.close();
      out=null;
    }
    catch(Exception ee){}
  }
  void close(){
    if(close)return;
    close=true;
    eof_local=eof_remote=true;
    int i = getRecipient();
    if(i == -1) return;
    try{
      Buffer buf=new Buffer(100);
      Packet packet=new Packet(buf);
      packet.reset();
      buf.putByte((byte)Session.SSH_MSG_CHANNEL_CLOSE);
      buf.putInt(i);
      synchronized(this){
        getSession().write(packet);
      }
    }
    catch(Exception e){
      AConfig.DebugPrintException("ex_7");
    }
  }
  public boolean isClosed(){
    return close;
  }
  static void disconnect(Session session){
    Channel[] channels=null;
    int count=0;
    synchronized(pool){
      channels=new Channel[pool.size()];
      for(int i=0; i<pool.size(); i++){
	try{
	  Channel c=((Channel)(pool.elementAt(i)));
	  if(c.session==session){
	    channels[count++]=c;
	  }
	}catch(Exception e){
          AConfig.DebugPrintException("ex_8");
	}
      } 
    }
    for(int i=0; i<count; i++)
      channels[i].disconnect();
  }

  public void disconnect(){
    try{
      synchronized(this){
        if(!connected){
          return;
        }
        connected=false;
      }
      close();
      eof_remote=eof_local=true;
      try{
        close();
      }
      catch(Exception e){
        AConfig.DebugPrintException("ex_9");
      }
    }finally{
      Channel.del(this);
    }
  }

  public boolean isConnected(){
    Session _session=this.session;
    if(_session!=null)
      return _session.isConnected() && connected;
    return false;
  }
  public void sendSignal(String signal) throws Exception {}

  void setExitStatus(int status){ exitstatus=status; }
  public int getExitStatus(){ return exitstatus; }

  public Session getSession() throws ExceptionC{ 
    Session _session=session;
    if(_session==null){
      throw new ExceptionC("session is not available");
    }
    return _session;
  }
  public int getId(){ return id; }

  protected void sendOpenConfirmation() throws Exception{
    Buffer buf=new Buffer(100);
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    buf.putInt(getRecipient());
    buf.putInt(id);
    buf.putInt(lwsize);
    buf.putInt(lmpsize);
    getSession().write(packet);
  }

  protected void sendOpenFailure(int reasoncode){
    try{
      Buffer buf=new Buffer(100);
      Packet packet=new Packet(buf);
      packet.reset();
      buf.putByte((byte)SSH_MSG_CHANNEL_OPEN_FAILURE);
      buf.putInt(getRecipient());
      buf.putInt(reasoncode);
      buf.putString(str2byte("open failed"));
      buf.putString((byte[])str2byte(""));      
      getSession().write(packet);
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_10");
    }
  }

  protected void sendChannelOpen() throws Exception {
    Session _session=getSession();
    if(!_session.isConnected()){
      throw new ExceptionC("session is down");
    }

    Buffer buf=new Buffer(100);
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)90);
    buf.putString(this.type);
    buf.putInt(this.id);
    buf.putInt(this.lwsize);
    buf.putInt(this.lmpsize);

    _session.write(packet);

    int retry=2000;
    long start=System.currentTimeMillis();
    long timeout=connectTimeout;
    if(timeout!=0L) retry = 1;
    synchronized(this){
      while(this.getRecipient()==-1 &&
            _session.isConnected() &&
             retry>0){
        if(timeout>0L){
          if((System.currentTimeMillis()-start)>timeout){
            retry=0;
            continue;
          }
        }
        try{
          long t = timeout==0L ? 10L : timeout;
          this.notifyme=1;
          wait(t);
        }
        catch(java.lang.InterruptedException e){
        }
        finally{
          this.notifyme=0;
        }
        retry--;
      }
    }
    if(!_session.isConnected()){
      throw new ExceptionC("session is down");
    }
    if(this.getRecipient()==-1){  // timeout
      throw new ExceptionC("channel is not opened.");
    }
    if(this.open_confirmation==false){
      throw new ExceptionC("channel is not opened.");
    }
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
	getSession().write(packet, this, i);
      }
    }catch(Exception e){
      AConfig.DebugPrintException("ex_20");
    }
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
