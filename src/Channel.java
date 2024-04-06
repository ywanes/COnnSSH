import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

public abstract class Channel implements Runnable{
  InputStream in=System.in;
  OutputStream out=System.out;
  OutputStream out_ext=null;
  
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
  protected byte[] type=str2byte("foo");
  volatile int lwsize_max=0x100000;
  volatile int lwsize=lwsize_max;
  volatile int lmpsize=0x4000;
  volatile long rwsize=0;
  volatile int rmpsize=0;
  Thread thread=null;
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

  Channel(){
    synchronized(pool){
      id=index++;
      pool.addElement(this);
    }
  }
  synchronized void setRecipient(int foo){
    this.recipient=foo;
    if(notifyme>0)
      notifyAll();
  }
  int getRecipient(){
    return recipient;
  }

  void init() throws ExceptionC {
  }

  public void connect() throws ExceptionC{
    connect(0);
  }

  public void connect(int connectTimeout) throws ExceptionC{
    this.connectTimeout=connectTimeout;
    try{
      sendChannelOpen();
      start();
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
  public void start() throws ExceptionC{}
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
  public InputStream getInputStream() throws IOException {
    int max_input_buffer_size = 32*1024;
    try {
      max_input_buffer_size =
        Integer.parseInt(AConfig.getNameByConfig("max_input_buffer_size"));
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_3");
    }
    PipedInputStream in = new MyPipedInputStream(32*1024,max_input_buffer_size);
    boolean resizable = 32*1024<max_input_buffer_size;
    setOutputStream(new PassiveOutputStream(in, resizable), false);
    return in;
  }
  public InputStream getExtInputStream() throws IOException {
    int max_input_buffer_size = 32*1024;
    try {
      max_input_buffer_size = Integer.parseInt(AConfig.getNameByConfig("max_input_buffer_size"));
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_4");
    }
    PipedInputStream in = new MyPipedInputStream(32*1024,max_input_buffer_size);
    boolean resizable = 32*1024<max_input_buffer_size;
    setExtOutputStream(new PassiveOutputStream(in, resizable), false);
    return in;
  }
  public OutputStream getOutputStream() throws IOException {
    return null;
  }

  class MyPipedInputStream extends PipedInputStream{
    private int BUFFER_SIZE = 1024;
    private int max_buffer_size = BUFFER_SIZE;
    MyPipedInputStream() throws IOException{ super(); }
    MyPipedInputStream(int size) throws IOException{
      super();
      buffer=new byte[size];
      BUFFER_SIZE = size;
      max_buffer_size = size;
    }
    MyPipedInputStream(int size, int max_buffer_size) throws IOException{
      this(size);
      this.max_buffer_size = max_buffer_size;
    }
    MyPipedInputStream(PipedOutputStream out) throws IOException{ super(out); }
    MyPipedInputStream(PipedOutputStream out, int size) throws IOException{
      super(out);
      buffer=new byte[size];
      BUFFER_SIZE=size;
    }
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
  void setLocalWindowSizeMax(int foo){ this.lwsize_max=foo; }
  void setLocalWindowSize(int foo){ this.lwsize=foo; }
  void setLocalPacketSize(int foo){ this.lmpsize=foo; }
  synchronized void setRemoteWindowSize(long foo){ this.rwsize=foo; }
  synchronized void addRemoteWindowSize(long foo){ 
    this.rwsize+=foo; 
    if(notifyme>0)
      notifyAll();
  }
  void setRemotePacketSize(int foo){ this.rmpsize=foo; }

  public void run(){}

  void write(byte[] foo) throws IOException {
    write(foo, 0, foo.length);
  }
  void write(byte[] foo, int s, int l) throws IOException {
    try{
      put(foo, s, l);
    }catch(NullPointerException e){}
  }
  void write_ext(byte[] foo, int s, int l) throws IOException {
    try{
      put_ext(foo, s, l);
    }catch(NullPointerException e){}
  }

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
      thread=null;
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

  class PassiveInputStream extends MyPipedInputStream{
    PipedOutputStream out;
    PassiveInputStream(PipedOutputStream out, int size) throws IOException{
      super(out, size);
      this.out=out;
    }
    PassiveInputStream(PipedOutputStream out) throws IOException{
      super(out);
      this.out=out;
    }
    public void close() throws IOException{
      if(out!=null){
        this.out.close();
      }
      out=null;
    }
  }
  class PassiveOutputStream extends PipedOutputStream{
    private MyPipedInputStream _sink=null;
    PassiveOutputStream(PipedInputStream in,
                        boolean resizable_buffer) throws IOException{
      super(in);
      if(resizable_buffer && (in instanceof MyPipedInputStream)) {
        this._sink=(MyPipedInputStream)in;
      }
    }
    public void write(int b) throws IOException {
      if(_sink != null) {
        _sink.checkSpace(1);
      }
      super.write(b);
    }
    public void write(byte[] b, int off, int len) throws IOException {
      if(_sink != null) {
        _sink.checkSpace(len);
      }
      super.write(b, off, len); 
    }
  }

  void setExitStatus(int status){ exitstatus=status; }
  public int getExitStatus(){ return exitstatus; }

  void setSession(Session session){
    this.session=session;
  }

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

  protected Packet genChannelOpenPacket(){
    Buffer buf=new Buffer(100);
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)90);
    buf.putString(this.type);
    buf.putInt(this.id);
    buf.putInt(this.lwsize);
    buf.putInt(this.lmpsize);
    return packet;
  }

  protected void sendChannelOpen() throws Exception {
    Session _session=getSession();
    if(!_session.isConnected()){
      throw new ExceptionC("session is down");
    }

    Packet packet = genChannelOpenPacket();
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

  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
