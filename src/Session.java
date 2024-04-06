import java.io.*;
import java.net.*;
import java.util.Vector;
public class Session implements Runnable{
  static final int SSH_MSG_DISCONNECT=                      1;
  static final int SSH_MSG_IGNORE=                          2;
  static final int SSH_MSG_UNIMPLEMENTED=                   3;
  static final int SSH_MSG_DEBUG=                           4;
  static final int SSH_MSG_SERVICE_REQUEST=                 5;
  static final int SSH_MSG_KEXINIT=                        20;
  static final int SSH_MSG_NEWKEYS=                        21;
  static final int SSH_MSG_KEXDH_INIT=                     30;
  static final int SSH_MSG_KEXDH_REPLY=                    31;
  static final int SSH_MSG_KEX_DH_GEX_GROUP=               31;
  static final int SSH_MSG_KEX_DH_GEX_INIT=                32;
  static final int SSH_MSG_KEX_DH_GEX_REPLY=               33;
  static final int SSH_MSG_KEX_DH_GEX_REQUEST=             34;
  static final int SSH_MSG_GLOBAL_REQUEST=                 80;
  static final int SSH_MSG_REQUEST_SUCCESS=                81;
  static final int SSH_MSG_REQUEST_FAILURE=                82;
  static final int SSH_MSG_CHANNEL_OPEN=                   90;
  static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION=      91;
  static final int SSH_MSG_CHANNEL_OPEN_FAILURE=           92;
  static final int SSH_MSG_CHANNEL_WINDOW_ADJUST=          93;
  static final int SSH_MSG_CHANNEL_DATA=                   94;
  static final int SSH_MSG_CHANNEL_EXTENDED_DATA=          95;
  static final int SSH_MSG_CHANNEL_EOF=                    96;
  static final int SSH_MSG_CHANNEL_CLOSE=                  97;
  static final int SSH_MSG_CHANNEL_REQUEST=                98;
  static final int SSH_MSG_CHANNEL_SUCCESS=                99;
  static final int SSH_MSG_CHANNEL_FAILURE=               100;
  private static final int PACKET_MAX_SIZE = 256 * 1024;
  private byte[] V_S;                                 
  private byte[] V_C=str2byte("SSH-2.0-JSCH-0.1.54");
  private byte[] I_C;
  private byte[] I_S;
  private byte[] session_id;
  private byte[] IVc2s;
  private byte[] IVs2c;
  private byte[] Ec2s;
  private byte[] Es2c;
  private byte[] MACc2s;
  private byte[] MACs2c;
  private int seqi=0;
  private int seqo=0;
  String[] guess=null;
  private AES256CTR s2ccipher;
  private AES256CTR c2scipher;
  private HmacSHA1 s2cmac;
  private HmacSHA1 c2smac;
  private byte[] s2cmac_result1;
  private byte[] s2cmac_result2;
  private Socket socket;
  private int timeout=0;
  private volatile boolean isConnected=false;
  private boolean isAuthed=false;
  private Thread connectThread=null;
  private Object lock=new Object();
  boolean x11_forwarding=false;
  boolean agent_forwarding=false;
  InputStream in=null;
  OutputStream out=null;
  OutputStream out_ext=null;
  private boolean in_dontclose=false;
  private boolean out_dontclose=false;
  private boolean out_ext_dontclose=false;
  static java.security.SecureRandom random;
  Buffer buf;
  Packet packet;
  static final int buffer_margin = 32 + 
                                   64 + 
                                   32;  

  private java.util.Hashtable config=null;
  private Proxy proxy=null;
  private String hostKeyAlias=null;
  private int serverAliveInterval=0;
  private int serverAliveCountMax=1;
  protected boolean daemon_thread=false;
  private long kex_start_time=0L;
  int max_auth_tries = 6;
  int auth_failures = 0;
  String host="127.0.0.1";
  String org_host="127.0.0.1";
  int port=22;
  String username=null;
  byte[] password=null;
  
  Session(String host, String username, int port) throws ExceptionC{
    super();
    buf=new Buffer();
    packet=new Packet(buf);
    this.username = username;
    this.org_host = this.host = host;
    this.port = port;

    if(this.username==null) {
      try {
        this.username=(String)(System.getProperties().get("user.name"));
      }catch(SecurityException e){}
    }
    if(this.username==null) 
      throw new ExceptionC("username is not given.");
  }

  public void connect() throws ExceptionC{
    connect(timeout);
  }

  static Socket createSocket(String host, int port, int timeout) throws ExceptionC{
    Socket socket=null;
    if(timeout==0){
      try{
        socket=new Socket(host, port);
        return socket;
      }
      catch(Exception e){
          AConfig.DebugPrintException("ex_162");
        String message=e.toString();
        if(e instanceof Throwable)
          throw new ExceptionC(message, (Throwable)e);
        throw new ExceptionC(message);
      }
    }
    final String _host=host;
    final int _port=port;
    final Socket[] sockp=new Socket[1];
    final Exception[] ee=new Exception[1];
    String message="";
    Thread tmp=new Thread(new Runnable(){
        public void run(){
          sockp[0]=null;
          try{
            sockp[0]=new Socket(_host, _port);
          }
          catch(Exception e){
              AConfig.DebugPrintException("ex_163");
            ee[0]=e;
            if(sockp[0]!=null && sockp[0].isConnected()){
              try{
                sockp[0].close();
              }
              catch(Exception eee){}
            }
            sockp[0]=null;
          }
        }
      });
    tmp.setName("Opening Socket "+host);
    tmp.start();
    try{ 
      tmp.join(timeout);
      message="timeout: ";
    }
    catch(java.lang.InterruptedException eee){
    }
    if(sockp[0]!=null && sockp[0].isConnected()){
      socket=sockp[0];
    }
    else{
      message+="socket is not established";
      if(ee[0]!=null){
        message=ee[0].toString();
      }
      tmp.interrupt();
      tmp=null;
      throw new ExceptionC(message, ee[0]);
    }
    return socket;
  } 
  
  public void connect(int connectTimeout) throws ExceptionC{
    if(isConnected){
      throw new ExceptionC("session is already connected");
    }

    if(random==null){
      try{
        random=new java.security.SecureRandom();
      }
      catch(Exception e){ 
          AConfig.DebugPrintException("ex_144");
        throw new ExceptionC(e.toString(), e);
      }
    }
    Packet.setRandom(random);
    try	{
      int i, j;

      if(proxy==null){
        socket=createSocket(host, port, connectTimeout);
        in=socket.getInputStream();
        out=socket.getOutputStream();
        socket.setTcpNoDelay(true);
      }

      if(connectTimeout>0 && socket!=null){
        socket.setSoTimeout(connectTimeout);
      }
      isConnected=true;
      byte[] foo=new byte[V_C.length+1];
      System.arraycopy(V_C, 0, foo, 0, V_C.length);
      foo[foo.length-1]=(byte)'\n';
      put(foo, 0, foo.length);

      while(true){
        i=0;
        j=0;
        while(i<buf.buffer.length){
          j=getByte();
          if(j<0)break;
          buf.buffer[i]=(byte)j; i++; 
          if(j==10)break;
        }
        if(j<0)
          throw new ExceptionC("connection is closed by foreign host");
        if(buf.buffer[i-1]==10){
          i--;
          if(i>0 && buf.buffer[i-1]==13)
            i--;
        }
        if(i<=3 
            || ((i!=buf.buffer.length) &&
            (buf.buffer[0]!='S'||buf.buffer[1]!='S'||
             buf.buffer[2]!='H'||buf.buffer[3]!='-'))){
          continue;
        }
        if(i==buf.buffer.length ||
           i<7 ||                                      
           (buf.buffer[4]=='1' && buf.buffer[6]!='9')  
        )
          throw new ExceptionC("invalid server's version string");
        break;
      }
      V_S=new byte[i]; System.arraycopy(buf.buffer, 0, V_S, 0, i);
      send_kexinit();
      buf=read(buf);
      if(buf.getCommand()!=SSH_MSG_KEXINIT){
        in_kex=false;
	throw new ExceptionC("invalid protocol: "+buf.getCommand());
      }
      ECDH521 kex=receive_kexinit(buf);
      while(true){
	buf=read(buf);
	if(kex.getState()==buf.getCommand()){
          kex_start_time=System.currentTimeMillis();
          boolean result=kex.next(buf);
	  if(!result){
            in_kex=false;
	    throw new ExceptionC("verify: "+result);
	  }
	}else{
          in_kex=false;
	  throw new ExceptionC("invalid protocol(kex): "+buf.getCommand());
	}
	if(kex.getState()==ECDH521.STATE_END)
	  break;
      }

      try{
        long tmp=System.currentTimeMillis();
        in_prompt = true;
        checkHost(host, port, kex);
        in_prompt = false;
        kex_start_time+=(System.currentTimeMillis()-tmp);
      }
      catch(ExceptionC ee){
        in_kex=false;
        in_prompt = false;
        throw ee;
      }

      send_newkeys();

      // receive SSH_MSG_NEWKEYS(21)
      buf=read(buf);
      //System.err.println("read: 21 ? "+buf.getCommand());
      if(buf.getCommand()==SSH_MSG_NEWKEYS){
	receive_newkeys(buf, kex);
      }else{
        in_kex=false;
	throw new ExceptionC("invalid protocol(newkyes): "+buf.getCommand());
      }
      try{
        String s = AConfig.getNameByConfig("MaxAuthTries");
        if(s!=null){
          max_auth_tries = Integer.parseInt(s);
        }
      }
      catch(NumberFormatException e){
        throw new ExceptionC("MaxAuthTries: "+AConfig.getNameByConfig("MaxAuthTries"), e);
      }

      boolean auth=false;
      boolean auth_cancel=false;

      UserAuth ua=null;
      try{
        ua = new UserAuthNone();        
      }
      catch(Exception e){ 
          AConfig.DebugPrintException("ex_145");
        throw new ExceptionC(e.toString(), e);
      }

      auth=ua.start(this);

      String cmethods=AConfig.getNameByConfig("PreferredAuthentications");

      String[] cmethoda=split(cmethods, ",");

      String smethods=null;
      if(!auth){
        smethods=((UserAuthNone)ua).getMethods();
        if(smethods!=null){
          smethods=smethods.toLowerCase();
        }
        else{
          // methods: publickey,password,keyboard-interactive
          //smethods="publickey,password,keyboard-interactive";
          smethods=cmethods;
        }
      }

      String[] smethoda=split(smethods, ",");

      int methodi=0;

      loop:
      while(true){

	while(!auth && 
	      cmethoda!=null && methodi<cmethoda.length){

          String method=cmethoda[methodi++];
          boolean acceptable=false;
          for(int k=0; k<smethoda.length; k++){
            if(smethoda[k].equals(method)){
              acceptable=true;
              break;
            }
          }
          if(!acceptable)
            continue;
	  ua=null;
          if ( method.equals("password") ){
            if ( method.equals("password") )
              ua = new UserAuthPassword();
            if ( method.equals("none") )
              ua = new UserAuthNone();
            auth_cancel=false;
	    try{ 
	      auth=ua.start(this); 
	    }catch(RuntimeException ee){
	      throw ee;
	    }catch(ExceptionC ee){
              throw ee;
	    }catch(Exception ee){
              break loop;
	    }
          }
	}
        break;
      }

      if(!auth){
        if(auth_cancel)
          throw new ExceptionC("Auth cancel");
        throw new ExceptionC("Auth fail");
      }
      if(socket!=null && (connectTimeout>0 || timeout>0))
        socket.setSoTimeout(timeout);
      isAuthed=true;
      synchronized(lock){
        if(isConnected){
          connectThread=new Thread(this);
          connectThread.setName("Connect thread "+host+" session");
          if(daemon_thread){
            connectThread.setDaemon(daemon_thread);
          }
          connectThread.start();
        }
        else{
          // The session has been already down and
          // we don't have to start new thread.
        }
      }
    }
    catch(Exception e) {
      in_kex=false;
      try{
        if(isConnected){
          String message = e.toString();
          packet.reset();
          buf.checkFreeSize(1+4*3+message.length()+2+buffer_margin);
          buf.putByte((byte)SSH_MSG_DISCONNECT);
          buf.putInt(3);
          buf.putString(str2byte(message));
          buf.putString(str2byte("en"));
          write(packet);
        }
      }
      catch(Exception ee){}
      try{ disconnect(); } catch(Exception ee){ }
      isConnected=false;
      //e.printStackTrace();
      if(e instanceof RuntimeException) throw (RuntimeException)e;
      if(e instanceof ExceptionC) throw (ExceptionC)e;
      throw new ExceptionC("Session.connect: "+e);
    }
    finally{
    }
  }

  static String[] split(String foo, String split){
    if(foo==null)
      return null;
    byte[] buf=str2byte(foo);
    java.util.Vector bar=new java.util.Vector();
    int start=0;
    int index;
    while(true){
      index=foo.indexOf(split, start);
      if(index>=0){
	bar.addElement(byte2str(buf, start, index-start));
	start=index+1;
	continue;
      }
      bar.addElement(byte2str(buf, start, buf.length-start));
      break;
    }
    String[] result=new String[bar.size()];
    for(int i=0; i<result.length; i++){
      result[i]=(String)(bar.elementAt(i));
    }
    return result;
  }
  
  private ECDH521 receive_kexinit(Buffer buf) throws Exception {
    int j=buf.getInt();
    if(j!=buf.getLength()){    // packet was compressed and
      buf.getByte();           // j is the size of deflated packet.
      I_S=new byte[buf.index-5];
    }
    else{
      I_S=new byte[j-1-buf.getByte()];
    }
   System.arraycopy(buf.buffer, buf.s, I_S, 0, I_S.length);

   if(!in_kex){     // We are in rekeying activated by the remote!
     send_kexinit();
   }

    guess=ECDH521.guess(I_S, I_C);
    if(guess==null){
      throw new ExceptionC("Algorithm negotiation fail");
    }

    if(!isAuthed &&
       (guess[ECDH521.PROPOSAL_ENC_ALGS_CTOS].equals("none") ||
        (guess[ECDH521.PROPOSAL_ENC_ALGS_STOC].equals("none")))){
      throw new ExceptionC("NONE Cipher should not be chosen before authentification is successed.");
    }

    ECDH521 kex=null;
    try{
      kex=new ECDH521();
    }
    catch(Exception e){ 
        AConfig.DebugPrintException("ex_147");
      throw new ExceptionC(e.toString(), e);
    }

    kex.init(this, V_S, V_C, I_S, I_C);
    return kex;
  }

  private volatile boolean in_kex=false;
  private volatile boolean in_prompt=false;
  public void rekey() throws Exception {
    send_kexinit();
  }

  static String diffString(String str, String[] not_available){
    String[] stra=split(str, ",");
    String result=null;
    loop:
    for(int i=0; i<stra.length; i++){
      for(int j=0; j<not_available.length; j++){
        if(stra[i].equals(not_available[j])){
          continue loop;
        }
      }
      if(result==null){ result=stra[i]; }
      else{ result=result+","+stra[i]; }
    }
    return result;
  }
  
  private void send_kexinit() throws Exception {
    if(in_kex)
      return;

    String cipherc2s=AConfig.getNameByConfig("cipher.c2s");
    String ciphers2c=AConfig.getNameByConfig("cipher.s2c");

    String[] not_available_ciphers=checkCiphers(AConfig.getNameByConfig("CheckCiphers"));
    if(not_available_ciphers!=null && not_available_ciphers.length>0){
      cipherc2s=diffString(cipherc2s, not_available_ciphers);
      ciphers2c=diffString(ciphers2c, not_available_ciphers);
      if(cipherc2s==null || ciphers2c==null){
        throw new ExceptionC("There are not any available ciphers.");
      }
    }

    String kex=AConfig.getNameByConfig("kex");
    String[] not_available_kexes=checkKexes(AConfig.getNameByConfig("CheckKexes"));
    if(not_available_kexes!=null && not_available_kexes.length>0){
      kex=diffString(kex, not_available_kexes);
      if(kex==null){
        throw new ExceptionC("There are not any available kexes.");
      }
    }

    String server_host_key = AConfig.getNameByConfig("server_host_key");
    String[] not_available_shks =
      checkSignatures(AConfig.getNameByConfig("CheckSignatures"));
    if(not_available_shks!=null && not_available_shks.length>0){
      server_host_key=diffString(server_host_key, not_available_shks);
      if(server_host_key==null){
        throw new ExceptionC("There are not any available sig algorithm.");
      }
    }
    in_kex=true;
    kex_start_time=System.currentTimeMillis();
    Buffer buf = new Buffer();                // send_kexinit may be invoked
    Packet packet = new Packet(buf);          // by user thread.
    packet.reset();
    buf.putByte((byte) SSH_MSG_KEXINIT);
    synchronized(random){
      //random fill
      byte[] foo_fill=buf.buffer;
      int start_fill=buf.index;
      int len_fill=16;
      byte[] tmp_fill=new byte[16];
      if(len_fill>tmp_fill.length){ tmp_fill=new byte[len_fill]; }
      random.nextBytes(tmp_fill);
      System.arraycopy(tmp_fill, 0, foo_fill, start_fill, len_fill);
      buf.skip(16);
    }
    buf.putString(str2byte(kex));
    buf.putString(str2byte(server_host_key));
    buf.putString(str2byte(cipherc2s));
    buf.putString(str2byte(ciphers2c));
    buf.putString(str2byte(AConfig.getNameByConfig("mac.c2s")));
    buf.putString(str2byte(AConfig.getNameByConfig("mac.s2c")));
    buf.putString(str2byte(AConfig.getNameByConfig("compression.c2s")));
    buf.putString(str2byte(AConfig.getNameByConfig("compression.s2c")));
    buf.putString(str2byte(AConfig.getNameByConfig("lang.c2s")));
    buf.putString(str2byte(AConfig.getNameByConfig("lang.s2c")));
    buf.putByte((byte)0);
    buf.putInt(0);
    buf.setOffSet(5);
    I_C=new byte[buf.getLength()];
    buf.getByte(I_C);
    write(packet);
  }

  private void send_newkeys() throws Exception {
    packet.reset();
    buf.putByte((byte)SSH_MSG_NEWKEYS);
    write(packet);
  }

  private void checkHost(String chost, int port, ECDH521 kex) throws ExceptionC {
    if(hostKeyAlias!=null)
      chost=hostKeyAlias;
    byte[] K_S=kex.getHostKey();
    String key_type=kex.getKeyType();
    String key_fprint=null;
    if(hostKeyAlias==null && port!=22)
      chost=("["+chost+"]:"+port);
  }

  public Channel openChannel(String type) throws ExceptionC{
    if(!isConnected){
      throw new ExceptionC("session is down");
    }
    try{
      Channel channel=new ChannelSessionShell();
      addChannel(channel);
      channel.init();
      return channel;
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_148");      
    }
    return null;
  }

  
  public void encode(Packet packet) throws Exception{
    if(c2scipher!=null){
      packet.padding(c2scipher_size);
      int pad=packet.buffer.buffer[4];
      synchronized(random){
        //random fill
        byte[] foo_fill=packet.buffer.buffer;
        int start_fill=packet.buffer.index-pad;
        int len_fill=pad;
        byte[] tmp_fill=new byte[16];
        if(len_fill>tmp_fill.length){ tmp_fill=new byte[len_fill]; }
        random.nextBytes(tmp_fill);
        System.arraycopy(tmp_fill, 0, foo_fill, start_fill, len_fill);
        
      }
    }else{
      packet.padding(8);
    }

    if(c2smac!=null){
      c2smac.update(seqo);
      c2smac.update(packet.buffer.buffer, 0, packet.buffer.index);
      c2smac.doFinal(packet.buffer.buffer, packet.buffer.index);
    }
    if(c2scipher!=null){
      byte[] buf=packet.buffer.buffer;
      c2scipher.update(buf, 0, packet.buffer.index, buf, 0);
    }
    if(c2smac!=null){
      packet.buffer.skip(c2smac.getBlockSize());
    }
  }

  int[] uncompress_len=new int[1];
  int[] compress_len=new int[1];

  private int s2ccipher_size=8;
  private int c2scipher_size=8;
  public Buffer read(Buffer buf) throws Exception{
    int j=0;
    while(true){
      buf.reset();
      getByte(buf.buffer, buf.index, s2ccipher_size); 
      buf.index+=s2ccipher_size;
      if(s2ccipher!=null){
        s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
      }
      j=((buf.buffer[0]<<24)&0xff000000)|
        ((buf.buffer[1]<<16)&0x00ff0000)|
        ((buf.buffer[2]<< 8)&0x0000ff00)|
        ((buf.buffer[3]    )&0x000000ff);
      // RFC 4253 6.1. Maximum Packet Length
      if(j<5 || j>PACKET_MAX_SIZE){
        start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE);
      }
      int need = j+4-s2ccipher_size;
      if((buf.index+need)>buf.buffer.length){
        byte[] foo=new byte[buf.index+need];
        System.arraycopy(buf.buffer, 0, foo, 0, buf.index);
        buf.buffer=foo;
      }

      if((need%s2ccipher_size)!=0){
        String message="Bad packet length "+need;
        start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE-s2ccipher_size);
      }

      if(need>0){
	getByte(buf.buffer, buf.index, need); buf.index+=(need);
	if(s2ccipher!=null){
	  s2ccipher.update(buf.buffer, s2ccipher_size, need, buf.buffer, s2ccipher_size);
	}
      }

      if(s2cmac!=null){
	s2cmac.update(seqi);
	s2cmac.update(buf.buffer, 0, buf.index);
        s2cmac.doFinal(s2cmac_result1, 0);
        // text terminal
	getByte(s2cmac_result2, 0, s2cmac_result2.length);
        if(!java.util.Arrays.equals(s2cmac_result1, s2cmac_result2)){
          if(need > PACKET_MAX_SIZE){
            throw new IOException("MAC Error");
          }
          start_discard(buf, s2ccipher, s2cmac, j, PACKET_MAX_SIZE-need);
          continue;
	}
      }
      seqi++;
      int type=buf.getCommand()&0xff;
      if(type==SSH_MSG_DISCONNECT){
        buf.rewind();
        buf.getInt();buf.getShort();
	int reason_code=buf.getInt();
	byte[] description=buf.getString();
	byte[] language_tag=buf.getString();
	throw new ExceptionC("SSH_MSG_DISCONNECT: "+
				    reason_code+
				" "+byte2str(description)+
				" "+byte2str(language_tag));
      }
      else if(type==SSH_MSG_IGNORE){
      }
      else if(type==SSH_MSG_UNIMPLEMENTED){
        buf.rewind();
        buf.getInt();buf.getShort();
	int reason_id=buf.getInt();
      }
      else if(type==SSH_MSG_DEBUG){
        buf.rewind();
        buf.getInt();buf.getShort();
      }
      else if(type==SSH_MSG_CHANNEL_WINDOW_ADJUST){
          buf.rewind();
          buf.getInt();buf.getShort();
	  Channel c=Channel.getChannel(buf.getInt(), this);
	  if(c==null){
	  }
	  else{
	    c.addRemoteWindowSize(buf.getUInt()); 
	  }
      }
      else if(type==UserAuth.SSH_MSG_USERAUTH_SUCCESS){
        isAuthed=true;
        break;
      }
      else{
        break;
      }
    }
    buf.rewind();
    return buf;
  }

  private void start_discard(Buffer buf, AES256CTR cipher, HmacSHA1 mac, 
                             int packet_length, int discard) throws ExceptionC, IOException{
    HmacSHA1 discard_mac = null;

    if(!cipher.isCBC()){
      throw new ExceptionC("Packet corrupt");
    }

    if(packet_length!=PACKET_MAX_SIZE && mac != null){
      discard_mac = mac;
    }

    discard -= buf.index;

    while(discard>0){
      buf.reset();
      int len = discard>buf.buffer.length ? buf.buffer.length : discard;
      getByte(buf.buffer, 0, len);
      if(discard_mac!=null){
        discard_mac.update(buf.buffer, 0, len);
      }
      discard -= len;
    }

    if(discard_mac!=null){
      discard_mac.doFinal(buf.buffer, 0);
    }

    throw new ExceptionC("Packet corrupt");
  }

  byte[] getSessionId(){
    return session_id;
  }

  private void receive_newkeys(Buffer buf, ECDH521 kex) throws Exception {
    in_kex=false;
    byte[] K=kex.getK();
    byte[] H=kex.getH();
    SHA512 hash=kex.getHash();
    if(session_id==null){
      session_id=new byte[H.length];
      System.arraycopy(H, 0, session_id, 0, H.length);
    }
    buf.reset();
    buf.putMPInt(K);
    buf.putByte(H);
    buf.putByte((byte)0x41);
    buf.putByte(session_id);
    hash.update(buf.buffer, 0, buf.index);
    IVc2s=hash.digest();
    int j=buf.index-session_id.length-1;
    buf.buffer[j]++;
    hash.update(buf.buffer, 0, buf.index);
    IVs2c=hash.digest();
    buf.buffer[j]++;
    hash.update(buf.buffer, 0, buf.index);
    Ec2s=hash.digest();
    buf.buffer[j]++;
    hash.update(buf.buffer, 0, buf.index);
    Es2c=hash.digest();
    buf.buffer[j]++;
    hash.update(buf.buffer, 0, buf.index);
    MACc2s=hash.digest();
    buf.buffer[j]++;
    hash.update(buf.buffer, 0, buf.index);
    MACs2c=hash.digest();
    try{
      String method;
      method=guess[ECDH521.PROPOSAL_ENC_ALGS_STOC];
      s2ccipher=new AES256CTR();
      while(s2ccipher.getBlockSize()>Es2c.length){
        buf.reset();
        buf.putMPInt(K);
        buf.putByte(H);
        buf.putByte(Es2c);
        hash.update(buf.buffer, 0, buf.index);
        byte[] foo=hash.digest();
        byte[] bar=new byte[Es2c.length+foo.length];
	System.arraycopy(Es2c, 0, bar, 0, Es2c.length);
	System.arraycopy(foo, 0, bar, Es2c.length, foo.length);
	Es2c=bar;
      }
      s2ccipher.init(AES256CTR.DECRYPT_MODE, Es2c, IVs2c);
      s2ccipher_size=s2ccipher.getIVSize();
      method=guess[ECDH521.PROPOSAL_MAC_ALGS_STOC];
      s2cmac = new HmacSHA1();
      MACs2c = expandKey(buf, K, H, MACs2c, hash, s2cmac.getBlockSize());
      s2cmac.init(MACs2c);
      s2cmac_result1=new byte[s2cmac.getBlockSize()];
      s2cmac_result2=new byte[s2cmac.getBlockSize()];
      method=guess[ECDH521.PROPOSAL_ENC_ALGS_CTOS];
      c2scipher = new AES256CTR();
      while(c2scipher.getBlockSize()>Ec2s.length){
        buf.reset();
        buf.putMPInt(K);
        buf.putByte(H);
        buf.putByte(Ec2s);
        hash.update(buf.buffer, 0, buf.index);
        byte[] foo=hash.digest();
        byte[] bar=new byte[Ec2s.length+foo.length];
	System.arraycopy(Ec2s, 0, bar, 0, Ec2s.length);
	System.arraycopy(foo, 0, bar, Ec2s.length, foo.length);
	Ec2s=bar;
      }
      c2scipher.init(AES256CTR.ENCRYPT_MODE, Ec2s, IVc2s);
      c2scipher_size=c2scipher.getIVSize();
      method=guess[ECDH521.PROPOSAL_MAC_ALGS_CTOS];
      c2smac = new HmacSHA1();
      MACc2s = expandKey(buf, K, H, MACc2s, hash, c2smac.getBlockSize());
      c2smac.init(MACc2s);
      method=guess[ECDH521.PROPOSAL_COMP_ALGS_CTOS];
      initDeflater(method);
      method=guess[ECDH521.PROPOSAL_COMP_ALGS_STOC];
      initInflater(method);
    }catch(Exception e){ 
      AConfig.DebugPrintException("ex_149");
      if(e instanceof ExceptionC)
        throw e;
      throw new ExceptionC(e.toString(), e);       
    }
  }
  private byte[] expandKey(Buffer buf, byte[] K, byte[] H, byte[] key, SHA512 hash, int required_length) throws Exception {
    byte[] result = key;
    int size = hash.getBlockSize();
    return result;
  }
  void write(Packet packet, Channel c, int length) throws Exception{
    long t = getTimeout();
    while(true){
      if(in_kex){
        if(t>0L && (System.currentTimeMillis()-kex_start_time)>t){
          throw new ExceptionC("timeout in waiting for rekeying process.");
        }
        try{Thread.sleep(10);}
        catch(java.lang.InterruptedException e){};
        continue;
      }
      synchronized(c){

        if(c.rwsize<length){
          try{ 
            c.notifyme++;
            c.wait(100); 
          }
          catch(java.lang.InterruptedException e){
          }
          finally{
            c.notifyme--;
          }
        }

        if(in_kex){
          continue;
        }

        if(c.rwsize>=length){
          c.rwsize-=length;
          break;
        }

      }
      if(c.close || !c.isConnected()){
	throw new IOException("channel is broken");
      }

      boolean sendit=false;
      int s=0;
      byte command=0;
      int recipient=-1;
      synchronized(c){
	if(c.rwsize>0){
	  long len=c.rwsize;
          if(len>length){
            len=length;
          }
          if(len!=length){
            s=packet.shift((int)len, 
                           (c2scipher!=null ? c2scipher_size : 8),
                           (c2smac!=null ? c2smac.getBlockSize() : 0));
          }
	  command=packet.buffer.getCommand();
	  recipient=c.getRecipient();
	  length-=len;
	  c.rwsize-=len;
	  sendit=true;
	}
      }
      if(sendit){
	_write(packet);
        if(length==0){
          return;
        }
	packet.unshift(command, recipient, s, length);
      }

      synchronized(c){
        if(in_kex){
          continue;
        }
        if(c.rwsize>=length){
          c.rwsize-=length;
          break;
        }
      }
    }
    _write(packet);
  }  
  public void write(Packet packet) throws Exception{
    long t = getTimeout();
    while(in_kex){
      if(t>0L &&
         (System.currentTimeMillis()-kex_start_time)>t &&
         !in_prompt
         ){
        throw new ExceptionC("timeout in waiting for rekeying process.");
      }
      byte command=packet.buffer.getCommand();
      if(command==SSH_MSG_KEXINIT ||
         command==SSH_MSG_NEWKEYS ||
         command==SSH_MSG_KEXDH_INIT ||
         command==SSH_MSG_KEXDH_REPLY ||
         command==SSH_MSG_KEX_DH_GEX_GROUP ||
         command==SSH_MSG_KEX_DH_GEX_INIT ||
         command==SSH_MSG_KEX_DH_GEX_REPLY ||
         command==SSH_MSG_KEX_DH_GEX_REQUEST ||
         command==SSH_MSG_DISCONNECT){
        break;
      }
      try{Thread.sleep(10);}
      catch(java.lang.InterruptedException e){};
    }
    _write(packet);
  }
  private void _write(Packet packet) throws Exception{
    synchronized(lock){
      encode(packet);
      put(packet);
      seqo++;
    }
  }
  Runnable thread;
  public void run(){
    thread=this;
    byte[] foo;
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    int i=0;
    Channel channel;
    int[] start=new int[1];
    int[] length=new int[1];
    ECDH521 kex=null;
    int stimeout=0;
    try{
      while(isConnected && thread!=null){
        try{
          buf=read(buf);
          stimeout=0;
        }
        catch(InterruptedIOException/*SocketTimeoutException*/ ee){
          if(!in_kex && stimeout<serverAliveCountMax){
            sendKeepAliveMsg();
            stimeout++;
            continue;
          }
          else if(in_kex && stimeout<serverAliveCountMax){
            stimeout++;
            continue;
          }
          throw ee;
        }
	int msgType=buf.getCommand()&0xff;
	if(kex!=null && kex.getState()==msgType){
          kex_start_time=System.currentTimeMillis();
	  boolean result=kex.next(buf);
	  if(!result){
	    throw new ExceptionC("verify: "+result);
	  }
	  continue;
	}
        switch(msgType){
	case SSH_MSG_KEXINIT:
	  kex=receive_kexinit(buf);
	  break;
	case SSH_MSG_NEWKEYS:
          send_newkeys();
	  receive_newkeys(buf, kex);
	  kex=null;
	  break;
	case SSH_MSG_CHANNEL_DATA:
          buf.getInt(); 
          buf.getByte(); 
          buf.getByte(); 
          i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
	  foo=buf.getString(start, length);
	  if(channel==null)
	    break;
          if(length[0]==0)
	    break;
          try{
            channel.write(foo, start[0], length[0]);
          }catch(Exception e){
            AConfig.DebugPrintException("ex_150");
            try{channel.disconnect();}catch(Exception ee){}
            break;
          }
	  int len=length[0];
	  channel.setLocalWindowSize(channel.lwsize-len);
 	  if(channel.lwsize<channel.lwsize_max/2){
            packet.reset();
	    buf.putByte((byte)SSH_MSG_CHANNEL_WINDOW_ADJUST);
	    buf.putInt(channel.getRecipient());
	    buf.putInt(channel.lwsize_max-channel.lwsize);
            synchronized(channel){
              if(!channel.close)
                write(packet);
            }
	    channel.setLocalWindowSize(channel.lwsize_max);
	  }
	  break;
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
          buf.getInt();
	  buf.getShort();
	  i=buf.getInt();
	  channel=Channel.getChannel(i, this);
	  buf.getInt();                   // data_type_code == 1
	  foo=buf.getString(start, length);
	  if(channel==null)
	    break;
          if(length[0]==0)
	    break;
	  channel.write_ext(foo, start[0], length[0]);
	  len=length[0];
	  channel.setLocalWindowSize(channel.lwsize-len);
 	  if(channel.lwsize<channel.lwsize_max/2){
            packet.reset();
	    buf.putByte((byte)SSH_MSG_CHANNEL_WINDOW_ADJUST);
	    buf.putInt(channel.getRecipient());
	    buf.putInt(channel.lwsize_max-channel.lwsize);
            synchronized(channel){
              if(!channel.close)
                write(packet);
            }
	    channel.setLocalWindowSize(channel.lwsize_max);
	  }
	  break;
	case SSH_MSG_CHANNEL_WINDOW_ADJUST:
          buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
	  if(channel==null)
	    break;
	  channel.addRemoteWindowSize(buf.getUInt()); 
	  break;
	case SSH_MSG_CHANNEL_EOF:
          buf.getInt(); 
          buf.getShort(); 
          i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
	  if(channel!=null)
	    channel.eof_remote();
	  break;
	case SSH_MSG_CHANNEL_CLOSE:
          buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
	  if(channel!=null)
	    channel.disconnect();
	  break;
	case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
          buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
          int r=buf.getInt();
          long rws=buf.getUInt();
          int rps=buf.getInt();
          if(channel!=null){
            channel.setRemoteWindowSize(rws);
            channel.setRemotePacketSize(rps);
            channel.open_confirmation=true;
            channel.setRecipient(r);
          }
          break;
	case SSH_MSG_CHANNEL_OPEN_FAILURE:
          buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
          if(channel!=null){
            int reason_code=buf.getInt(); 
            channel.setExitStatus(reason_code);
            channel.close=true;
            channel.eof_remote=true;
            channel.setRecipient(0);
          }
	  break;
	case SSH_MSG_CHANNEL_REQUEST:
          buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  foo=buf.getString(); 
          boolean reply=(buf.getByte()!=0);
	  channel=Channel.getChannel(i, this);
	  if(channel!=null){
	    byte reply_type=(byte)SSH_MSG_CHANNEL_FAILURE;
	    if((byte2str(foo)).equals("exit-status")){
	      i=buf.getInt();             // exit-status
	      channel.setExitStatus(i);
	      reply_type=(byte)SSH_MSG_CHANNEL_SUCCESS;
	    }
	    if(reply){
	      packet.reset();
	      buf.putByte(reply_type);
	      buf.putInt(channel.getRecipient());
	      write(packet);
	    }
	  }
	  break;
	case SSH_MSG_CHANNEL_OPEN:
          buf.getInt(); 
	  buf.getShort(); 
	  foo=buf.getString(); 
	  String ctyp=byte2str(foo);
          if(!"forwarded-tcpip".equals(ctyp) && !("x11".equals(ctyp) && x11_forwarding) && !("auth-agent@openssh.com".equals(ctyp) && agent_forwarding)){
	    packet.reset();
	    buf.putByte((byte)SSH_MSG_CHANNEL_OPEN_FAILURE);
	    buf.putInt(buf.getInt());
 	    buf.putInt(Channel.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
	    buf.putString((byte[])str2byte(""));
	    buf.putString((byte[])str2byte(""));
	    write(packet);
	  }
          break;
	case SSH_MSG_CHANNEL_SUCCESS:
          buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
	  if(channel==null)
	    break;
	  channel.reply=1;
	  break;
	case SSH_MSG_CHANNEL_FAILURE:
	  buf.getInt(); 
	  buf.getShort(); 
	  i=buf.getInt(); 
	  channel=Channel.getChannel(i, this);
	  if(channel==null)
	    break;
	  channel.reply=0;
	  break;
	case SSH_MSG_GLOBAL_REQUEST:
	  buf.getInt(); 
	  buf.getShort(); 
	  foo=buf.getString();
	  reply=(buf.getByte()!=0);
	  if(reply){
	    packet.reset();
	    buf.putByte((byte)SSH_MSG_REQUEST_FAILURE);
	    write(packet);
	  }
	  break;
	case SSH_MSG_REQUEST_FAILURE:
	case SSH_MSG_REQUEST_SUCCESS:
          throw new IOException("removido");
	default:
	  throw new IOException("Unknown SSH message type "+msgType);
	}
      }
    }
    catch(Exception e){
      AConfig.DebugPrintException("ex_151 " + e.toString());
      in_kex=false;
    }
    try{
      disconnect();
    }catch(NullPointerException e){
    }catch(Exception e){
      AConfig.DebugPrintException("ex_152");      
    }
    isConnected=false;
  }
  public void disconnect(){
    if(!isConnected) return;
    Channel.disconnect(this);
    isConnected=false;
    synchronized(lock){
      if(connectThread!=null){
        Thread.yield();
        connectThread.interrupt();
        connectThread=null;
      }
    }
    thread=null;
    try{
      if(in!=null) in.close();
      if(out!=null) out.close();
      if(out_ext!=null) out_ext.close();
      if(socket!=null)
        socket.close();
    }catch(Exception e){
        AConfig.DebugPrintException("ex_153");
    }
    socket=null;
  }

  private void initDeflater(String method) throws ExceptionC{
    if(method.equals("none"))
      return;
  }
  private void initInflater(String method) throws ExceptionC{
    if(method.equals("none"))
      return;
  }
  void addChannel(Channel channel){
    channel.setSession(this);
  }

  public void setProxy(Proxy proxy){ this.proxy=proxy; }
  public void setHost(String host){ this.host=host; }
  public void setPort(int port){ this.port=port; }
  void setUserName(String username){ this.username=username; }
  public void setInputStream(InputStream in){ this.in=in; }
  public void setOutputStream(OutputStream out){ this.out=out; }
  public void setPassword(String password){
    if(password!=null)
      this.password=str2byte(password);
  }
  public boolean isConnected(){ return isConnected; }
  public int getTimeout(){ return timeout; }
  public void setTimeout(int timeout) throws ExceptionC {
    if(socket==null){
      if(timeout<0){
        throw new ExceptionC("invalid timeout value");
      }
      this.timeout=timeout;
      return;
    }
    try{
      socket.setSoTimeout(timeout);
      this.timeout=timeout;
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_156");
      if(e instanceof Throwable)
        throw new ExceptionC(e.toString(), (Throwable)e);
      throw new ExceptionC(e.toString());
    }
  }
  public String getServerVersion(){
    return byte2str(V_S);
  }
  public String getClientVersion(){
    return byte2str(V_C);
  }
  public void setClientVersion(String cv){
    V_C=str2byte(cv);
  }
  public void sendIgnore() throws Exception{
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)SSH_MSG_IGNORE);
    write(packet);
  }
  private static final byte[] keepalivemsg=str2byte("keepalive@jcraft.com");
  public void sendKeepAliveMsg() throws Exception{
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)SSH_MSG_GLOBAL_REQUEST);
    buf.putString(keepalivemsg);
    buf.putByte((byte)1);
    write(packet);
  }
  private static final byte[] nomoresessions=str2byte("no-more-sessions@openssh.com");
  public void noMoreSessionChannels() throws Exception{
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte)SSH_MSG_GLOBAL_REQUEST);
    buf.putString(nomoresessions);
    buf.putByte((byte)0);
    write(packet);
  }
  
  public String getHost(){return host;}
  public String getUserName(){return username;}
  public int getPort(){return port;}
  public void setHostKeyAlias(String hostKeyAlias){
    this.hostKeyAlias=hostKeyAlias;
  }
  public String getHostKeyAlias(){
    return hostKeyAlias;
  }

  public void setServerAliveInterval(int interval) throws ExceptionC {
    setTimeout(interval);
    this.serverAliveInterval=interval;
  }

  public int getServerAliveInterval(){
    return this.serverAliveInterval;
  }

  public void setServerAliveCountMax(int count){
    this.serverAliveCountMax=count;
  }

  public int getServerAliveCountMax(){
    return this.serverAliveCountMax;
  }

  public void setDaemonThread(boolean enable){
    this.daemon_thread=enable;
  }

  private String[] checkCiphers(String ciphers){
    if(ciphers==null || ciphers.length()==0)
      return null;
    String cipherc2s=AConfig.getNameByConfig("cipher.c2s");
    String ciphers2c=AConfig.getNameByConfig("cipher.s2c");
    Vector result=new Vector();
    String[] _ciphers=split(ciphers, ",");
    for(int i=0; i<_ciphers.length; i++){
      String cipher=_ciphers[i];
      if(ciphers2c.indexOf(cipher) == -1 && cipherc2s.indexOf(cipher) == -1)
        continue; 
      if ( cipher.equals("aes256-ctr") )
        continue;
      result.addElement(cipher);
    }
    if(result.size()==0)
      return null;
    String[] foo=new String[result.size()];
    System.arraycopy(result.toArray(), 0, foo, 0, result.size());
    return foo;
  }

  static boolean checkCipher(String cipher){
    try{
      AES256CTR _c=new AES256CTR();
      _c.init(AES256CTR.ENCRYPT_MODE,
              new byte[_c.getBlockSize()],
              new byte[_c.getIVSize()]);
      return true;
    }
    catch(Exception e){
        AConfig.DebugPrintException("ex_157 " + cipher);
      return false;
    }
  }
  
  private String[] checkKexes(String kexes){
    if(kexes==null || kexes.length()==0)
      return null;
    java.util.Vector result=new java.util.Vector();
    String[] _kexes=split(kexes, ",");
    for(int i=0; i<_kexes.length; i++){
      if ( _kexes[i].equals("ecdh-sha2-nistp521") )        
        continue;
      result.addElement(_kexes[i]);
    }
    if(result.size()==0)
      return null;
    String[] foo=new String[result.size()];
    System.arraycopy(result.toArray(), 0, foo, 0, result.size());
    return foo;
  }

  private String[] checkSignatures(String sigs){
    if(sigs==null || sigs.length()==0)
      return null;
    java.util.Vector result=new java.util.Vector();
    String[] _sigs=split(sigs, ",");
    for(int i=0; i<_sigs.length; i++)
      result.addElement(_sigs[i]);
   if(result.size()==0)
      return null;
    String[] foo=new String[result.size()];
    System.arraycopy(result.toArray(), 0, foo, 0, result.size());
    return foo;
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
  int getByte() throws IOException {
    return in.read();
  }
  void getByte(byte[] array) throws IOException {
    getByte(array, 0, array.length);
  }

  void getByte(byte[] array, int begin, int length) throws IOException {
    do{
      int completed = in.read(array, begin, length);
      if(completed<0){
	throw new IOException("End of IO Stream Read");
      }
      begin+=completed;
      length-=completed;
    }
    while (length>0);
  }
  void out_close(){
    try{
      if(out!=null && !out_dontclose) out.close();
      out=null;
    }
    catch(Exception ee){}
  }
  public void close(){
    try{
      if(in!=null && !in_dontclose) in.close();
      in=null;
    }catch(Exception ee){}
    out_close();
    try{
      if(out_ext!=null && !out_ext_dontclose) out_ext.close();
      out_ext=null;
    }
    catch(Exception ee){}
  }

  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
