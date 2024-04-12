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
  private javax.crypto.Cipher s2ccipher;
  private javax.crypto.Cipher c2scipher;
  private javax.crypto.Mac s2cmac;
  private javax.crypto.Mac c2smac;
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
  static final int buffer_margin = 32 + 64 + 32;  
  private Proxy proxy=null;
  private String hostKeyAlias=null;
  private int serverAliveInterval=0;
  private int serverAliveCountMax=1;
  protected boolean daemon_thread=false;
  private long kex_start_time=0L;
  int max_auth_tries = 6;
  int auth_failures = 0;
  String host=null;
  int port=22;
  String username=null;
  byte[] password=null;
  
  Session(String host, String username, int port, String password, int timeout){
    super();
    try{
      buf=new Buffer();
      packet=new Packet(buf);
      this.username = username;
      this.port = port;
      if(this.username==null)
        this.username=(String)(System.getProperties().get("user.name"));
      setPassword(password);
      connect(timeout);
    }catch(ExceptionC e){
      System.err.println(e.toString());
      System.exit(1);        
    }
  }

  static Socket createSocket(String host, int port) throws ExceptionC{
    Socket socket=null;
    final String _host=host;
    final int _port=port;
    final Socket[] sockp=new Socket[1];
    final Exception[] ee=new Exception[1];
    Thread tmp=new Thread(new Runnable(){
        public void run(){
            try{
                sockp[0]=new Socket(_host, _port);
            }catch(Exception eee){}
        }
    });
    tmp.start();    
    try{
      tmp.join();
    }catch(java.lang.InterruptedException e){}
    if(sockp[0]!=null && sockp[0].isConnected()){
      socket=sockp[0];    
      return socket;
    }
    throw new ExceptionC("timeout: ", ee[0]);    
  }
  
  public void connect(int connectTimeout) throws ExceptionC{
    if(isConnected)
      throw new ExceptionC("session is already connected");
    random=new java.security.SecureRandom();
    Packet.setRandom(random);
    try	{
      int i, j;
      if(proxy==null){
        socket=createSocket(host, port);
        in=socket.getInputStream();
        out=socket.getOutputStream();
        socket.setTcpNoDelay(true);
      }
      isConnected=true;
      byte[] foo=new byte[V_C.length+1];
      System.arraycopy(V_C, 0, foo, 0, V_C.length);
      foo[foo.length-1]=(byte)'\n';
      put(foo, 0, foo.length);
      while( true ){
        i=0;
        j=0;
        while( i<buf.buffer.length ){
          j=getByte();
          if(j<0)break;
          buf.buffer[i]=(byte)j; i++; 
          if(j==10)
            break;
        }
        if( j<0 )
          throw new ExceptionC("connection is closed by foreign host");
        if( buf.buffer[i-1]==10 ){
          i--;
          if( i>0 && buf.buffer[i-1]==13 )
            i--;
        }
        if(i<=3 || ((i!=buf.buffer.length) && (buf.buffer[0]!='S' || buf.buffer[1]!='S' || buf.buffer[2]!='H' || buf.buffer[3]!='-')))
          continue;
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
        in_prompt=true;
        checkHost(host, port, kex);
        in_prompt=false;
        kex_start_time+=(System.currentTimeMillis()-tmp);
      }
      catch(ExceptionC ee){
        in_kex=false;
        in_prompt=false;
        throw ee;
      }
      send_newkeys();
      buf=read(buf);
      if(buf.getCommand()==SSH_MSG_NEWKEYS){
	receive_newkeys(buf, kex);
      }else{
        in_kex=false;
	throw new ExceptionC("invalid protocol(newkyes): "+buf.getCommand());
      }
      try{
        packet.reset();
        buf.putByte((byte)Session.SSH_MSG_SERVICE_REQUEST);
        buf.putString(str2byte("ssh-userauth"));
        write(packet);    
        read(buf);        
      }catch(Exception e){ 
        throw new ExceptionC(e.toString(), e);
      }

      int SSH_MSG_USERAUTH_REQUEST=50;
      int SSH_MSG_USERAUTH_FAILURE=51;
      int SSH_MSG_USERAUTH_BANNER=53;
      int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ=60;
      if(password == null)
        throw new Exception("Error AuthCancel - not found password");      
      if(auth_failures >= max_auth_tries)
        return;
      packet.reset();
      buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
      buf.putString(str2byte(username));
      buf.putString(str2byte("ssh-connection"));
      buf.putString(str2byte("password"));
      buf.putByte((byte)0);
      buf.putString(password);
      write(packet);
      buf=read(buf);
      int command=buf.getCommand()&0xff;
      if(command==SSH_MSG_USERAUTH_BANNER)
        throw new Exception("USERAUTH_BANNER");
      if(command==SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
        throw new Exception("Stop - USERAUTH_PASSWD_CHANGEREQ");
      if(command==SSH_MSG_USERAUTH_FAILURE)
        throw new Exception("UserAuth Fail!");        
      
      if(socket!=null && (connectTimeout>0 || timeout>0))
        socket.setSoTimeout(timeout);
      isAuthed=true;
      synchronized(lock){
        if(isConnected){
          connectThread=new Thread(this);
          connectThread.setName("Connect thread "+host+" session");
          if(daemon_thread)
            connectThread.setDaemon(daemon_thread);
          connectThread.start();
        }
      }
    }catch(Exception e){
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
      if(e instanceof RuntimeException) throw (RuntimeException)e;
      if(e instanceof ExceptionC) throw (ExceptionC)e;
      throw new ExceptionC("Session.connect: "+e);
    }
  }

  private ECDH521 receive_kexinit(Buffer buf) throws Exception {
    int j=buf.getInt();
    if(j!=buf.getLength()){
      buf.getByte();
      I_S=new byte[buf.index-5];
    }else
      I_S=new byte[j-1-buf.getByte()];
    System.arraycopy(buf.buffer, buf.s, I_S, 0, I_S.length);
    if(!in_kex)
      send_kexinit();
    guess=ECDH521.guess(I_S, I_C);
    if(guess==null)
      throw new ExceptionC("Algorithm negotiation fail");
    if(!isAuthed && (guess[ECDH521.PROPOSAL_ENC_ALGS_CTOS].equals("none") || (guess[ECDH521.PROPOSAL_ENC_ALGS_STOC].equals("none"))))
      throw new ExceptionC("NONE Cipher should not be chosen before authentification is successed.");
    ECDH521 kex=new ECDH521();
    kex.init(this, V_S, V_C, I_S, I_C);
    return kex;
  }
  private volatile boolean in_kex=false;
  private volatile boolean in_prompt=false;
  public void rekey() throws Exception {
    send_kexinit();
  }

  static String diffString(String str, String[] not_available){
    String[] stra=str.split(",");
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

    in_kex=true;
    kex_start_time=System.currentTimeMillis();
    Buffer buf = new Buffer();
    Packet packet = new Packet(buf);
    packet.reset();
    buf.putByte((byte) SSH_MSG_KEXINIT);
    synchronized(random){
      //random fill
      int start_fill=buf.index;
      int len_fill=16;
      byte[] tmp_fill=new byte[16];
      if(len_fill>tmp_fill.length){ tmp_fill=new byte[len_fill]; }
      random.nextBytes(tmp_fill);
      System.arraycopy(tmp_fill, 0, buf.buffer, start_fill, len_fill);
      buf.skip(16);
    }
    
    buf.putString(str2byte("ecdh-sha2-nistp521"));
    buf.putString(str2byte("ssh-rsa,ecdsa-sha2-nistp521"));
    buf.putString(str2byte("aes256-ctr"));
    buf.putString(str2byte("aes256-ctr"));
    buf.putString(str2byte("hmac-sha1"));
    buf.putString(str2byte("hmac-sha1"));
    buf.putString(str2byte("none"));
    buf.putString(str2byte("none"));
    buf.putString(str2byte(""));
    buf.putString(str2byte(""));
    buf.putByte((byte)0);
    buf.putInt(0);
    buf.setOffSet(5);
    I_C=new byte[buf.getLength()];
    buf.getByte(I_C, 0, I_C.length);
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
    if(hostKeyAlias==null && port!=22)
      chost=("["+chost+"]:"+port);
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
      byte [] tmp=new byte[4];
      tmp[0] = (byte)(seqo>>>24);
      tmp[1] = (byte)(seqo>>>16);
      tmp[2] = (byte)(seqo>>>8);
      tmp[3] = (byte)seqo;
      c2smac.update(tmp, 0, 4);
      c2smac.update(packet.buffer.buffer, 0, packet.buffer.index);
      c2smac.doFinal(packet.buffer.buffer, packet.buffer.index);
    }
    if(c2scipher!=null){
      byte[] buf=packet.buffer.buffer;
      c2scipher.update(buf, 0, packet.buffer.index, buf, 0);
    }
    if(c2smac!=null){
      packet.buffer.skip(20);
    }
  }

  private int s2ccipher_size=8;
  private int c2scipher_size=8;
  public Buffer read(Buffer buf) throws Exception{
    int j=0;
    while(true){
      buf.reset();
      getByte(buf.buffer, buf.index, s2ccipher_size); 
      buf.index+=s2ccipher_size;
      if(s2ccipher!=null)
        s2ccipher.update(buf.buffer, 0, s2ccipher_size, buf.buffer, 0);
      j=((buf.buffer[0]<<24)&0xff000000)|((buf.buffer[1]<<16)&0x00ff0000)|((buf.buffer[2]<< 8)&0x0000ff00)|((buf.buffer[3]    )&0x000000ff);
      int need = j+4-s2ccipher_size;
      if((buf.index+need)>buf.buffer.length){
        byte[] foo=new byte[buf.index+need];
        System.arraycopy(buf.buffer, 0, foo, 0, buf.index);
        buf.buffer=foo;
      }
      if(need>0){
	getByte(buf.buffer, buf.index, need); buf.index+=(need);
	if(s2ccipher!=null){
	  s2ccipher.update(buf.buffer, s2ccipher_size, need, buf.buffer, s2ccipher_size);
	}
      }
      if(s2cmac!=null){
        byte [] tmp=new byte[4];
        tmp[0] = (byte)(seqi>>>24);
        tmp[1] = (byte)(seqi>>>16);
        tmp[2] = (byte)(seqi>>>8);
        tmp[3] = (byte)seqi;
        s2cmac.update(tmp, 0, 4);
	s2cmac.update(buf.buffer, 0, buf.index);
        s2cmac.doFinal(s2cmac_result1, 0);
	getByte(s2cmac_result2, 0, s2cmac_result2.length);
        if(!java.util.Arrays.equals(s2cmac_result1, s2cmac_result2)){
          if(need > PACKET_MAX_SIZE)
            throw new IOException("MAC Error");
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
	throw new ExceptionC("SSH_MSG_DISCONNECT: "+reason_code+" "+byte2str(description)+" "+byte2str(language_tag));
      }else if(type==SSH_MSG_IGNORE){
      }else if(type==SSH_MSG_UNIMPLEMENTED){
        buf.rewind();
        buf.getInt();
        buf.getShort();
	buf.getInt();
      }else if(type==SSH_MSG_DEBUG){
        buf.rewind();
        buf.getInt();
        buf.getShort();
      }else if(type==SSH_MSG_CHANNEL_WINDOW_ADJUST){
          buf.rewind();
          buf.getInt();
          buf.getShort();          
	  Channel c=Channel.getChannel(buf.getInt(), this);
	  if(c!=null)
	    c.addRemoteWindowSize(buf.getUInt()); 
      }else{
        isAuthed=true;
        break;
      }
    }
    buf.rewind();
    return buf;
  }

  private void receive_newkeys(Buffer buf, ECDH521 kex) throws Exception {
    in_kex=false;
    byte[] K=kex.getK();
    byte[] H=kex.getH();
    java.security.MessageDigest sha512=kex.getHash();
    if(session_id==null){
      session_id=new byte[H.length];
      System.arraycopy(H, 0, session_id, 0, H.length);
    }
    buf.reset();
    buf.putMPInt(K);
    buf.putByte(H);
    buf.putByte((byte)0x41);
    buf.putByte(session_id);
    sha512.update(buf.buffer, 0, buf.index);
    IVc2s=sha512.digest();
    int j=buf.index-session_id.length-1;
    buf.buffer[j]++;
    sha512.update(buf.buffer, 0, buf.index);
    IVs2c=sha512.digest();
    buf.buffer[j]++;
    sha512.update(buf.buffer, 0, buf.index);
    Ec2s=sha512.digest();
    buf.buffer[j]++;
    sha512.update(buf.buffer, 0, buf.index);
    Es2c=sha512.digest();
    buf.buffer[j]++;
    sha512.update(buf.buffer, 0, buf.index);
    MACc2s=sha512.digest();
    buf.buffer[j]++;
    sha512.update(buf.buffer, 0, buf.index);
    MACs2c=sha512.digest();
    try{
      String method;
      method=guess[ECDH521.PROPOSAL_ENC_ALGS_STOC];
      while(32>Es2c.length){
        buf.reset();
        buf.putMPInt(K);
        buf.putByte(H);
        buf.putByte(Es2c);
        sha512.update(buf.buffer, 0, buf.index);
        byte[] foo=sha512.digest();
        byte[] bar=new byte[Es2c.length+foo.length];
	System.arraycopy(Es2c, 0, bar, 0, Es2c.length);
	System.arraycopy(foo, 0, bar, Es2c.length, foo.length);
	Es2c=bar;
      }
      byte[] tmp;
      if(IVs2c.length>16){
        tmp=new byte[16];
        System.arraycopy(IVs2c, 0, tmp, 0, tmp.length);
        IVs2c=tmp;
      }
      if(Es2c.length>32){
        tmp=new byte[32];
        System.arraycopy(Es2c, 0, tmp, 0, tmp.length);
        Es2c=tmp;
      }      
      s2ccipher=javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
      synchronized(javax.crypto.Cipher.class){
        s2ccipher.init(javax.crypto.Cipher.DECRYPT_MODE,new javax.crypto.spec.SecretKeySpec(Es2c, "AES"), new javax.crypto.spec.IvParameterSpec(IVs2c));
      }
      s2ccipher_size=16;
      method=guess[ECDH521.PROPOSAL_MAC_ALGS_STOC];
      if(MACs2c.length>20){
        byte[] tmp2 = new byte[20];
        System.arraycopy(MACs2c, 0, tmp2, 0, 20);	  
        MACs2c = tmp2;
      }
      s2cmac = javax.crypto.Mac.getInstance("HmacSHA1");
      s2cmac.init(new javax.crypto.spec.SecretKeySpec(MACs2c, "HmacSHA1"));
      s2cmac_result1=new byte[20];
      s2cmac_result2=new byte[20];
      method=guess[ECDH521.PROPOSAL_ENC_ALGS_CTOS];
      while(32>Ec2s.length){
        buf.reset();
        buf.putMPInt(K);
        buf.putByte(H);
        buf.putByte(Ec2s);
        sha512.update(buf.buffer, 0, buf.index);
        byte[] foo=sha512.digest();
        byte[] bar=new byte[Ec2s.length+foo.length];
	System.arraycopy(Ec2s, 0, bar, 0, Ec2s.length);
	System.arraycopy(foo, 0, bar, Ec2s.length, foo.length);
	Ec2s=bar;
      }
      byte[] tmp3;
      if(IVc2s.length>16){
        tmp3=new byte[16];
        System.arraycopy(IVc2s, 0, tmp3, 0, tmp3.length);
        IVc2s=tmp3;
      }
      if(Ec2s.length>32){
        tmp3=new byte[32];
        System.arraycopy(Ec2s, 0, tmp3, 0, tmp3.length);
        Ec2s=tmp3;
      }      
      c2scipher=javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
      synchronized(javax.crypto.Cipher.class){
        c2scipher.init(javax.crypto.Cipher.ENCRYPT_MODE,new javax.crypto.spec.SecretKeySpec(Ec2s, "AES"), new javax.crypto.spec.IvParameterSpec(IVc2s));
      }
      c2scipher_size=16;
      if(MACc2s.length>20){
        byte[] tmp4 = new byte[20];
        System.arraycopy(MACc2s, 0, tmp4, 0, 20);	  
        MACc2s = tmp4;
      }
      c2smac = javax.crypto.Mac.getInstance("HmacSHA1");
      c2smac.init(new javax.crypto.spec.SecretKeySpec(MACc2s, "HmacSHA1"));
      
    }catch(Exception e){ 
      System.out.println("ex_149");
      if(e instanceof ExceptionC)
        throw e;
      throw new ExceptionC(e.toString(), e);       
    }
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
                           (c2smac!=null ? 20 : 0));
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
            channel.put(foo, start[0], length[0]);
          }catch(Exception e){
            System.out.println("ex_150");
            try{channel.disconnect();}catch(Exception ee){}
            break;
          }
	  //int len=length[0];
	  //channel.setLocalWindowSize(channel.lwsize-len);
	  break;
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
          buf.getInt();
	  buf.getShort();
	  i=buf.getInt();
	  channel=Channel.getChannel(i, this);
	  buf.getInt();
	  foo=buf.getString(start, length);
	  if(channel==null)
	    break;
          if(length[0]==0)
	    break;
	  channel.put_ext(foo, start[0], length[0]);
	  //len=length[0];
	  //channel.setLocalWindowSize(channel.lwsize-len);
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
      System.out.println("ex_151 " + e.toString());
      in_kex=false;
    }
    try{
      disconnect();
    //}catch(NullPointerException e){
    }catch(Exception e){
      System.out.println("ex_152");      
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
        System.out.println("ex_153");
    }
    socket=null;
  }

  public void setProxy(Proxy proxy){ this.proxy=proxy; }
  public void setHost(String host){ this.host=host; }
  public void setPort(int port){ this.port=port; }
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
        System.out.println("ex_156");
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
  public void put(Packet p) throws IOException, java.net.SocketException {
    out.write(p.buffer.buffer, 0, p.buffer.index);
    out.flush();
  }
  void put(byte[] array, int begin, int length) throws IOException {
    out.write(array, begin, length);
    out.flush();
  }
  int getByte() throws IOException {
    return in.read();
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
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
