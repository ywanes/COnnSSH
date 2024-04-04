public class KeyExchangeDHGEX extends KeyExchange{

  private static final int SSH_MSG_KEX_DH_GEX_GROUP=               31;
  private static final int SSH_MSG_KEX_DH_GEX_INIT=                32;
  private static final int SSH_MSG_KEX_DH_GEX_REPLY=               33;
  private static final int SSH_MSG_KEX_DH_GEX_REQUEST=             34;

  static int min=1024;
  static int preferred=1024;
  int max=1024;

  private int state;

  KeyExchangeDH dh;

  byte[] V_S;
  byte[] V_C;
  byte[] I_S;
  byte[] I_C;

  private Buffer buf;
  private Packet packet;

  private byte[] p;
  private byte[] g;
  private byte[] e;

  protected String hash="sha-1";

  public void init(Session session,
		   byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception{
    this.session=session;
    this.V_S=V_S;      
    this.V_C=V_C;      
    this.I_S=I_S;      
    this.I_C=I_C;      

    try{
LoadClass.DebugPrint("..?");        
      sha=(HASH)LoadClass.getInstanceByConfig(hash);
      sha.init();
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_95");
      System.err.println(e);
    }

    buf=new Buffer();
    packet=new Packet(buf);

    try{
      Class c=LoadClass.getClassByConfig("dh");
      preferred = max = check2048(c, max); 
      dh=(KeyExchangeDH)(c.newInstance());
      dh.init();
    }
    catch(Exception e){
        LoadClass.DebugPrintException("ex_96");
      throw e;
    }

    packet.reset();
    buf.putByte((byte)SSH_MSG_KEX_DH_GEX_REQUEST);
    buf.putInt(min);
    buf.putInt(preferred);
    buf.putInt(max);
    session.write(packet); 

    if(JSch.getLogger().isEnabled(Logger.INFO)){
      JSch.getLogger().log(Logger.INFO, 
                           "SSH_MSG_KEX_DH_GEX_REQUEST("+min+"<"+preferred+"<"+max+") sent");
      JSch.getLogger().log(Logger.INFO, 
                           "expecting SSH_MSG_KEX_DH_GEX_GROUP");
    }

    state=SSH_MSG_KEX_DH_GEX_GROUP;
  }

  public boolean next(Buffer _buf) throws Exception{
    int i,j;
    switch(state){
    case SSH_MSG_KEX_DH_GEX_GROUP:
      // byte  SSH_MSG_KEX_DH_GEX_GROUP(31)
      // mpint p, safe prime
      // mpint g, generator for subgroup in GF (p)
      _buf.getInt();
      _buf.getByte();
      j=_buf.getByte();
      if(j!=SSH_MSG_KEX_DH_GEX_GROUP){
	System.err.println("type: must be SSH_MSG_KEX_DH_GEX_GROUP "+j);
	return false;
      }

      p=_buf.getMPInt();
      g=_buf.getMPInt();

      dh.setP(p);
      dh.setG(g);
      // The client responds with:
      // byte  SSH_MSG_KEX_DH_GEX_INIT(32)
      // mpint e <- g^x mod p
      //         x is a random number (1 < x < (p-1)/2)

      e=dh.getE();

      packet.reset();
      buf.putByte((byte)SSH_MSG_KEX_DH_GEX_INIT);
      buf.putMPInt(e);
      session.write(packet);

      if(JSch.getLogger().isEnabled(Logger.INFO)){
        JSch.getLogger().log(Logger.INFO, 
                             "SSH_MSG_KEX_DH_GEX_INIT sent");
        JSch.getLogger().log(Logger.INFO, 
                             "expecting SSH_MSG_KEX_DH_GEX_REPLY");
      }

      state=SSH_MSG_KEX_DH_GEX_REPLY;
      return true;
      //break;

    case SSH_MSG_KEX_DH_GEX_REPLY:
      // The server responds with:
      // byte      SSH_MSG_KEX_DH_GEX_REPLY(33)
      // string    server public host key and certificates (K_S)
      // mpint     f
      // string    signature of H
      j=_buf.getInt();
      j=_buf.getByte();
      j=_buf.getByte();
      if(j!=SSH_MSG_KEX_DH_GEX_REPLY){
	System.err.println("type: must be SSH_MSG_KEX_DH_GEX_REPLY "+j);
	return false;
      }

      K_S=_buf.getString();

      byte[] f=_buf.getMPInt();
      byte[] sig_of_H=_buf.getString();

      dh.setF(f);

      dh.checkRange();

      K=normalize(dh.getK());

      //The hash H is computed as the HASH hash of the concatenation of the
      //following:
      // string    V_C, the client's version string (CR and NL excluded)
      // string    V_S, the server's version string (CR and NL excluded)
      // string    I_C, the payload of the client's SSH_MSG_KEXINIT
      // string    I_S, the payload of the server's SSH_MSG_KEXINIT
      // string    K_S, the host key
      // uint32    min, minimal size in bits of an acceptable group
      // uint32   n, preferred size in bits of the group the server should send
      // uint32    max, maximal size in bits of an acceptable group
      // mpint     p, safe prime
      // mpint     g, generator for subgroup
      // mpint     e, exchange value sent by the client
      // mpint     f, exchange value sent by the server
      // mpint     K, the shared secret
      // This value is called the exchange hash, and it is used to authenti-
      // cate the key exchange.

      buf.reset();
      buf.putString(V_C); buf.putString(V_S);
      buf.putString(I_C); buf.putString(I_S);
      buf.putString(K_S);
      buf.putInt(min); buf.putInt(preferred); buf.putInt(max);
      buf.putMPInt(p); buf.putMPInt(g); buf.putMPInt(e); buf.putMPInt(f);
      buf.putMPInt(K);

      byte[] foo=new byte[buf.getLength()];
      buf.getByte(foo);
      sha.update(foo, 0, foo.length);

      H=sha.digest();

      // System.err.print("H -> "); dump(H, 0, H.length);

      i=0;
      j=0;
      j=((K_S[i++]<<24)&0xff000000)|((K_S[i++]<<16)&0x00ff0000)|
	((K_S[i++]<<8)&0x0000ff00)|((K_S[i++])&0x000000ff);
      String alg=Util.byte2str(K_S, i, j);
      i+=j;

      boolean result = verify(alg, K_S, i, sig_of_H);

      state=STATE_END;
      return result;
    }
    return false;
  }

  public int getState(){return state; }

  protected int check2048(Class c, int _max) throws Exception {
    KeyExchangeDH dh=(KeyExchangeDH)(c.newInstance());
    dh.init();
    byte[] foo = new byte[257];
    foo[1]=(byte)0xdd;
    foo[256]=0x73;
    dh.setP(foo);
    byte[] bar = {(byte)0x02};
    dh.setG(bar);
    try {
      dh.getE();
      _max=2048;
    }
    catch(Exception e){ 
        LoadClass.DebugPrintException("ex_97");
    }
    
    return _max;
  }
}
