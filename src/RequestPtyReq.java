class RequestPtyReq extends Request{
  private String ttype="vt100";
  private int tcol=80;
  private int trow=24;
  private int twp=640;
  private int thp=480;
  private byte[] terminal_mode=(byte[])str2byte("");

  void setTType(String ttype){
    this.ttype=ttype;
  }
  
  void setTerminalMode(byte[] terminal_mode){
    this.terminal_mode=terminal_mode;
  }

  void setTSize(int tcol, int trow, int twp, int thp){
    this.tcol=tcol;
    this.trow=trow;
    this.twp=twp;
    this.thp=thp;
  }

  public void request(Session session, Channel channel) throws Exception{
    super.request(session, channel);
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(channel.getRecipient());
    buf.putString(str2byte("pty-req"));
    buf.putByte((byte)(waitForReply() ? 1 : 0));
    buf.putString(str2byte(ttype));
    buf.putInt(tcol);
    buf.putInt(trow);
    buf.putInt(twp);
    buf.putInt(thp);
    buf.putString(terminal_mode);
    write(packet);
  }
  
  static byte[] str2byte(String str){return str2byte(str, "UTF-8");}
  static String byte2str(byte[] str){return byte2str(str, 0, str.length, "UTF-8");}
  static String byte2str(byte[] str, int s, int l){return byte2str(str, s, l, "UTF-8");}  
  static String byte2str(byte[] str, int s, int l, String encoding){try{ return new String(str, s, l, encoding); }catch(java.io.UnsupportedEncodingException e){return new String(str, s, l);}}
  static byte[] str2byte(String str, String encoding){if(str==null) return null;try{ return str.getBytes(encoding); }catch(java.io.UnsupportedEncodingException e){return str.getBytes();}}
  
}
