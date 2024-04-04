class RequestPtyReq extends Request{
  private String ttype="vt100";
  private int tcol=80;
  private int trow=24;
  private int twp=640;
  private int thp=480;

  private byte[] terminal_mode=Util.empty;

  void setCode(String cookie){
  }

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
    buf.putString(Util.str2byte("pty-req"));
    buf.putByte((byte)(waitForReply() ? 1 : 0));
    buf.putString(Util.str2byte(ttype));
    buf.putInt(tcol);
    buf.putInt(trow);
    buf.putInt(twp);
    buf.putInt(thp);
    buf.putString(terminal_mode);
    write(packet);
  }
}
