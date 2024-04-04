class RequestEnv extends Request{
  byte[] name=new byte[0];
  byte[] value=new byte[0];
  void setEnv(byte[] name, byte[] value){
    this.name=name;
    this.value=value;
  }
  public void request(Session session, Channel channel) throws Exception{
    super.request(session, channel);

    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);

    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(channel.getRecipient());
    buf.putString(Util.str2byte("env"));
    buf.putByte((byte)(waitForReply() ? 1 : 0));
    buf.putString(name);
    buf.putString(value);
    write(packet);
  }
}
