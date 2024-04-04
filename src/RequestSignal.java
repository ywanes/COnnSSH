class RequestSignal extends Request{
  private String signal="KILL";
  public void setSignal(String foo){ signal=foo; }
  public void request(Session session, Channel channel) throws Exception{
    super.request(session, channel);
    Buffer buf=new Buffer();
    Packet packet=new Packet(buf);
    packet.reset();
    buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
    buf.putInt(channel.getRecipient());
    buf.putString(Util.str2byte("signal"));
    buf.putByte((byte)(waitForReply() ? 1 : 0));
    buf.putString(Util.str2byte(signal));
    write(packet);
  }
}
