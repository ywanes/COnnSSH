abstract class Request{
  private boolean reply=false;
  private Session session=null;
  private Channel channel=null;
  void request(Session session, Channel channel) throws Exception{
    this.session=session;
    this.channel=channel;
    if(channel.connectTimeout>0)
      setReply(true);
  }
  boolean waitForReply(){ return reply; }
  void setReply(boolean reply){ this.reply=reply; }
}
