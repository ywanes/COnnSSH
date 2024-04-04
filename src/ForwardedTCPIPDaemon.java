import java.io.*;

public interface ForwardedTCPIPDaemon extends Runnable{
  void setChannel(ChannelForwardedTCPIP channel, InputStream in, OutputStream out);
  void setArg(Object[] arg);
}
