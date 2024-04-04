import java.io.*;
import java.net.Socket;
public interface Proxy{
  void connect(SocketFactory socket_factory, String host, int port, int timeout) throws Exception;
  InputStream getInputStream();
  OutputStream getOutputStream();
  Socket getSocket();
  void close();
}
