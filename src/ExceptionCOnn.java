public class ExceptionCOnn extends Exception{
  private Throwable cause=null;
  public ExceptionCOnn () {
    super();
  }
  public ExceptionCOnn (String s) {
    super(s);
  }
  public ExceptionCOnn (String s, Throwable e) {
    super(s);
    this.cause=e;
  }
  public Throwable getCause(){
    return this.cause;
  }
}
