class ExceptionC extends Exception {
    private Throwable cause = null;
    public ExceptionC() {
        super();
    }
    public ExceptionC(String s) {
        super(s);
    }
    public ExceptionC(String s, Throwable e) {
        super(s);
        this.cause = e;
    }
    public Throwable getCause() {
        return this.cause;
    }
}

