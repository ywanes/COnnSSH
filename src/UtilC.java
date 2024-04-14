class UtilC{
    static String byte2str(byte[] str) {
        return byte2str(str, 0, str.length, "UTF-8");
    }
    static String byte2str(byte[] str, int s, int l, String encoding) {
        try {
            return new String(str, s, l, encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            return new String(str, s, l);
        }
    }
    static byte[] str2byte(String str, String encoding) {
        if (str == null) return null;
        try {
            return str.getBytes(encoding);
        } catch (java.io.UnsupportedEncodingException e) {
            return str.getBytes();
        }
    }            
}
