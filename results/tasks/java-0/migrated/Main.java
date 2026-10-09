import java.io.File;
public class Main {
    public static void main(String[] args) throws Exception {
        String python = System.getenv().getOrDefault("QMIGRATE_PYTHON", "python");
        Process process = new ProcessBuilder(python, "crypto_adapter.py", "--selftest")
            .directory(new File(".")).inheritIO().start();
        int code = process.waitFor();
        if (code != 0) throw new IllegalStateException("Cryptographic validation failed: " + code);
    }
}
