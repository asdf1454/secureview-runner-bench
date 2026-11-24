import java.io.IOException;
import java.util.Set;

public class Cwe78 {
    private static final Set<String> HOSTS = Set.of("db1", "db2");

    public Process ping(String host) throws IOException {
        return Runtime.getRuntime().exec("ping -c 1 " + host); // expect: TRUE_POSITIVE
    }

    public Process shell(String name) throws IOException {
        String[] cmd = {"sh", "-c", "cat /tmp/" + name};
        return Runtime.getRuntime().exec(cmd); // expect: TRUE_POSITIVE
    }

    public Process allowed(String host) throws IOException {
        if (!HOSTS.contains(host)) {
            throw new IllegalArgumentException("unknown host");
        }
        return new ProcessBuilder("ping", "-c", "1", host).start(); // expect: LIKELY_FALSE_POSITIVE
    }

    public Process fixed() throws IOException {
        return Runtime.getRuntime().exec("uptime"); // expect: LIKELY_FALSE_POSITIVE
    }
}
