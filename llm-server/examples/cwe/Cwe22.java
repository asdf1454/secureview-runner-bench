import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Cwe22 {
    private static final Path BASE = Paths.get("/var/app/files");

    public FileInputStream open(String name) throws IOException {
        return new FileInputStream("/var/app/files/" + name); // expect: TRUE_POSITIVE
    }

    public FileInputStream openIn(String dir, String name) throws IOException {
        String path = dir + "/" + name;
        return new FileInputStream(path); // expect: TRUE_POSITIVE
    }

    public FileInputStream checked(String name) throws IOException {
        Path p = BASE.resolve(name).normalize();
        if (!p.startsWith(BASE)) {
            throw new SecurityException("outside base");
        }
        return new FileInputStream(p.toFile()); // expect: LIKELY_FALSE_POSITIVE
    }

    public FileInputStream config() throws IOException {
        return new FileInputStream("/etc/app/config.properties"); // expect: LIKELY_FALSE_POSITIVE
    }
}
