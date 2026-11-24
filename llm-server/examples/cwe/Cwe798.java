import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import javax.crypto.spec.SecretKeySpec;

public class Cwe798 {
    private static final String DB_PASSWORD = "S3cret!pass";

    public Connection field() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://db/app", "admin", DB_PASSWORD); // expect: TRUE_POSITIVE
    }

    public SecretKeySpec key() {
        byte[] raw = "0123456789abcdef".getBytes();
        return new SecretKeySpec(raw, "AES"); // expect: TRUE_POSITIVE
    }

    public Connection fromEnv() throws SQLException {
        String password = System.getenv("DB_PASSWORD");
        return DriverManager.getConnection("jdbc:mysql://db/app", "admin", password); // expect: LIKELY_FALSE_POSITIVE
    }

    public Connection fromParameter(String password) throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://db/app", "admin", password); // expect: LIKELY_FALSE_POSITIVE
    }
}
