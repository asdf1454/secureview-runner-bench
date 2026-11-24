import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;

// CWE-89 판정 평가용 예제. 각 sink 줄 끝의 "// expect:"가 정답 라벨이다.
// Eval은 LLM에 보내기 전에 이 라벨 주석을 지운다.
public class SqlCases {

    private static final String TABLE = "users";
    private static final Map<String, String> SORT_COLUMNS = Map.of("name", "name", "date", "created_at");

    private final Connection conn;

    public SqlCases(Connection conn) { this.conn = conn; }

    public ResultSet concat(String name) throws SQLException {
        return conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + name + "'"); // expect: TRUE_POSITIVE
    }

    public ResultSet builder(String city) throws SQLException {
        StringBuilder sql = new StringBuilder("SELECT * FROM users WHERE city = '");
        sql.append(city).append("'");
        return conn.createStatement().executeQuery(sql.toString()); // expect: TRUE_POSITIVE
    }

    public ResultSet formatted(String email) throws SQLException {
        String sql = String.format("SELECT * FROM users WHERE email = '%s'", email);
        return conn.createStatement().executeQuery(sql); // expect: TRUE_POSITIVE
    }

    public ResultSet bound(String name) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery(); // expect: LIKELY_FALSE_POSITIVE
    }

    public ResultSet constant() throws SQLException {
        return conn.createStatement().executeQuery("SELECT COUNT(*) FROM users"); // expect: LIKELY_FALSE_POSITIVE
    }

    public ResultSet constantField() throws SQLException {
        return conn.createStatement().executeQuery("SELECT * FROM " + TABLE); // expect: LIKELY_FALSE_POSITIVE
    }

    public ResultSet allowlisted(String name) throws SQLException {
        if (!name.matches("[A-Za-z]{1,20}")) {
            throw new IllegalArgumentException("invalid name");
        }
        return conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + name + "'"); // expect: LIKELY_FALSE_POSITIVE
    }

    public ResultSet sorted(String sortKey) throws SQLException {
        String column = SORT_COLUMNS.getOrDefault(sortKey, "name");
        return conn.createStatement().executeQuery("SELECT * FROM users ORDER BY " + column); // expect: LIKELY_FALSE_POSITIVE
    }
}
