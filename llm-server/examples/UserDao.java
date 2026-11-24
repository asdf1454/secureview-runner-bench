import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

// 데모용 예제. find는 SQL 인젝션 취약(라인 16), findById는 안전(라인 22).
public class UserDao {

    private final Connection conn;

    public UserDao(Connection conn) { this.conn = conn; }

    public ResultSet find(String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public ResultSet findById(int id) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setInt(1, id);
        return ps.executeQuery();
    }

    public ResultSet countAll() throws SQLException {
        return conn.createStatement().executeQuery("SELECT COUNT(*) FROM users");
    }
}
