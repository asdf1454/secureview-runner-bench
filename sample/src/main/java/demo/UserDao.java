package demo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

/** PR 검토 끝까지 확인용 예제. 이 파일은 main에 있고, 테스트 PR이 메서드를 추가한다. */
public class UserDao {

    private final Connection conn;

    public UserDao(Connection conn) {
        this.conn = conn;
    }

    public int count() throws SQLException {
        try (ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM users")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }
}
