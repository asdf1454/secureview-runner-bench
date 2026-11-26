package demo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

/** PR 검토 끝까지 확인용 예제. 이 파일은 main에 있고, 테스트 PR이 메서드를 추가한다. */
public class UserDao {

    private static final String TABLE = "users";
    private static final int PAGE_SIZE = 20;

    private final Connection conn;

    public UserDao(Connection conn) {
        this.conn = conn;
    }

    public int count() throws SQLException {
        try (ResultSet rs = conn.createStatement().executeQuery("SELECT COUNT(*) FROM users")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    /** 이름으로 찾기: 입력을 SQL에 그대로 붙인다 (진짜 취약점). */
    public ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM " + TABLE + " WHERE name = '" + name + "'";
        return conn.createStatement().executeQuery(sql);
    }

    /** 전체 목록: 상수로만 만든 SQL (오탐이어야 함). */
    public ResultSet findAll() throws SQLException {
        String sql = "SELECT * FROM " + TABLE + " ORDER BY id";
        return conn.createStatement().executeQuery(sql);
    }

    /** 정렬: 허용한 열 이름만 쓴다 (오탐이어야 함). */
    public ResultSet sorted(String column) throws SQLException {
        String col = "name".equals(column) ? "name" : "id";
        String sql = "SELECT * FROM users ORDER BY " + col;
        return conn.createStatement().executeQuery(sql);
    }
}
