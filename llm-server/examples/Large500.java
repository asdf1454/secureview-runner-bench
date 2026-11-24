import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

// 처리 속도 측정용 500줄 예제. 경고 표시가 붙은 줄이 5건이다 (진짜 취약점 3, 안전 2).
public class Large500 {
    private final Connection conn;

    public Large500(Connection conn) { this.conn = conn; }

    public ResultSet method1(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT * FROM t1 WHERE a = '" + value + "'"); // warning
    }

    public ResultSet method2(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method3(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method4(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method5(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method6(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT * FROM t6 WHERE a = '" + value + "'"); // warning
    }

    public ResultSet method7(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method8(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method9(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method10(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method11(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT COUNT(*) FROM t11"); // warning
    }

    public ResultSet method12(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method13(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method14(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method15(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method16(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT * FROM t16 WHERE a = '" + value + "'"); // warning
    }

    public ResultSet method17(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method18(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method19(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method20(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method21(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM t21 WHERE a = ?");
        ps.setString(1, value);
        return ps.executeQuery(); // warning
    }

    public ResultSet method22(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method23(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    public ResultSet method24(String value, int limit) throws SQLException {
        int step0 = limit + 0;
        int step1 = limit + 1;
        int step2 = limit + 2;
        int step3 = limit + 3;
        int step4 = limit + 4;
        int step5 = limit + 5;
        int step6 = limit + 6;
        int step7 = limit + 7;
        int step8 = limit + 8;
        int step9 = limit + 9;
        int step10 = limit + 10;
        int step11 = limit + 11;
        int step12 = limit + 12;
        if (step0 < 0) {
            return null;
        }
        return conn.createStatement().executeQuery("SELECT 1");
    }

    // padding
    // padding
    // padding
    // padding
    // padding
    // padding
}
