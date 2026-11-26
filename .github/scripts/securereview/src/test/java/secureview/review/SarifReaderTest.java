package secureview.review;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 분석 담당이 통일할 SARIF 2.1.0에서 경고 위치, CWE, 심각도를 읽는다. */
class SarifReaderTest {

    private static final String SARIF = """
            {"version": "2.1.0", "runs": [{
              "tool": {"driver": {"name": "SpotBugs", "rules": [
                {"id": "SQL_INJECTION_JDBC", "shortDescription": {"text": "SQL 인젝션"},
                 "relationships": [{"target": {"id": "89", "toolComponent": {"name": "CWE"}}}]},
                {"id": "PATH_TRAVERSAL_IN", "properties": {"tags": ["security", "external/cwe/cwe-22"]}},
                {"id": "DM_DEFAULT_ENCODING"}
              ]}},
              "results": [
                {"ruleId": "SQL_INJECTION_JDBC", "ruleIndex": 0, "level": "error",
                 "message": {"text": "This use of executeQuery can be vulnerable"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/UserDao.java"},
                                                     "region": {"startLine": 13}}}]},
                {"ruleId": "PATH_TRAVERSAL_IN", "level": "warning", "message": {"text": "path"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///home/runner/work/r/r/src/Files.java"},
                                                     "region": {"startLine": 7}}}]},
                {"ruleId": "DM_DEFAULT_ENCODING", "level": "note", "message": {"text": "encoding"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/A.java"},
                                                     "region": {"startLine": 3}}}]}
              ]}]}""";

    @Test
    void readsLocationCweAndSeverity() {
        List<Warning> warnings = SarifReader.read(SARIF);

        assertEquals(2, warnings.size(), "CWE가 없는 경고는 판정 대상이 아니다");
        Warning sql = warnings.get(0);
        assertEquals("src/UserDao.java", sql.path());
        assertEquals(13, sql.line());
        assertEquals("CWE-89", sql.cwe());
        assertEquals("HIGH", sql.severity());
        assertEquals("SQL_INJECTION_JDBC", sql.ruleId());
        assertEquals("SQL 인젝션", sql.title());
        assertEquals("SpotBugs", sql.tool());
        assertEquals("This use of executeQuery can be vulnerable", sql.message());
    }

    @Test
    void readsCweFromTagsAndStripsFileUri() {
        Warning path = SarifReader.read(SARIF).get(1);

        assertEquals("CWE-22", path.cwe());
        assertEquals("MEDIUM", path.severity());
        assertEquals("/home/runner/work/r/r/src/Files.java", path.path());
        assertEquals("PATH_TRAVERSAL_IN", path.title(), "설명이 없으면 규칙 이름");
    }

    @Test
    void pathMatchingAllowsSourceRootPrefixes() {
        Warning w = new Warning("secureview/UserDao.java", 1, "CWE-89", "HIGH", "r", "t", "m", "SpotBugs");

        assertTrue(w.matches("src/main/java/secureview/UserDao.java"));
        assertFalse(w.matches("src/main/java/other/UserDao.java"));
        assertFalse(w.matches("src/main/java/secureview/MyUserDao.java"));
        assertTrue(new Warning("/home/runner/work/r/r/src/Files.java", 1, "CWE-22", "LOW", "r", "t", "m", "x")
                .matches("src/Files.java"));
    }
}
