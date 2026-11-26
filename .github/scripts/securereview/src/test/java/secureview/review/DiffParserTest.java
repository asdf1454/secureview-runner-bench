package secureview.review;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** 설계안 Phase 1 완료 기준: 신규 줄 번호가 정확하고, 삭제 전용·중복이 빠지고, 같은 입력은 같은 ID. */
class DiffParserTest {

    private static final String DIFF = """
            diff --git a/src/UserDao.java b/src/UserDao.java
            index 111..222 100644
            --- a/src/UserDao.java
            +++ b/src/UserDao.java
            @@ -10,4 +10,5 @@ public class UserDao {
                 public ResultSet find(String name) throws SQLException {
                     Statement st = conn.createStatement();
            -        return st.executeQuery("SELECT 1");
            +        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
            +        return st.executeQuery(sql);
                 }
            @@ -30,3 +31,2 @@ public class UserDao {
                 void a() {}
            -    void b() {}
                 void c() {}
            @@ -40,2 +40,3 @@
                 void d() {}
            +    // 주석만 추가
                 void e() {}
            diff --git a/README.md b/README.md
            --- a/README.md
            +++ b/README.md
            @@ -1 +1 @@
            -old
            +new
            diff --git a/src/Old.java b/src/Old.java
            deleted file mode 100644
            --- a/src/Old.java
            +++ /dev/null
            @@ -1,2 +0,0 @@
            -class Old {
            -}
            diff --git a/src/New.java b/src/New.java
            new file mode 100644
            --- /dev/null
            +++ b/src/New.java
            @@ -0,0 +1,3 @@
            +class New {
            +    String f(String x) { return x; }
            +}
            diff --git a/lib/a.jar b/lib/a.jar
            Binary files a/lib/a.jar and b/lib/a.jar differ
            """;

    private static List<Hunk> parse() {
        return DiffParser.parse(DIFF, 64 * 1024);
    }

    @Test
    void keepsOnlyJavaHunksWithAddedCode() {
        List<Hunk> hunks = parse();

        assertEquals(List.of("src/UserDao.java", "src/New.java"), hunks.stream().map(Hunk::filePath).toList());
    }

    @Test
    void addedLinesHaveNewFileLineNumbers() {
        Hunk h = parse().get(0);

        assertEquals(10, h.newStartLine());
        assertEquals(5, h.newLineCount());
        assertEquals(10, h.oldStartLine());
        assertEquals(4, h.oldLineCount());
        assertEquals(List.of(12, 13), h.addedLines().stream().map(Hunk.AddedLine::line).toList());
        assertEquals("        return st.executeQuery(sql);", h.addedLines().get(1).code());
        assertTrue(h.header().startsWith("@@ -10,4 +10,5 @@"));
        assertTrue(h.patch().startsWith(h.header() + "\n"));
    }

    @Test
    void newFileStartsAtLineOne() {
        Hunk h = parse().get(1);

        assertEquals(List.of(1, 2, 3), h.addedLines().stream().map(Hunk.AddedLine::line).toList());
    }

    @Test
    void sameInputGivesSameIdAndDuplicatesAreDropped() {
        String twice = DIFF + DIFF;

        List<Hunk> again = DiffParser.parse(twice, 64 * 1024);

        assertEquals(parse().stream().map(Hunk::id).toList(), again.stream().map(Hunk::id).toList());
        assertEquals(64, parse().get(0).id().length());
    }

    @Test
    void oversizedHunkIsDropped() {
        assertEquals(List.of("src/New.java"),
                DiffParser.parse(DIFF, 120).stream().map(Hunk::filePath).toList());
    }

    @Test
    void crlfDiffIsParsedTheSame() {
        assertEquals(parse().stream().map(Hunk::addedLines).toList(),
                DiffParser.parse(DIFF.replace("\n", "\r\n"), 64 * 1024).stream().map(Hunk::addedLines).toList());
    }
}
