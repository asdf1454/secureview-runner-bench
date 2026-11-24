package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class ContextExtractorTest {

    private final ContextExtractor extractor = new ContextExtractor();

    private static Finding at(String file, int line) {
        return new Finding("F", file, line, line, "R", 89, "HIGH", "m", List.of("t"));
    }

    @Test
    void javaReturnsWholeEnclosingMethod() {
        String src = """
                class A {
                    void safe() {}

                    void bad(String s) {
                        String q = "x" + s;
                        run(q);
                    }
                }
                """;
        CodeContext ctx = extractor.extract(at("A.java", 6), src);

        assertTrue(ctx.wholeFunction());
        assertEquals(4, ctx.startLine());
        assertEquals(7, ctx.endLine());
        assertTrue(ctx.numbered().startsWith("4|     void bad(String s) {"));
    }

    @Test
    void javaIncludesOnlyFieldsUsedByMethod() {
        String src = """
                class A {
                    private static final String TABLE = "users";
                    private static final String OTHER = "x";

                    void q() {
                        run("SELECT * FROM " + TABLE);
                    }
                }
                """;
        CodeContext ctx = extractor.extract(at("A.java", 6), src);

        assertEquals(List.of(2), List.copyOf(ctx.related().keySet()));
        assertTrue(ctx.contains(2));
        assertFalse(ctx.contains(3));
        assertTrue(ctx.numbered().startsWith("2|     private static final String TABLE = \"users\";\n...\n5|"));
    }

    @Test
    void javaPicksInnermostMethod() {
        String src = """
                class A {
                    void outer() {
                        Runnable r = new Runnable() {
                            public void run() {
                                danger();
                            }
                        };
                    }
                }
                """;
        CodeContext ctx = extractor.extract(at("A.java", 5), src);

        assertEquals(4, ctx.startLine());
        assertEquals(6, ctx.endLine());
    }

    @Test
    void unparsableJavaFallsBackToWindow() {
        CodeContext ctx = extractor.extract(at("A.java", 2), "class A {\n  void broken( {\n");

        assertFalse(ctx.wholeFunction());
        assertEquals(1, ctx.startLine());
        assertEquals(2, ctx.endLine());
    }

    @Test
    void cUsesWindowClampedToFile() {
        String src = IntStream.rangeClosed(1, 100).mapToObj(i -> "line" + i).collect(Collectors.joining("\n"));
        CodeContext ctx = extractor.extract(at("a.c", 50), src);

        assertFalse(ctx.wholeFunction());
        assertEquals(20, ctx.startLine());
        assertEquals(80, ctx.endLine());
        assertEquals("line20", ctx.lines().get(0));

        CodeContext nearEnd = extractor.extract(at("a.c", 95), src);
        assertEquals(100, nearEnd.endLine());
    }
}
