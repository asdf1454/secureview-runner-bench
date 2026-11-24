package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CFunctionExtractionTest {

    private static CodeContext extract(String source, int line) {
        Finding f = new Finding("F", "a.c", line, line, "R", 120, "HIGH", "m", List.of("t"));
        return new ContextExtractor().extract(f, source);
    }

    private static void assertFunction(CodeContext c, int start, int end) {
        assertTrue(c.wholeFunction(), "함수 전체여야 한다");
        assertEquals(start, c.startLine());
        assertEquals(end, c.endLine());
    }

    @Test
    void findsFunctionWithBodyBracesAndSignatureOnSeveralLines() {
        String src = """
                #include <string.h>

                int
                copy(char *dst,
                     const char *src)
                {
                    if (src) {
                        strcpy(dst, src);
                    }
                    return 0;
                }

                int other(void) { return 1; }
                """;
        assertFunction(extract(src, 8), 3, 11);
        assertFunction(extract(src, 13), 13, 13);
    }

    @Test
    void ignoresBracesInStringsCharsAndComments() {
        String src = """
                /* { comment before } */
                void f(void) {
                    char *s = "}}}";  // }}}
                    char c = '}';
                    /* } */
                    use(s, c);
                }
                void g(void) {
                    use2();
                }
                """;
        assertFunction(extract(src, 6), 2, 7);
        assertFunction(extract(src, 9), 8, 10);
    }

    @Test
    void functionStartSkipsPreprocessorAndPreviousStruct() {
        String src = """
                #define MAX(a, b) \\
                    ((a) > (b) ? (a) : (b))
                struct point { int x; int y; };
                static int table[] = { 1, 2 };
                static int h(int a) {
                    return a;
                }
                """;
        assertFunction(extract(src, 6), 5, 7);
    }

    @Test
    void lineOutsideAnyFunctionFallsBackToWindow() {
        String src = """
                struct point {
                    int x;
                };
                void f(void) {
                }
                """;
        assertFalse(extract(src, 2).wholeFunction());
    }

    @Test
    void unbalancedBracesFromPreprocessorFallBackToWindow() {
        String src = """
                void f(int a) {
                #ifdef A
                    if (a) {
                #else
                    if (!a) {
                #endif
                        use();
                    }
                }
                """;
        assertFalse(extract(src, 7).wholeFunction());
    }

    @Test
    void headerFileIsAlsoHandled() {
        Finding f = new Finding("F", "a.h", 2, 2, "R", 120, "HIGH", "m", List.of("t"));
        CodeContext c = new ContextExtractor().extract(f, "static inline int f(void) {\n  return 1;\n}\n");
        assertFunction(c, 1, 3);
    }
}
