package secureview.llm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** 명령어 삽입(78), 경로 조작(22), XSS(79)에도 같은 상수 판정을 쓴다. 예시는 OWASP Benchmark 사례를 줄인 것. */
class ConstantArgsOtherCweTest {

    /** 3번 줄이 param, 4번 줄부터 body, 마지막 body 줄이 경고 줄. */
    private static boolean constant(int cwe, String... body) {
        StringBuilder src = new StringBuilder("public class A {\n  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n")
                .append("    String param = request.getParameter(\"x\");\n");
        for (String line : body) {
            src.append("    ").append(line).append('\n');
        }
        src.append("  }\n}\n");
        return ConstantArgs.isConstant(src.toString(), 3 + body.length, cwe);
    }

    @Test
    void commandWithConstantListIsConstant() {
        assertTrue(constant(78,
                "java.util.List<String> argList = new java.util.ArrayList<String>();",
                "argList.add(\"sh\");",
                "argList.add(\"-c\");",
                "argList.add(\"echo \" + \"safe\");",
                "ProcessBuilder pb = new ProcessBuilder(argList);"));
    }

    @Test
    void commandEnvironmentWithInputIsNotConstant() {
        assertFalse(constant(78,
                "String[] args = {\"sh\", \"-c\", \"echo\"};",
                "String[] argsEnv = {\"foo=\" + param};",
                "Process p = Runtime.getRuntime().exec(args, argsEnv);"));
    }

    @Test
    void nestedFileWithConstantNameIsConstant() {
        assertTrue(constant(22,
                "String bar = \"safe\";",
                "String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;",
                "java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File(fileName));"));
    }

    @Test
    void fileWithInputIsNotConstant() {
        assertFalse(constant(22,
                "String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;",
                "java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File(fileName));"));
    }

    @Test
    void lowercaseFieldIsNotTrusted() {
        assertFalse(constant(22,
                "java.io.File f = new java.io.File(this.uploadDir, \"a.txt\");"));
    }

    @Test
    void systemPropertyIsTrusted() {
        assertTrue(constant(22,
                "java.io.File f = new java.io.File(System.getProperty(\"user.dir\"), \"a.txt\");"));
    }

    @Test
    void writerWithConstantIsConstantButInputIsNot() {
        assertTrue(constant(79, "response.getWriter().write(\"Parameter value: \" + \"safe\");"));
        assertFalse(constant(79, "response.getWriter().write(\"Parameter value: \" + param);"));
    }

    @Test
    void formatWithConstantArgumentsIsConstant() {
        assertTrue(constant(79,
                "Object[] obj = {\"a\", \"b\"};",
                "response.getWriter().format(java.util.Locale.US, \"%s %s\", obj);"));
    }

    @Test
    void unsupportedCweIsNotDecided() {
        assertFalse(constant(798, "String password = \"secret\";"));
    }
}
