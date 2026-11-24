package secureview.llm;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** API 명세 형식 A: 분석 모듈이 LLM 모듈로 보내는 경고 하나. */
public record AnalysisFinding(String jobId, String findingId, String language, String cwe, String title,
                              String severity, String tool, String ruleId, String toolMessage, Integer line,
                              String sourcePath) {

    private static final Pattern CWE = Pattern.compile("CWE-(\\d{1,6})");

    /** 필수 값이 없거나 형식이 틀리면 {@link IllegalArgumentException}. */
    Finding toFinding() {
        if (findingId == null || findingId.isBlank()) {
            throw new IllegalArgumentException("findingId가 없습니다.");
        }
        if (line == null || line < 1) {
            throw new IllegalArgumentException("line은 1 이상이어야 합니다.");
        }
        Matcher matcher = CWE.matcher(cwe == null ? "" : cwe);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("cwe는 CWE-89 형식이어야 합니다.");
        }
        return new Finding(findingId, fileName(), line, line, ruleId, Integer.parseInt(matcher.group(1)), severity,
                toolMessage, tool == null ? List.of() : List.of(tool));
    }

    /** 분석 서버의 경로는 LLM 서버에서 쓸 수 없으므로 언어 판단과 프롬프트에 필요한 파일 이름만 쓴다. */
    private String fileName() {
        if (sourcePath == null || sourcePath.isBlank()) {
            return "C".equals(language) ? "source.c" : "source.java";
        }
        return sourcePath.substring(Math.max(sourcePath.lastIndexOf('/'), sourcePath.lastIndexOf('\\')) + 1);
    }
}
