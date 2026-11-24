package secureview.llm;

import java.util.List;

/**
 * S3가 넘겨주는 취약점 정보 (계획서의 Finding 항목).
 * 임시본: 10/31 팀 코딩 세션에서 공통 데이터 클래스가 확정되면 그것으로 교체한다.
 */
public record Finding(String id, String file, int startLine, int endLine,
                      String ruleId, int cwe, String severity, String message,
                      List<String> tools) {
}
