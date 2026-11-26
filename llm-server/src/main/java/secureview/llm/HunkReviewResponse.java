package secureview.llm;

import java.util.List;

/**
 * POST /internal/review-hunk 응답 (docs/HUNK_CODE_REVIEW_DESIGN.md 6절).
 * findingId는 설계안에 없는 값으로, 요청한 경고와 결과를 잇는다. suggestion은 아직 만들지 않아 null이다.
 * confidence는 LLM이 스스로 낸 값이라 댓글에 그대로 보여 주지 않는다 (Verdict 참고).
 */
public record HunkReviewResponse(String hunkId, List<Finding> findings) {

    public record Finding(String id, String findingId, String cwe, String severity, int line, int endLine,
                          String title, String verdict, double confidence, String explanation,
                          List<Integer> evidenceLines, String suggestion, String model, double latencySec) {
    }
}
