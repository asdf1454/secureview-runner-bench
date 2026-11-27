package secureview.llm;

import java.util.List;

/**
 * POST /internal/review-hunk 응답 (docs/HUNK_CODE_REVIEW_DESIGN.md 6절).
 * findingId는 설계안에 없는 값으로, 요청한 경고와 결과를 잇는다. suggestion은 시간이 남았을 때만 있고 없으면 null이다.
 * confidence는 LLM이 스스로 낸 값이라 댓글에 그대로 보여 주지 않는다 (Verdict 참고).
 * rateLimited도 설계안에 없는 값으로, 이 요청 중에 LLM API 사용 한도(429)에 걸렸으면 true다(무료 한도 초과를 PR 요약에 알리려고).
 */
public record HunkReviewResponse(String hunkId, List<Finding> findings, boolean rateLimited) {

    public record Finding(String id, String findingId, String cwe, String severity, int line, int endLine,
                          String title, String verdict, double confidence, String explanation,
                          List<Integer> evidenceLines, String suggestion, String model, double latencySec) {
    }
}
