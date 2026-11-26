package secureview.llm;

import java.util.List;

/**
 * POST /internal/review-hunk 요청 (docs/HUNK_CODE_REVIEW_DESIGN.md 6절).
 * 설계안과 달리 findings에 그 헝크에 걸린 정적 분석 경고(형식 A)를 함께 받는다. LLM은 경고를 판정만 한다.
 * budgetSec는 PR 전체 예산 중 남은 시간이다. 없으면 서버의 최대값을 쓴다.
 */
public record HunkReviewRequest(String reviewId, Hunk hunk, String sourceCode, List<AnalysisFinding> findings,
                                Integer budgetSec) {

    public record Hunk(String id, String filePath, String language, String baseSha, String headSha,
                       int newStartLine, int newLineCount, String patch, List<AddedLine> addedLines) {
    }

    public record AddedLine(int line, String code) {
    }
}
