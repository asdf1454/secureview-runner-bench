package secureview.review;

import java.util.stream.Collectors;

/**
 * PR 댓글 본문. LLM이 만든 문장은 PR 코드의 지시를 따라 했을 수 있으므로 그대로 붙이지 않는다:
 * 멘션(@)과 HTML 주석(중복 확인 표시 위조)을 막고 길이를 자른다.
 * confidence는 LLM이 스스로 낸 값이라 보여 주지 않는다.
 */
public final class CommentRenderer {

    static final int MAX_TEXT = 1000;

    private CommentRenderer() {
    }

    public static String marker(String headSha, String findingId) {
        return "<!-- securereview-id: " + headSha + ":" + findingId + " -->";
    }

    public static String summaryMarker(String headSha) {
        return "<!-- securereview-summary: " + headSha + " -->";
    }

    static String inline(PrReviewer.Reviewed r, String marker) {
        String evidence = r.evidenceLines().stream().map(String::valueOf).collect(Collectors.joining(", "));
        return "**SecuReview: " + safe(r.cwe()) + " " + safe(r.title()) + "** (심각도 " + safe(r.severity()) + ")\n\n"
                + safe(r.explanation()) + "\n\n"
                + (evidence.isEmpty() ? "" : "근거 줄: " + evidence + "\n\n")
                + (r.suggestion() == null || r.suggestion().isBlank() ? "" : "**수정 방향:** " + safe(r.suggestion()) + "\n\n")
                + "_정적 분석 경고를 LLM이 판정한 결과입니다. 틀릴 수 있으니 확인 후 반영하세요._\n"
                + marker;
    }

    static String summary(PrReviewer.Outcome o, String marker) {
        StringBuilder b = new StringBuilder("## SecuReview 결과\n\n")
                .append("| 항목 | 값 |\n|---|---|\n")
                .append("| 바뀐 Java 헝크 | ").append(o.hunks()).append("개 (검토 ").append(o.reviewedHunks()).append("개) |\n")
                .append("| 바뀐 줄에 걸린 경고 | ").append(o.warnings()).append("건 |\n")
                .append("| 진짜 취약점 | ").append(o.truePositives()).append("건 (새 댓글 ").append(o.posted()).append("개) |\n")
                .append("| 오탐 추정 | ").append(o.falsePositives()).append("건 |\n")
                .append("| 판정 못 함 | ").append(o.undecided()).append("건 |\n")
                .append("| 걸린 시간 | ").append(o.seconds()).append("초 |\n");
        if (o.warnings() == 0) {
            b.append("\n바뀐 줄에 걸린 정적 분석 경고가 없습니다.\n");
        }
        if (!o.problems().isEmpty()) {
            b.append("\n### 확인이 필요한 부분\n");
            o.problems().forEach(p -> b.append("- ").append(safe(p)).append('\n'));
        }
        return b.append('\n').append(marker).toString();
    }

    static String safe(String text) {
        if (text == null) {
            return "";
        }
        String cut = text.length() > MAX_TEXT ? text.substring(0, MAX_TEXT) + "…" : text;
        return cut.replace("<!--", "&lt;!--").replace("@", "@​");
    }
}
