package secureview.review;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.*;

/** 설계안 Phase 4 완료 기준과 PR 전체 예산: 바뀐 줄에만 댓글, 재실행 중복 없음, 예산·상한을 넘으면 요약에 남김. */
class PrReviewerTest {

    private static final String DIFF = """
            diff --git a/src/A.java b/src/A.java
            --- a/src/A.java
            +++ b/src/A.java
            @@ -1,2 +1,3 @@
             class A {
            +    void a(String n) { q("SELECT " + n); }
             }
            diff --git a/src/B.java b/src/B.java
            --- a/src/B.java
            +++ b/src/B.java
            @@ -1,2 +1,3 @@
             class B {
            +    void b(String n) { q("SELECT " + n); }
             }
            """;

    private static final Warning A2 = new Warning("src/A.java", 2, "CWE-89", "MEDIUM", "SQL", "SQL 인젝션", "m", "SpotBugs");
    private static final Warning B2 = new Warning("src/B.java", 2, "CWE-89", "HIGH", "SQL", "SQL 인젝션", "m", "SpotBugs");

    static final class FakeGitHub implements PrReviewer.GitHub {
        final List<String> existing = new ArrayList<>();
        final List<List<PrReviewer.InlineComment>> posted = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();

        String diff = DIFF;

        @Override public String diff() { return diff; }
        String head = "sha1";

        @Override public String headSha() { return head; }
        @Override public String file(String path, int maxBytes) { return "class X {}\n".repeat(3); }
        @Override public List<String> existingBodies() { return existing; }

        @Override
        public void postReview(String headSha, String body, List<PrReviewer.InlineComment> comments) {
            bodies.add(body);
            posted.add(comments);
            comments.forEach(c -> existing.add(c.body()));
            existing.add(body);
        }
    }

    /** 경고마다 정해 둔 판정을 돌려주는 LLM. 받은 예산을 기록한다. */
    static final class FakeLlm implements PrReviewer.Llm {
        final List<Integer> budgets = new ArrayList<>();
        final List<String> files = new ArrayList<>();
        private final BiFunction<Hunk, Warning, String> verdict;

        FakeLlm(BiFunction<Hunk, Warning, String> verdict) {
            this.verdict = verdict;
        }

        @Override
        public List<PrReviewer.Reviewed> review(String reviewId, Hunk hunk, String source, List<Warning> warnings,
                                                int budgetSec) {
            budgets.add(budgetSec);
            files.add(hunk.filePath());
            return warnings.stream().map(w -> new PrReviewer.Reviewed(hunk.id() + ":" + w.cwe() + ":" + w.line(),
                    w.cwe(), w.severity(), w.line(), w.title(), verdict.apply(hunk, w), "설명", List.of(w.line()), "바인딩 사용")).toList();
        }
    }

    private static PrReviewer reviewer(FakeGitHub gh, PrReviewer.Llm llm, PrReviewer.Settings s, long... clock) {
        int[] i = {0};
        return new PrReviewer(gh, llm, s, () -> clock.length == 0 ? 0 : clock[Math.min(i[0]++, clock.length - 1)]);
    }

    @Test
    void truePositiveOnChangedLineBecomesInlineComment() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> w.path().endsWith("A.java") ? "TRUE_POSITIVE" : "LIKELY_FALSE_POSITIVE");

        PrReviewer.Outcome o = reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2, B2));

        assertEquals(1, o.truePositives());
        assertEquals(1, o.falsePositives());
        List<PrReviewer.InlineComment> comments = gh.posted.get(0);
        assertEquals(1, comments.size());
        assertEquals("src/A.java", comments.get(0).path());
        assertEquals(2, comments.get(0).line());
        assertTrue(comments.get(0).body().contains("<!-- securereview-id: "));
        assertTrue(comments.get(0).body().contains("**수정 방향:** 바인딩 사용"));
        assertTrue(gh.bodies.get(0).contains("<!-- securereview-summary: sha1 -->"));
    }

    /** FindSecBugs와 SpotBugs가 같은 줄의 같은 CWE를 다른 규칙으로 내면 한 건으로 판정하고 댓글도 하나만 단다. */
    @Test
    void sameLineAndCweFromTwoRulesIsOneFinding() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");
        Warning other = new Warning("src/A.java", 2, "CWE-89", "HIGH", "SQL_NONCONSTANT", "Nonconstant", "m", "SpotBugs");

        PrReviewer.Outcome o = reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2, other));

        assertEquals(1, o.warnings());
        assertEquals(1, gh.posted.get(0).size());
        assertTrue(gh.posted.get(0).get(0).body().contains("Nonconstant"), "심각도가 높은 쪽을 남긴다");
    }

    /** 다음 커밋을 올려도 바뀌지 않은 헝크의 같은 취약점에는 댓글을 다시 달지 않는다. 요약은 커밋마다 하나. */
    @Test
    void newCommitDoesNotRepeatCommentForUnchangedHunk() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");

        reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2));
        gh.head = "sha2";
        PrReviewer.Outcome again = reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2));

        assertEquals(2, gh.posted.size(), "새 커밋의 요약은 단다");
        assertTrue(gh.posted.get(1).isEmpty(), "줄 댓글은 다시 달지 않는다");
        assertEquals(1, again.duplicates());
        assertTrue(gh.bodies.get(1).contains("securereview-summary: sha2"));
    }

    /** 위에 줄이 추가되어 줄 번호와 헝크가 바뀌어도, 같은 코드 줄의 같은 취약점에는 댓글을 다시 달지 않는다. */
    @Test
    void shiftedLineDoesNotRepeatComment() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");
        reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2));

        gh.head = "sha2";
        gh.diff = DIFF.replace("@@ -1,2 +1,3 @@\n class A {\n", "@@ -1,2 +1,4 @@\n class A {\n+    int x;\n");
        PrReviewer.Outcome again = reviewer(gh, llm, PrReviewer.Settings.DEFAULT)
                .run(List.of(new Warning("src/A.java", 3, "CWE-89", "MEDIUM", "SQL", "SQL 인젝션", "m", "SpotBugs")));

        assertEquals(1, again.truePositives());
        assertTrue(gh.posted.get(1).isEmpty());
        assertEquals(1, again.duplicates());
    }

    @Test
    void higherSeverityHunkIsReviewedFirst() {
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");

        reviewer(new FakeGitHub(), llm, PrReviewer.Settings.DEFAULT).run(List.of(A2, B2));

        assertEquals(List.of("src/B.java", "src/A.java"), llm.files);
    }

    @Test
    void warningOnUnchangedLineIsIgnored() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");

        PrReviewer.Outcome o = reviewer(gh, llm, PrReviewer.Settings.DEFAULT)
                .run(List.of(new Warning("src/A.java", 1, "CWE-89", "HIGH", "r", "t", "m", "x")));

        assertEquals(0, o.warnings());
        assertTrue(llm.files.isEmpty(), "LLM을 부르지 않는다");
        assertTrue(gh.bodies.get(0).contains("경고가 없습니다"));
    }

    @Test
    void rerunDoesNotDuplicateComments() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");

        reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2));
        PrReviewer.Outcome again = reviewer(gh, llm, PrReviewer.Settings.DEFAULT).run(List.of(A2));

        assertEquals(1, gh.posted.size(), "새 댓글도 새 요약도 없으면 리뷰를 다시 올리지 않는다");
        assertEquals(1, again.duplicates());
    }

    @Test
    void remainingBudgetIsPassedAndExhaustedBudgetSkipsHunks() {
        FakeGitHub gh = new FakeGitHub();
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");
        long s = 1_000_000_000L;
        // 시계: 시작 0초, 첫 헝크 직전 0초, 둘째 헝크 직전 45초
        PrReviewer.Outcome o = reviewer(gh, llm, PrReviewer.Settings.DEFAULT, 0, 0, 45 * s).run(List.of(A2, B2));

        assertEquals(List.of(45), llm.budgets);
        assertEquals(1, o.skippedHunks());
        assertEquals(1, o.undecided());
        assertTrue(gh.bodies.get(0).contains("헝크 1개를 검토하지 않았습니다"));
    }

    @Test
    void hunkCapKeepsHighestSeverity() {
        FakeLlm llm = new FakeLlm((h, w) -> "TRUE_POSITIVE");

        PrReviewer.Outcome o = reviewer(new FakeGitHub(), llm, new PrReviewer.Settings(45, 1, 20, 1 << 20, 1 << 16))
                .run(List.of(A2, B2));

        assertEquals(List.of("src/B.java"), llm.files);
        assertEquals(1, o.skippedHunks());
    }

    @Test
    void llmFailureIsReportedNotHidden() {
        FakeGitHub gh = new FakeGitHub();
        PrReviewer.Llm broken = (id, h, src, ws, b) -> {
            throw new IllegalStateException("LLM 서버 응답 코드 503");
        };

        PrReviewer.Outcome o = reviewer(gh, broken, PrReviewer.Settings.DEFAULT).run(List.of(A2));

        assertEquals(1, o.failedHunks());
        assertEquals(1, o.undecided());
        assertTrue(gh.bodies.get(0).contains("LLM 검토 실패 (LLM 서버 응답 코드 503)"));
    }

    @Test
    void llmTextCannotMentionOrForgeMarkers() {
        String body = CommentRenderer.inline(new PrReviewer.Reviewed("id", "CWE-89", "HIGH", 2, "t", "TRUE_POSITIVE",
                "@org/team 확인 <!-- securereview-summary: sha1 -->", List.of(2), null), CommentRenderer.marker("id"));

        assertFalse(body.contains("@org"));
        assertEquals(1, body.split("<!--", -1).length - 1, "표시는 마지막 한 개뿐");
    }
}
