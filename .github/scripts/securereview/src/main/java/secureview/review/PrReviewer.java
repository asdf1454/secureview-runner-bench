package secureview.review;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * PR 한 번의 검토: diff를 헝크로 나누고, 바뀐 줄에 걸린 경고가 있는 헝크만 LLM에 보내고, 진짜 취약점을 댓글로 단다.
 * 시간은 PR 전체 예산(budgetSec) 하나로 묶는다. 헝크마다 남은 시간을 넘기고, 예산이 바닥나면 나머지 헝크는 검토하지 않는다.
 * 헝크 수·파일 수 상한을 넘으면 심각도가 높은 경고가 있는 헝크부터 고른다.
 */
public final class PrReviewer {

    public interface GitHub {
        String diff();

        String headSha();

        /** head 커밋의 파일 내용. 크기 제한을 넘거나 없으면 null */
        String file(String path, int maxBytes);

        /** 이미 단 봇 댓글·리뷰 본문들 (중복 확인용) */
        List<String> existingBodies();

        void postReview(String headSha, String body, List<InlineComment> comments);
    }

    public interface Llm {
        List<Reviewed> review(String reviewId, Hunk hunk, String source, List<Warning> warnings, int budgetSec);

        /** 지금까지의 검토 중 LLM API 사용 한도(무료 한도 등)에 걸린 적이 있는가. */
        default boolean rateLimited() {
            return false;
        }
    }

    public record Settings(int budgetSec, int maxHunks, int maxFiles, int maxSourceBytes, int maxPatchBytes) {
        public static final Settings DEFAULT = new Settings(45, 20, 20, 1024 * 1024, 64 * 1024);
    }

    /** LLM 서버가 돌려준 판정 하나 (HunkReviewResponse.Finding에서 댓글에 쓰는 값만) */
    public record Reviewed(String id, String cwe, String severity, int line, String title, String verdict,
                           String explanation, List<Integer> evidenceLines, String suggestion) {
    }

    public record InlineComment(String path, int line, String body) {
    }

    /** 요약에 쓰는 숫자. undecided에는 시간·상한 때문에 검토하지 못한 경고도 들어간다. */
    public record Outcome(int hunks, int reviewedHunks, int warnings, int truePositives, int falsePositives,
                          int undecided, int skippedHunks, int failedHunks, int posted, int duplicates,
                          double seconds, List<String> problems) {
    }

    private final GitHub github;
    private final Llm llm;
    private final Settings settings;
    private final LongSupplier nanoTime;

    public PrReviewer(GitHub github, Llm llm, Settings settings) {
        this(github, llm, settings, System::nanoTime);
    }

    PrReviewer(GitHub github, Llm llm, Settings settings, LongSupplier nanoTime) {
        this.github = github;
        this.llm = llm;
        this.settings = settings;
        this.nanoTime = nanoTime;
    }

    public Outcome run(List<Warning> warnings) {
        long started = nanoTime.getAsLong();
        String headSha = github.headSha();
        List<Hunk> hunks = DiffParser.parse(github.diff(), settings.maxPatchBytes());

        // 바뀐 줄에 걸린 경고만 남긴다. 원래 있던 코드의 경고는 이 PR의 책임이 아니다.
        Map<Hunk, List<Warning>> targets = new HashMap<>();
        for (Hunk hunk : hunks) {
            List<Warning> mine = merged(warnings.stream()
                    .filter(w -> w.matches(hunk.filePath()) && hunk.added(w.line()))
                    .toList());
            if (!mine.isEmpty()) {
                targets.put(hunk, mine);
            }
        }
        int warningCount = targets.values().stream().mapToInt(List::size).sum();
        List<Hunk> ordered = targets.keySet().stream()
                .sorted(Comparator.comparingInt((Hunk h) -> bestRank(targets.get(h))).thenComparingInt(hunks::indexOf))
                .toList();

        List<String> problems = new ArrayList<>();
        Set<String> files = new LinkedHashSet<>();
        Map<String, String> sources = new HashMap<>();
        List<Reviewed> results = new ArrayList<>();
        Map<String, Hunk> hunkOf = new HashMap<>();
        int reviewed = 0;
        int skipped = 0;
        int failed = 0;
        int unreviewedWarnings = 0;
        for (Hunk hunk : ordered) {
            int remaining = settings.budgetSec() - (int) ((nanoTime.getAsLong() - started) / 1_000_000_000L);
            boolean newFile = !files.contains(hunk.filePath());
            if (reviewed >= settings.maxHunks() || (newFile && files.size() >= settings.maxFiles()) || remaining <= 0) {
                skipped++;
                unreviewedWarnings += targets.get(hunk).size();
                continue;
            }
            String source = sources.computeIfAbsent(hunk.filePath(), p -> github.file(p, settings.maxSourceBytes()));
            if (source == null) {
                skipped++;
                unreviewedWarnings += targets.get(hunk).size();
                problems.add(hunk.filePath() + ": 파일이 없거나 " + settings.maxSourceBytes() + "바이트를 넘어 검토하지 않았습니다.");
                continue;
            }
            files.add(hunk.filePath());
            reviewed++;
            try {
                for (Reviewed r : llm.review(headSha, hunk, source, targets.get(hunk), remaining)) {
                    results.add(r);
                    hunkOf.put(r.id(), hunk);
                }
            } catch (RuntimeException e) {
                failed++;
                unreviewedWarnings += targets.get(hunk).size();
                problems.add(hunk.filePath() + " " + hunk.header() + ": LLM 검토 실패 (" + e.getMessage() + ")");
            }
        }
        if (llm.rateLimited()) {
            problems.add("LLM API 사용 한도(무료 한도 등)에 걸렸습니다. 일부 경고가 '판정 못 함'이거나 설명·수정 방향이 빠졌을 수 있습니다."
                    + " 잠시 후 다시 실행하거나 API 요금제를 확인하세요.");
        }
        if (skipped > 0) {
            problems.add("시간 예산(" + settings.budgetSec() + "초) 또는 상한(헝크 " + settings.maxHunks() + "개, 파일 "
                    + settings.maxFiles() + "개) 때문에 헝크 " + skipped + "개를 검토하지 않았습니다.");
        }

        String existing = String.join("\n", github.existingBodies());
        List<InlineComment> comments = new ArrayList<>();
        Set<String> added = new java.util.HashSet<>();
        int truePositives = 0;
        int falsePositives = 0;
        int undecided = unreviewedWarnings;
        int duplicates = 0;
        for (Reviewed r : results) {
            switch (r.verdict()) {
                case "TRUE_POSITIVE" -> truePositives++;
                case "LIKELY_FALSE_POSITIVE" -> falsePositives++;
                default -> undecided++;
            }
            Hunk hunk = hunkOf.get(r.id());
            if (!"TRUE_POSITIVE".equals(r.verdict())) {
                continue;
            }
            if (!hunk.added(r.line())) {
                problems.add(hunk.filePath() + ":" + r.line() + " " + r.cwe()
                        + ": 취약하다고 판정했지만 바뀐 줄이 아니라 줄 댓글을 달 수 없습니다.");
                continue;
            }
            String marker = CommentRenderer.marker(placeKey(hunk, r));
            if (existing.contains(marker) || !added.add(marker)) {
                duplicates++;
                continue;
            }
            comments.add(new InlineComment(hunk.filePath(), r.line(), CommentRenderer.inline(r, marker)));
        }

        double seconds = Math.round((nanoTime.getAsLong() - started) / 100_000_000.0) / 10.0;
        Outcome outcome = new Outcome(hunks.size(), reviewed, warningCount, truePositives, falsePositives, undecided,
                skipped, failed, comments.size(), duplicates, seconds, List.copyOf(problems));
        String summaryMarker = CommentRenderer.summaryMarker(headSha);
        if (!comments.isEmpty() || !existing.contains(summaryMarker)) {
            github.postReview(headSha, CommentRenderer.summary(outcome, summaryMarker), comments);
        }
        return outcome;
    }

    /**
     * 중복 확인 키: 파일, CWE, 그 줄의 코드. 위에 줄이 추가되어 줄 번호나 헝크가 바뀌어도 같은 코드의 같은 취약점이면 같은 키다.
     * 같은 파일에 똑같은 코드 줄이 두 번 있으면 한 번만 단다.
     */
    private static String placeKey(Hunk hunk, Reviewed r) {
        String code = hunk.addedLines().stream().filter(a -> a.line() == r.line()).findFirst()
                .map(a -> a.code().strip()).orElse("");
        return DiffParser.sha256(hunk.filePath() + "\n" + r.cwe() + "\n" + code).substring(0, 32);
    }

    /**
     * 같은 줄·같은 CWE 경고는 한 건으로 합친다. FindSecBugs와 SpotBugs가 같은 SQL 실행을 서로 다른 규칙으로 내는 경우가 있다.
     * 심각도가 높은 쪽을 남긴다.
     */
    private static List<Warning> merged(List<Warning> warnings) {
        Map<String, Warning> byPlace = new java.util.LinkedHashMap<>();
        for (Warning w : warnings) {
            byPlace.merge(w.line() + ":" + w.cwe(), w, (a, b) -> bestRank(List.of(b)) < bestRank(List.of(a)) ? b : a);
        }
        return List.copyOf(byPlace.values());
    }

    private static int bestRank(List<Warning> warnings) {
        return warnings.stream().mapToInt(w -> switch (w.severity()) {
            case "HIGH" -> 0;
            case "MEDIUM" -> 1;
            default -> 2;
        }).min().orElse(3);
    }
}
