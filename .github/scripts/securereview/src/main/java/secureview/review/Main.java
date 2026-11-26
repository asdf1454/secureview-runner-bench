package secureview.review;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * GitHub Actions의 pull_request 실행에서 PR 검토를 한 번 돌린다.
 * 환경 변수
 * - GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH(PR 번호), GITHUB_API_URL: Actions가 넣어 주는 값
 * - SR_SARIF: 분석 담당이 만든 SARIF 파일 경로(필수)
 * - SR_LLM_URL(기본 http://127.0.0.1:8081), SR_INTERNAL_KEY(필수): llm-server
 * - SR_BUDGET_SEC(기본 45), SR_MAX_HUNKS(기본 20), SR_MAX_FILES(기본 20)
 * 결과 요약은 GITHUB_STEP_SUMMARY에도 쓴다. 댓글을 달지 못하면(포크 PR의 읽기 전용 토큰 등) 요약을 남긴 뒤 실패로 끝낸다.
 */
public final class Main {

    public static void main(String[] args) throws IOException {
        String token = required("GITHUB_TOKEN");
        String repo = required("GITHUB_REPOSITORY");
        int number = prNumber();
        String key = required("SR_INTERNAL_KEY");
        List<Warning> warnings = SarifReader.read(Files.readString(Path.of(required("SR_SARIF")), StandardCharsets.UTF_8));
        PrReviewer.Settings d = PrReviewer.Settings.DEFAULT;
        PrReviewer.Settings settings = new PrReviewer.Settings(number("SR_BUDGET_SEC", d.budgetSec()),
                number("SR_MAX_HUNKS", d.maxHunks()), number("SR_MAX_FILES", d.maxFiles()),
                d.maxSourceBytes(), d.maxPatchBytes());

        GitHubApi github = new GitHubApi(env("GITHUB_API_URL", "https://api.github.com"), repo, number, token);
        LlmApi llm = new LlmApi(env("SR_LLM_URL", "http://127.0.0.1:8081"), key);
        PrReviewer.Outcome outcome;
        try {
            outcome = new PrReviewer(github, llm, settings).run(warnings);
        } catch (Http.Failure e) {
            String why = e.status == 403 || e.status == 404
                    ? "PR 댓글을 달 권한이 없습니다. 워크플로에 permissions: pull-requests: write가 있는지, 포크에서 온 PR이라"
                      + " 토큰이 읽기 전용이 아닌지 확인하세요. (" + e.getMessage() + ")"
                    : e.getMessage();
            System.err.println("SecuReview 실패: " + why);
            summary("## SecuReview 실패\n\n" + why + "\n");
            System.exit(1);
            return;
        }
        String text = "SecuReview: 헝크 " + outcome.reviewedHunks() + "/" + outcome.hunks() + "개 검토, 경고 "
                + outcome.warnings() + "건 중 진짜 취약점 " + outcome.truePositives() + "건, 새 댓글 " + outcome.posted()
                + "개, " + outcome.seconds() + "초";
        System.out.println(text);
        outcome.problems().forEach(p -> System.out.println("- " + p));
        summary("## SecuReview\n\n" + text + "\n" + String.join("", outcome.problems().stream().map(p -> "- " + p + "\n").toList()));
    }

    private static int prNumber() throws IOException {
        String event = System.getenv("GITHUB_EVENT_PATH");
        if (event != null && Files.exists(Path.of(event))) {
            int n = SarifReader.MAPPER.readTree(Files.readString(Path.of(event))).path("pull_request").path("number").asInt(0);
            if (n > 0) {
                return n;
            }
        }
        return Integer.parseInt(required("SR_PR_NUMBER"));
    }

    private static void summary(String markdown) throws IOException {
        String file = System.getenv("GITHUB_STEP_SUMMARY");
        if (file != null) {
            Files.writeString(Path.of(file), markdown, StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        }
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            System.err.println("환경 변수 " + name + "를 설정하세요.");
            System.exit(1);
        }
        return value;
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }

    private static int number(String name, int fallback) {
        return Integer.parseInt(env(name, String.valueOf(fallback)));
    }
}
