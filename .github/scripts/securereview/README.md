# securereview (PR 검토 실행기)

`docs/HUNK_CODE_REVIEW_DESIGN.md`의 Phase 1(Hunk 추출)과 Phase 4(PR 댓글 게시)를 구현한 모듈이다. 담당: 유환민.

## 하는 일

1. GitHub API로 PR diff를 받아 헝크로 나눈다 (`DiffParser`). `.java` 파일에서 코드가 추가된 헝크만 남기고, 삭제 전용·주석 전용·중복 헝크는 뺀다.
2. 분석 담당이 만든 SARIF를 읽는다 (`SarifReader`). CWE가 없는 경고는 뺀다.
3. **바뀐 줄에 걸린 경고**가 있는 헝크만 llm-server `POST /internal/review-hunk`로 보낸다 (`LlmApi`).
4. 진짜 취약점(`TRUE_POSITIVE`)은 그 줄에 댓글을 달고, 전체 결과는 요약 리뷰 하나로 단다 (`GitHubApi`, `CommentRenderer`).

## 시간 기준

경고 한 건당 30초가 아니라 **PR 전체 예산**을 쓴다(기본 45초). 헝크마다 남은 시간을 llm-server에 넘기고, 예산이 바닥나면 나머지 헝크는 검토하지 않고 요약에 적는다. 헝크는 최대 20개, 파일은 최대 20개다. 상한을 넘으면 심각도가 높은 경고가 있는 헝크부터 검토한다.

## 중복 방지

댓글 끝에 `<!-- securereview-id: 키 -->`, 요약 끝에 `<!-- securereview-summary: headSha -->`를 붙인다. 키는 파일·CWE·그 줄의 코드로 만든 해시라, 위에 줄이 추가되어 줄 번호가 바뀌어도 같은 코드의 같은 취약점에는 다음 커밋에서 댓글을 다시 달지 않는다. 요약은 커밋마다 하나 단다. 예전 댓글은 지우지 않는다.

설계안 8절은 커밋 SHA로 중복을 판단하지만, 그러면 커밋을 올릴 때마다 바뀌지 않은 줄에도 같은 댓글이 다시 달린다(테스트 PR에서 확인). 그래서 줄 댓글은 코드 내용으로 판단한다. 같은 파일에 똑같은 코드 줄이 두 번 있으면 댓글은 하나만 달린다.

같은 줄·같은 CWE의 경고는 한 건으로 합친다. FindSecBugs의 `SQL_INJECTION_JDBC`와 SpotBugs의 `SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE`가 같은 줄에 함께 나와 댓글이 두 개 달린 것을 테스트 PR에서 확인했다.

## 환경 변수

| 변수 | 설명 |
|---|---|
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH` | Actions가 넣어 준다. 워크플로에 `pull-requests: write` 권한이 필요하다 |
| `SR_SARIF` | SARIF 파일 경로 (필수) |
| `SR_INTERNAL_KEY` | llm-server 내부 키 (필수) |
| `SR_LLM_URL` | 기본 `http://127.0.0.1:8081` |
| `SR_BUDGET_SEC`, `SR_MAX_HUNKS`, `SR_MAX_FILES` | 기본 45, 20, 20 |

## 워크플로 예시

`action.yml`은 강민재 담당이라 여기서는 예시만 둔다. llm-server를 같은 러너에서 외부 API 모드로 띄운 뒤 실행한다.

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    env:
      SR_INTERNAL_KEY: run-only
      SR_LLM_PROVIDER: openai
      SR_LLM_BASE_URL: https://api.groq.com/openai/v1
      SR_LLM_MODEL: openai/gpt-oss-120b
      SR_LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
      SR_SARIF: ${{ github.workspace }}/spotbugs.sarif   # 분석 단계가 만든 파일
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: '17' }
      # (분석 단계: spotbugs.sarif 생성 — 정성훈·김회승 담당)
      - name: llm-server 실행
        working-directory: llm-server
        run: |
          nohup ./mvnw -q -B compile exec:java "-Dexec.mainClass=secureview.llm.LlmServer" > /tmp/llm.log 2>&1 &
          for i in $(seq 1 120); do curl -sf -H "X-Internal-Key: $SR_INTERNAL_KEY" http://127.0.0.1:8081/internal/health && break; sleep 1; done
      - name: PR 검토
        working-directory: .github/scripts/securereview
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: ./mvnw -q -B compile exec:java
```

## 아직 안 한 것

- 댓글의 "수정 방향"은 LLM 수정안(S6)의 이유 문장이다. 수정 코드를 GitHub `suggestion` 블록으로 올리는 것은 채무진 님의 사전 검증(수정안 적용 후 재분석)을 통과한 것만 하기로 해서 아직 하지 않는다.
- 포크 PR은 토큰이 읽기 전용이라 댓글을 달 수 없다. 이때는 요약을 Actions 실행 화면에 남기고 실패로 끝낸다.
- 포크 PR 권한 부족, 시간 예산 초과는 가짜 서버 테스트로만 확인했다.

## 실제 PR 확인 (2026-11-26)

측정 저장소 asdf1454/secureview-runner-bench의 PR 1에서 `pr-review.yml`(SpotBugs 4.8.6 + FindSecBugs 1.13.0 → SARIF → llm-server Groq `openai/gpt-oss-120b` → 이 실행기)로 확인했다.

| 커밋 | 결과 |
|---|---|
| SQL 인젝션 메서드 추가 | SpotBugs 경고 9개 중 바뀐 줄의 CWE-89 2개(두 규칙, 같은 줄). 진짜 취약점, 댓글에 설명·수정 방향. 8.1초. 같은 줄에 댓글이 두 개 달려 합치기를 추가함 |
| 허용 목록 정렬 추가 | 경고 2건 중 진짜 1, 오탐 추정 1. 5.6초 |
| 위쪽에 상수 한 줄 추가 | 줄 번호가 바뀌었지만 새 댓글 0개. 5.1초 |
| 같은 커밋 재실행 | 요약·댓글 다시 달지 않음 |

분석과 LLM 서버 준비를 포함한 Actions 실행 전체는 32~36초였다(Maven 캐시가 있을 때).

## 테스트

```bash
./mvnw test
```
