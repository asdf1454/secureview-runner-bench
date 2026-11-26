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

댓글 끝에 `<!-- securereview-id: headSha:findingId -->`, 요약 끝에 `<!-- securereview-summary: headSha -->`를 붙인다. 같은 커밋에서 다시 실행하면 이미 단 댓글과 요약은 다시 달지 않는다. 커밋이 바뀌면 새로 단다. 예전 댓글은 지우지 않는다.

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
- 실제 PR에서 끝까지 돌려 본 적은 아직 없다. 테스트는 가짜 GitHub·LLM 서버로 했다.

## 테스트

```bash
./mvnw test
```
