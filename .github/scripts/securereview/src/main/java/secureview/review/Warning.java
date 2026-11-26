package secureview.review;

/** 정적 분석 경고 하나. path는 SARIF에 적힌 그대로라 저장소 상대 경로가 아닐 수 있다. */
public record Warning(String path, int line, String cwe, String severity, String ruleId, String title,
                      String message, String tool) {

    /**
     * 경고 경로와 PR 파일 경로가 같은 파일을 가리키면 true. 분석 도구는 소스 루트 기준(secureview/A.java)이나
     * 절대 경로를 쓰기도 하므로, 짧은 쪽이 긴 쪽의 끝 경로 조각과 같으면 같은 파일로 본다.
     */
    public boolean matches(String repoPath) {
        String a = normalize(path);
        String b = normalize(repoPath);
        return a.equals(b) || a.endsWith("/" + b) || b.endsWith("/" + a);
    }

    private static String normalize(String p) {
        String n = p.replace('\\', '/');
        return n.startsWith("./") ? n.substring(2) : n;
    }
}
