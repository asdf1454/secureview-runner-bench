package secureview.review;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** GitHub API와 LLM 서버 호출 공통. 응답 코드가 2xx가 아니면 {@link Failure}. 오류 메시지에 토큰·키를 넣지 않는다. */
final class Http {

    static final class Failure extends RuntimeException {
        final int status;

        Failure(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private final HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NORMAL).build();

    String send(String method, URI uri, Map<String, String> headers, String body, Duration timeout) {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(timeout)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(b::header);
        try {
            HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() / 100 != 2) {
                String text = r.body().length() > 300 ? r.body().substring(0, 300) + "…" : r.body();
                throw new Failure(r.statusCode(), method + " " + uri.getPath() + " 응답 코드 " + r.statusCode() + ": " + text);
            }
            return r.body();
        } catch (IOException e) {
            throw new Failure(0, method + " " + uri.getHost() + uri.getPath() + " 연결 실패: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new Failure(0, "호출 중단");
        }
    }
}
