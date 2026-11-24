package secureview.llm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

/**
 * API 명세의 LLM 서버 내부 API: POST /internal/judge, GET /internal/health.
 * 환경 변수: SR_INTERNAL_KEY(필수), SR_LLM_HOST(기본 127.0.0.1, 배포 때 VPN 주소), SR_LLM_PORT(기본 8081), OLLAMA_URL.
 * 외부 API: SR_LLM_PROVIDER=openai, SR_LLM_BASE_URL(필수), SR_LLM_MODEL(필수), SR_LLM_API_KEY.
 * Ollama /v1을 쓸 때는 Ollama 쪽에 OLLAMA_CONTEXT_LENGTH=8192, OLLAMA_KEEP_ALIVE=24h를 설정한다(README 참고).
 */
public final class LlmServer {

    /** 업로드 상한 1MB 파일을 JSON에 담은 크기까지 받는다. */
    static final int MAX_BODY_BYTES = 4 * 1024 * 1024;

    private final JudgeService judge;
    private FixApiService fixes;
    private final String model;
    private final BooleanSupplier available;
    private final BooleanSupplier ready;
    private final byte[] key;
    private HttpServer server;
    private ExecutorService requests;

    public LlmServer(JudgeService judge, String model, BooleanSupplier available, String key) {
        this(judge, model, available, () -> true, key);
    }

    /** @param ready 모델이 메모리에 올라왔으면 true. 그 전에는 판정 요청을 받지 않는다 */
    public LlmServer(JudgeService judge, String model, BooleanSupplier available, BooleanSupplier ready, String key) {
        this.judge = judge;
        this.model = model;
        this.available = available;
        this.ready = ready;
        this.key = key.getBytes(StandardCharsets.UTF_8);
    }

    /** POST /internal/fix를 켠다. 설정하지 않으면 그 주소는 404다. */
    public LlmServer withFixes(FixApiService fixes) {
        this.fixes = fixes;
        return this;
    }

    public void start(String host, int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/", this::handle);
        requests = Executors.newFixedThreadPool(8);
        server.setExecutor(requests);
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void stop() {
        server.stop(0);
        requests.shutdownNow();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            try {
                route(exchange);
            } catch (JsonProcessingException e) {
                error(exchange, 400, "INVALID_INPUT", "요청 JSON 형식이 맞지 않습니다.");
            } catch (IllegalArgumentException e) {
                error(exchange, 400, "INVALID_INPUT", e.getMessage());
            } catch (IOException e) {
                throw e;
            } catch (LlmUnavailableException e) {
                error(exchange, 503, "INTERNAL_ERROR", "LLM을 사용할 수 없습니다. Ollama 실행 여부를 확인하세요.");
            } catch (RuntimeException e) {
                e.printStackTrace();
                error(exchange, 500, "INTERNAL_ERROR", "서버 오류가 발생했습니다.");
            }
        }
    }

    private void route(HttpExchange exchange) throws IOException {
        if (!authorized(exchange)) {
            error(exchange, 401, "UNAUTHORIZED", "내부 API 키가 없거나 틀렸습니다.");
            return;
        }
        String path = exchange.getRequestURI().getPath();
        String method = exchange.getRequestMethod();
        boolean fix = fixes != null && path.equals("/internal/fix");
        if ((path.equals("/internal/judge") || fix) && method.equals("POST")) {
            byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
            if (body.length > MAX_BODY_BYTES) {
                exchange.getRequestBody().transferTo(OutputStream.nullOutputStream()); // 다 받아야 클라이언트가 응답을 읽는다.
                error(exchange, 413, "FILE_TOO_LARGE", "요청이 너무 큽니다.");
                return;
            }
            if (!ready.getAsBoolean()) {
                // 올라오는 중에 판정을 시작하면 30초 제한이 모델 올리기까지 끊어, 끝내 올라오지 못한다.
                error(exchange, 503, "INTERNAL_ERROR", "모델을 올리는 중입니다. 잠시 뒤 다시 시도하세요.");
                return;
            }
            send(exchange, 200, fix
                    ? fixes.fix(StructuredLlm.MAPPER.readValue(body, FixRequest.class))
                    : judge.judge(StructuredLlm.MAPPER.readValue(body, JudgeRequest.class)));
        } else if (path.equals("/internal/health") && method.equals("GET")) {
            boolean up = ready.getAsBoolean() && available.getAsBoolean();
            send(exchange, up ? 200 : 503, Map.of("status", up ? "UP" : "DOWN", "model", model));
        } else {
            error(exchange, 404, "NOT_FOUND", "없는 주소입니다.");
        }
    }

    private boolean authorized(HttpExchange exchange) {
        String given = exchange.getRequestHeaders().getFirst("X-Internal-Key");
        return given != null && MessageDigest.isEqual(key, given.getBytes(StandardCharsets.UTF_8));
    }

    private static void error(HttpExchange exchange, int status, String error, String message) throws IOException {
        send(exchange, status, Map.of("error", error, "message", message));
    }

    private static void send(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] json = StructuredLlm.MAPPER.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, json.length);
        exchange.getResponseBody().write(json);
    }

    public static void main(String[] args) throws IOException {
        String key = System.getenv("SR_INTERNAL_KEY");
        if (key == null || key.isBlank()) {
            System.err.println("환경 변수 SR_INTERNAL_KEY를 설정하세요.");
            System.exit(1);
        }
        String host = System.getenv().getOrDefault("SR_LLM_HOST", "127.0.0.1");
        int port = Integer.parseInt(System.getenv().getOrDefault("SR_LLM_PORT", "8081"));
        String ollama = System.getenv().getOrDefault("OLLAMA_URL", "http://localhost:11434");

        // 모델 올리기(warmUp)는 메모리가 부족한 PC에서 3분 넘게 걸린 적이 있어, 판정용(2분)보다 길게 기다린다.
        LlmClient client;
        String model;
        BooleanSupplier available;
        Runnable warmUp;
        String target;
        if ("openai".equals(System.getenv("SR_LLM_PROVIDER"))) {
            String baseUrl = System.getenv("SR_LLM_BASE_URL");
            String apiKey = System.getenv("SR_LLM_API_KEY");
            model = System.getenv("SR_LLM_MODEL");
            if (baseUrl == null || baseUrl.isBlank() || model == null || model.isBlank()) {
                System.err.println("SR_LLM_PROVIDER=openai이면 SR_LLM_BASE_URL과 SR_LLM_MODEL을 설정하세요.");
                System.exit(1);
            }
            client = new OpenAiCompatibleClient(baseUrl, apiKey, model, Duration.ofMinutes(2));
            available = () -> true;
            warmUp = new OpenAiCompatibleClient(baseUrl, apiKey, model, Duration.ofMinutes(10))::warmUp;
            target = "외부 API " + baseUrl + ", 모델 " + model;
        } else {
            OllamaClient ollamaClient = new OllamaClient(ollama, OllamaClient.DEFAULT_MODEL, Duration.ofMinutes(2));
            client = ollamaClient;
            model = ollamaClient.model();
            available = ollamaClient::available;
            warmUp = new OllamaClient(ollama, OllamaClient.DEFAULT_MODEL, Duration.ofMinutes(10))::warmUp;
            target = "모델 " + model;
        }

        AtomicBoolean ready = new AtomicBoolean();
        LlmServer server = new LlmServer(new JudgeService(client, model, JudgeService.TIME_LIMIT),
                model, available, ready::get, key)
                .withFixes(new FixApiService(client, model, FixApiService.TIME_LIMIT));
        server.start(host, port);
        System.out.println("LLM 서버 시작: http://" + host + ":" + port + " (" + target
                + "). 모델을 올리는 중이며, 끝나면 /internal/health가 UP이 됩니다.");

        // 모델이 올라올 때까지 계속 시도한다. Ollama가 나중에 켜져도 따로 다시 시작할 필요가 없다.
        while (!ready.get()) {
            try {
                warmUp.run();
                ready.set(true);
                System.out.println("모델 준비 완료");
            } catch (LlmException e) {
                System.err.println("모델을 올리지 못했습니다. 5초 뒤 다시 시도합니다: " + e.getMessage());
                try {
                    Thread.sleep(5_000);
                } catch (InterruptedException interrupted) {
                    return;
                }
            }
        }
    }
}
