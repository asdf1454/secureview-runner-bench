package secureview.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OpenAiCompatibleClientTest {

    private final List<JsonNode> bodies = new ArrayList<>();
    private final List<String> auth = new ArrayList<>();
    private HttpServer server;
    private String base;
    private int status = 200;
    private String reply = "{\"choices\":[{\"message\":{\"content\":\"{\\\"ok\\\":true}\"}}]}";

    @BeforeEach
    void startFakeApi() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            bodies.add(StructuredLlm.MAPPER.readTree(exchange.getRequestBody().readAllBytes()));
            auth.add(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = reply.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        base = "http://localhost:" + server.getAddress().getPort() + "/v1";
    }

    @AfterEach
    void stopFakeApi() {
        server.stop(0);
    }

    private OpenAiCompatibleClient client(String key) {
        return new OpenAiCompatibleClient(base, key, "m", Duration.ofSeconds(5));
    }

    @Test
    void returnsMessageContent() {
        assertEquals("{\"ok\":true}", client("k").generateJson("p"));
    }

    @Test
    void sendsApiKeyAsBearerToken() {
        client("secret").generateJson("p");

        assertEquals("Bearer secret", auth.get(0));
    }

    /** 팀 PC의 Ollama(/v1)는 키가 필요 없다. */
    @Test
    void sendsNoAuthorizationWithoutKey() {
        client(null).generateJson("p");

        assertNull(auth.get(0));
    }

    @Test
    void sendsModelPromptAndLowTemperature() {
        client("k").generateJson("p");

        JsonNode body = bodies.get(0);
        assertEquals("m", body.path("model").asText());
        assertEquals(0.1, body.path("temperature").asDouble());
        assertEquals("user", body.path("messages").get(0).path("role").asText());
        assertEquals("p", body.path("messages").get(0).path("content").asText());
        assertEquals("json_object", body.path("response_format").path("type").asText());
    }

    @Test
    void generateWithSchemaSendsSchemaAndSystemPrompt() throws Exception {
        client("k").generateJson("p", StructuredLlm.MAPPER.readTree("{\"type\":\"object\"}"));

        JsonNode body = bodies.get(0);
        assertEquals("json_schema", body.path("response_format").path("type").asText());
        assertEquals("object", body.path("response_format").path("json_schema").path("schema").path("type").asText());
        JsonNode system = body.path("messages").get(0);
        assertEquals("system", system.path("role").asText());
        assertTrue(system.path("content").asText().contains("<<<CODE"));
        assertEquals("p", body.path("messages").get(1).path("content").asText());
    }

    @Test
    void errorStatusThrowsLlmException() {
        status = 401;
        reply = "{\"error\":\"bad key\"}";

        LlmException e = assertThrows(LlmException.class, () -> client("k").generateJson("p"));
        assertFalse(e instanceof LlmUnavailableException);
        assertTrue(e.getMessage().contains("401"));
    }

    @Test
    void connectionFailureThrowsUnavailable() {
        OpenAiCompatibleClient off = new OpenAiCompatibleClient("http://localhost:1/v1", "k", "m", Duration.ofSeconds(1));

        assertThrows(LlmUnavailableException.class, () -> off.generateJson("p"));
    }

    /** Ollama /v1은 모델을 미리 올리지 않아, 첫 판정이 모델 올리기를 기다리다 30초 제한에 걸렸다. */
    @Test
    void warmUpSendsOneShortRequest() {
        client("k").warmUp();

        assertEquals(1, bodies.size());
        assertEquals("m", bodies.get(0).path("model").asText());
    }

    @Test
    void warmUpFailureThrows() {
        OpenAiCompatibleClient off = new OpenAiCompatibleClient("http://localhost:1/v1", "k", "m", Duration.ofSeconds(1));

        assertThrows(LlmUnavailableException.class, off::warmUp);
    }

    @Test
    void errorMessageDoesNotLeakApiKey() {
        status = 500;
        reply = "{}";

        LlmException e = assertThrows(LlmException.class, () -> client("secret-key").generateJson("p"));
        assertFalse(e.getMessage().contains("secret-key"));
    }
}
