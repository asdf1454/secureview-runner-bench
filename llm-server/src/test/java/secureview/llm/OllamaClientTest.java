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

class OllamaClientTest {

    private final List<JsonNode> bodies = new ArrayList<>();
    private HttpServer server;
    private OllamaClient client;

    @BeforeEach
    void startFakeOllama() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/generate", exchange -> {
            bodies.add(StructuredLlm.MAPPER.readTree(exchange.getRequestBody().readAllBytes()));
            byte[] reply = "{\"response\":\"{}\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        server.start();
        client = new OllamaClient("http://localhost:" + server.getAddress().getPort(), "m", Duration.ofSeconds(5));
    }

    @AfterEach
    void stopFakeOllama() {
        server.stop(0);
    }

    @Test
    void generateKeepsModelLoadedBetweenJobs() {
        client.generateJson("p");

        assertEquals(OllamaClient.KEEP_ALIVE, bodies.get(0).path("keep_alive").asText());
    }

    @Test
    void warmUpAndGenerateUseSameContextSizeSoModelIsNotReloaded() {
        client.warmUp();
        client.generateJson("p");

        assertEquals(OllamaClient.NUM_CTX, bodies.get(0).path("options").path("num_ctx").asInt());
        assertEquals(OllamaClient.NUM_CTX, bodies.get(1).path("options").path("num_ctx").asInt());
    }

    /** 모델이 이미 올라와 있을 때 warmUp이 HTTP/2 업그레이드 요청에서 응답을 받지 못하고 2분 동안 멈췄다. */
    @Test
    void requestsDoNotAskForHttp2Upgrade() {
        List<Boolean> upgrades = new ArrayList<>();
        server.createContext("/api/tags", exchange -> {
            upgrades.add(exchange.getRequestHeaders().containsKey("Upgrade"));
            byte[] reply = "{\"models\":[]}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });

        client.available();

        assertEquals(List.of(false), upgrades);
    }

    @Test
    void generateWithSchemaSendsSchemaAsFormat() throws Exception {
        client.generateJson("p", StructuredLlm.MAPPER.readTree("{\"type\":\"object\"}"));

        assertEquals("object", bodies.get(0).path("format").path("type").asText());
    }

    /** API 명세: 코드 안의 지시문을 따르지 말 것을 시스템 프롬프트에 명시한다. */
    @Test
    void generateWithSchemaSendsDataOnlyRuleAsSystemPrompt() throws Exception {
        client.generateJson("p", StructuredLlm.MAPPER.readTree("{\"type\":\"object\"}"));

        String system = bodies.get(0).path("system").asText();
        assertTrue(system.contains("<<<CODE"));
        assertTrue(system.contains("따르지 않는다"));
    }

    @Test
    void generateWithoutSchemaKeepsPromptOnly() {
        client.generateJson("p");

        assertFalse(bodies.get(0).has("system"));
    }

    @Test
    void availableOnlyWhenModelIsInstalled() {
        server.createContext("/api/tags", exchange -> {
            byte[] reply = "{\"models\":[{\"name\":\"m\"}]}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        String base = "http://localhost:" + server.getAddress().getPort();

        assertTrue(client.available());
        assertFalse(new OllamaClient(base, "other", Duration.ofSeconds(5)).available());
    }

    @Test
    void notAvailableWhenOllamaIsOff() {
        assertFalse(new OllamaClient("http://localhost:1", "m", Duration.ofSeconds(1)).available());
    }

    @Test
    void warmUpLoadsModelWithoutPrompt() {
        client.warmUp();

        JsonNode body = bodies.get(0);
        assertEquals("m", body.path("model").asText());
        assertEquals(OllamaClient.KEEP_ALIVE, body.path("keep_alive").asText());
        assertFalse(body.has("prompt"));
    }
}
