import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.owasp.encoder.Encode;

public class Cwe79 {
    public void direct(HttpServletRequest req, HttpServletResponse res) throws IOException {
        PrintWriter out = res.getWriter();
        out.println("<h1>" + req.getParameter("name") + "</h1>"); // expect: TRUE_POSITIVE
    }

    public void viaVariable(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String q = req.getParameter("q");
        String html = "<p>Search: " + q + "</p>";
        res.getWriter().write(html); // expect: TRUE_POSITIVE
    }

    public void encoded(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String safe = Encode.forHtml(req.getParameter("name"));
        res.getWriter().println("<h1>" + safe + "</h1>"); // expect: LIKELY_FALSE_POSITIVE
    }

    public void constant(HttpServletResponse res) throws IOException {
        res.getWriter().println("<h1>Welcome</h1>"); // expect: LIKELY_FALSE_POSITIVE
    }
}
