import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;

public class VulnerableAuthService {

    // Hardcoded Database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/appdb";
    private static final String USER = "db_admin";
    private static final String PASS = "HardcodedPassword99!";

    // SQL Injection
    public boolean authenticateUser(String username, String password) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
        Statement stmt = conn.createStatement();
        // Dynamic concatenation allows SQL injection bypass
        String sql = "SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next();
    }

    // Broken Cryptography (MD5)
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }
}
