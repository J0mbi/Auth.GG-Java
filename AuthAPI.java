package me.jombi.security;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AuthAPI {
    private final String apikey, secret, authorization, aid;

    public AuthAPI(String apikey, String secret, String authorization, String aid) {
        this.apikey = apikey;
        this.secret = secret;
        this.authorization = authorization;
        this.aid = aid;
    }
    // User
    public String login(String user, String pass) throws Exception {
        String url = "https://api.auth.gg/v1/", charset = StandardCharsets.UTF_8.name(), hwid = getHWID();

        String query = String.format("type=login&hwid=%s&password=%s&username=%s&secret=%s&apikey=%s&aid=%s",
                URLEncoder.encode(hwid, charset),
                URLEncoder.encode(pass, charset),
                URLEncoder.encode(user, charset),
                URLEncoder.encode(secret, charset),
                URLEncoder.encode(apikey, charset),
                URLEncoder.encode(aid, charset));

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setDoOutput(true);
        connection.setRequestProperty("Accept-Charset", charset);
        connection.setRequestProperty("User-Agent", "Jombi");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);
        try (OutputStream output = connection.getOutputStream()) {
            output.write(query.getBytes(charset));
        }

        InputStream response = connection.getInputStream();
        if (connection.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(response));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());
            if (!element.getAsJsonObject().get("result").getAsString().equalsIgnoreCase("failed")) {
                return element.getAsString();
            }
            return element.getAsJsonObject().get("result").getAsString();
        }
        return "failed";
    }

    public String register(String email, String user, String pass, String license) throws Exception {
        String url = "https://api.auth.gg/v1/", charset = StandardCharsets.UTF_8.name(), hwid = getHWID();

        String query = String.format("type=register&aid=%s&apikey=%s&secret=%s&username=%s&password=%s&hwid=%s&license=%s&email=%s",
                URLEncoder.encode(aid, charset),
                URLEncoder.encode(apikey, charset),
                URLEncoder.encode(secret, charset),
                URLEncoder.encode(user, charset),
                URLEncoder.encode(pass, charset),
                URLEncoder.encode(hwid, charset),
                URLEncoder.encode(license, charset),
                URLEncoder.encode(email, charset));

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setDoOutput(true);
        connection.setRequestProperty("Accept-Charset", charset);
        connection.setRequestProperty("User-Agent", "Jombi");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);
        try (OutputStream output = connection.getOutputStream()) {
            output.write(query.getBytes(charset));
        }

        InputStream response = connection.getInputStream();
        if (connection.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(response));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());
            return element.getAsJsonObject().get("result").getAsString();
        }
        return "failed";
    }

    public String extend(String user, String pass, String license) throws Exception {
        String url = "https://api.auth.gg/v1/", charset = StandardCharsets.UTF_8.name();

        String query = String.format("type=extend&aid=%s&apikey=%s&secret=%s&username=%s&password=%s&license=%s",
                URLEncoder.encode(aid, charset),
                URLEncoder.encode(apikey, charset),
                URLEncoder.encode(secret, charset),
                URLEncoder.encode(user, charset),
                URLEncoder.encode(pass, charset),
                URLEncoder.encode(license, charset));

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setDoOutput(true);
        connection.setRequestProperty("Accept-Charset", charset);
        connection.setRequestProperty("User-Agent", "Jombi");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);
        try (OutputStream output = connection.getOutputStream()) {
            output.write(query.getBytes(charset));
        }

        InputStream response = connection.getInputStream();
        if (connection.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(response));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());
            return element.getAsJsonObject().get("result").getAsString();
        }
        return "failed";
    }

    public String log(String action, String pcuser, String uesrname) throws Exception {
        String url = "https://api.auth.gg/v1/", charset = StandardCharsets.UTF_8.name();
// ...

        String query = String.format("type=log&aid=%s&apikey=%s&secret=%s&username=%s&pcuser=%s&action=%s",
                URLEncoder.encode(aid, charset),
                URLEncoder.encode(apikey, charset),
                URLEncoder.encode(secret, charset),
                URLEncoder.encode(uesrname, charset),
                URLEncoder.encode(pcuser, charset),
                URLEncoder.encode(action, charset));

        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setDoOutput(true);
        connection.setRequestProperty("Accept-Charset", charset);
        connection.setRequestProperty("User-Agent", "Jombi");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded;charset=" + charset);
        try (OutputStream output = connection.getOutputStream()) {
            output.write(query.getBytes(charset));
        }

        InputStream response = connection.getInputStream();
        if (connection.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(response));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());
            return element.getAsJsonObject().get("result").getAsString();
        }
        return "failed";
    }

    // Admin
    public String fetchAllUsers() throws Exception {
        URL url = new URL("https://developers.auth.gg/USERS/?type=fetchall&authorization=" + authorization);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("User-Agent", "Jombi");
        System.out.println(con.getResponseCode());
        System.out.println(con.getResponseMessage());
        if (con.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());
            List<String> users = new ArrayList<>();
            for (int i = 0; i < sb.length(); i++) {
                users.add(element.getAsJsonObject().get(String.valueOf(i)).getAsString());
            }
            return String.valueOf(users);
        }

        return "failed";
    }

    public String deleteUser(String user) throws Exception {
        URL url = new URL("https://developers.auth.gg/USERS/?type=delete&user=" + user + "&authorization=" + authorization);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("User-Agent", "Jombi");
        System.out.println(con.getResponseCode());
        System.out.println(con.getResponseMessage());
        if (con.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());

            return element.getAsJsonObject().get("info").getAsString();
        }

        return "failed";
    }

    public String countUser() throws Exception {
        URL url = new URL("https://developers.auth.gg/USERS/?type=count&authorization=" + authorization);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("User-Agent", "Jombi");
        System.out.println(con.getResponseCode());
        System.out.println(con.getResponseMessage());
        if (con.getResponseCode() == 200) {
            BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JsonParser parser = new JsonParser();
            JsonElement element = parser.parse(sb.toString());

            if (element.getAsJsonObject().get("status").getAsString().equalsIgnoreCase("failed"))
                return element.getAsJsonObject().get("info").getAsString();
            else
                return element.getAsJsonObject().get("value").getAsString();
        }

        return "failed";
    }

    public String getHWID() {
        try {
            String toEncrypt = System.getenv("PROCESSOR_IDENTIFIER") + System.getenv("PROCESSOR_LEVEL");
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(toEncrypt.getBytes());
            StringBuilder hexString = new StringBuilder();

            byte[] byteData = md.digest();

            for (byte aByteData : byteData) {
                String hex = Integer.toHexString(0xff & aByteData);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error";
        }
    }
}
