#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <WiFi.h>
#include <XPT2046_Touchscreen.h>

#include "secrets.h"

#define TFT_CS 17
#define TFT_DC 21
#define TFT_RST 22
#define TFT_MOSI 23
#define TFT_MISO 19
#define TFT_SCLK 18

#define TOUCH_CS 16
#define TOUCH_IRQ 4

Adafruit_ILI9341 tft(TFT_CS, TFT_DC, TFT_RST);
XPT2046_Touchscreen touch(TOUCH_CS, TOUCH_IRQ);

unsigned long lastFetchMs = 0;
const unsigned long FETCH_INTERVAL_MS = 3000;
int currentPage = 0;
String lastJson = "{}";

String statusText = "READY";
String threatText = "Waiting for backend";
String reasonText = "Connect Flask dashboard";
String modeText = "monitor";
String sensitivityText = "normal";
int riskScore = 0;

String extractJsonString(const String& json, const String& key, const String& fallback) {
  String searchKey = String("\"") + key + "\"";
  int keyIndex = json.indexOf(searchKey);
  if (keyIndex < 0) return fallback;
  int colonIndex = json.indexOf(':', keyIndex);
  if (colonIndex < 0) return fallback;
  int quoteStart = json.indexOf('"', colonIndex + 1);
  if (quoteStart < 0) return fallback;
  int quoteEnd = json.indexOf('"', quoteStart + 1);
  if (quoteEnd < 0) return fallback;
  return json.substring(quoteStart + 1, quoteEnd);
}

int extractJsonInt(const String& json, const String& key, int fallback) {
  String searchKey = String("\"") + key + "\"";
  int keyIndex = json.indexOf(searchKey);
  if (keyIndex < 0) return fallback;
  int colonIndex = json.indexOf(':', keyIndex);
  if (colonIndex < 0) return fallback;
  int start = colonIndex + 1;
  while (start < json.length() && json.charAt(start) == ' ') start++;
  String number = "";
  while (start < json.length()) {
    char c = json.charAt(start);
    if (!isDigit(c) && c != '-') break;
    number += c;
    start++;
  }
  return number.length() ? number.toInt() : fallback;
}

void header(const String& title) {
  tft.fillScreen(ILI9341_BLACK);
  tft.setRotation(1);
  tft.setTextColor(ILI9341_CYAN);
  tft.setTextSize(2);
  tft.setCursor(10, 9);
  tft.print("WiFiGhost Sentinel");
  tft.setTextColor(ILI9341_LIGHTGREY);
  tft.setTextSize(1);
  tft.setCursor(10, 34);
  tft.print(title);
}

uint16_t stateColor() {
  if (statusText == "ALERT") return ILI9341_RED;
  if (statusText == "WATCH") return ILI9341_ORANGE;
  if (statusText == "SAFE") return ILI9341_GREEN;
  return ILI9341_CYAN;
}

void button(int x, int y, int w, int h, const String& label, uint16_t color) {
  tft.fillRoundRect(x, y, w, h, 6, color);
  tft.drawRoundRect(x, y, w, h, 6, ILI9341_WHITE);
  tft.setTextColor(ILI9341_BLACK);
  tft.setTextSize(1);
  tft.setCursor(x + 8, y + 12);
  tft.print(label);
}

void drawHome() {
  header("live risk and reason");
  uint16_t color = stateColor();
  tft.fillRoundRect(12, 52, 110, 88, 8, color);
  tft.setTextColor(ILI9341_BLACK);
  tft.setTextSize(3);
  tft.setCursor(27, 72);
  tft.print(riskScore);
  tft.setTextSize(1);
  tft.setCursor(32, 112);
  tft.print(statusText);

  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(136, 58);
  tft.print(threatText.substring(0, 18));
  tft.setTextSize(1);
  tft.setCursor(136, 92);
  tft.print(reasonText.substring(0, 28));
  tft.setCursor(136, 110);
  tft.print(reasonText.substring(28, 58));

  button(10, 180, 72, 42, "Pause", ILI9341_ORANGE);
  button(88, 180, 72, 42, "Learn", ILI9341_GREEN);
  button(166, 180, 72, 42, "Page", ILI9341_CYAN);
  button(244, 180, 66, 42, "Demo", ILI9341_RED);
}

void drawDetails() {
  header("details and controls");
  tft.setTextColor(ILI9341_WHITE);
  tft.setTextSize(2);
  tft.setCursor(12, 58);
  tft.print("Status: ");
  tft.print(statusText);
  tft.setCursor(12, 88);
  tft.print("Mode: ");
  tft.print(modeText);
  tft.setCursor(12, 118);
  tft.print("Sens: ");
  tft.print(sensitivityText);
  tft.setTextSize(1);
  tft.setCursor(12, 154);
  tft.print("Use dashboard for full evidence table.");
  button(10, 180, 92, 42, "Page", ILI9341_CYAN);
  button(112, 180, 92, 42, "Pause", ILI9341_ORANGE);
  button(214, 180, 96, 42, "Learn", ILI9341_GREEN);
}

void drawScreen() {
  if (currentPage % 2 == 0) drawHome();
  else drawDetails();
}

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  header("connecting Wi-Fi");
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(350);
    tft.print(".");
    attempts++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    header("Wi-Fi connected");
    tft.setTextColor(ILI9341_WHITE);
    tft.setTextSize(1);
    tft.setCursor(10, 62);
    tft.print("SSID: ");
    tft.print(WIFI_SSID);
    tft.setCursor(10, 82);
    tft.print("ESP32 IP: ");
    tft.print(WiFi.localIP());
    delay(1200);
    drawScreen();
  } else {
    statusText = "NO WIFI";
    riskScore = 0;
    threatText = "Wi-Fi failed";
    reasonText = "Check SSID/password and hotspot";
    drawScreen();
  }
}

void fetchState() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
    return;
  }
  HTTPClient http;
  http.begin(API_STATE_URL);
  int code = http.GET();
  String response = http.getString();
  http.end();

  if (code <= 0 || response.length() < 5) {
    statusText = "OFFLINE";
    riskScore = 0;
    threatText = "Backend offline";
    reasonText = "Check laptop IP and port 5000";
    drawScreen();
    tft.setTextColor(ILI9341_YELLOW);
    tft.setTextSize(1);
    tft.setCursor(12, 148);
    tft.print("API: ");
    tft.print(String(API_STATE_URL).substring(7, 29));
    return;
  }

  lastJson = response;
  statusText = extractJsonString(response, "status", "READY");
  threatText = extractJsonString(response, "threat", "No threat");
  reasonText = extractJsonString(response, "top_reason", "No reason yet");
  modeText = extractJsonString(response, "mode", "monitor");
  sensitivityText = extractJsonString(response, "sensitivity", "normal");
  riskScore = extractJsonInt(response, "risk_score", 0);
  currentPage = extractJsonInt(response, "device_page", currentPage);
  drawScreen();
}

void sendControl(const String& action) {
  if (WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  http.begin(API_CONTROL_URL);
  http.addHeader("Content-Type", "application/json");
  String payload = String("{\"action\":\"") + action + "\"}";
  http.POST(payload);
  http.end();
  delay(250);
  fetchState();
}

void handleTouch() {
  if (!touch.touched()) return;
  TS_Point p = touch.getPoint();
  int x = map(p.x, 200, 3900, 0, 320);
  int y = map(p.y, 200, 3900, 0, 240);
  y = 240 - y;

  if (y < 170) return;
  if (x < 82) sendControl("toggle_pause");
  else if (x < 160) sendControl("learn_current");
  else if (x < 238) sendControl("cycle_page");
  else sendControl("demo_mixed");
}

void setup() {
  Serial.begin(115200);
  SPI.begin(TFT_SCLK, TFT_MISO, TFT_MOSI, TFT_CS);
  tft.begin();
  tft.setRotation(1);
  touch.begin();
  touch.setRotation(1);
  connectWiFi();
  fetchState();
}

void loop() {
  handleTouch();
  if (millis() - lastFetchMs > FETCH_INTERVAL_MS) {
    lastFetchMs = millis();
    fetchState();
  }
}
