/*
  SECURITY ROBOT (Robot 2) - ESP32 (30-pin)  |  ROBOHAUL fleet ka hissa
  --------------------------------------------------------------------
  - Apna alag Wi-Fi dashboard: phone ko "SECURITY_AP" se jodo, browser me 192.168.4.1 kholo.
  - Sensors: HC-SR04, DHT11, MQ-2 gas/smoke, flame sensor, OLED. Servo/camera nahi.
  - ALERT system: fire / gas / garmi / paas aati cheez -> buzzer + LED + OLED + dashboard banner/vibration (dashboard open ho to).
  - SOS: dashboard ka virtual button. Internet ki zaroorat nahi.
      * Local: siren + OLED + dashboard + Robot 1 (fleet) ko alert.
      * Dispatch panel sirf local demo/event log hai; koi SMS ya external service message nahi bheja jata.
  - Robot 1 ke dashboard ke "Security" tab se bhi control hota hai (ESP-NOW).

  NAYA (is version me):
    * Professional dispatch message (Incident / Priority / Location / Robot / Time / Mode / Sensors / Action).
    * MANUAL mode (pehle jaisa) aur AUTO PATROL mode.
    * Fixed route: dashboard se route likho, jaise  F3000,R700,F3000,R700
        F = aage, B = peeche, L = left ghumo, R = right ghumo, S = ruko  (number = milliseconds)
      Route flash (Preferences) me save hota hai, reboot ke baad bhi yaad rahega.
    * Patrol Start / Stop, Loop on/off, Patrol speed.
    * AUTO me safety: obstacle (<STOP_CM) pe aage ruk jata hai, fire/gas/SOS pe patrol hold,
      E-STOP hamesha kaam karta hai. AUTO me manual drive band rehti hai.

  Libraries (Library Manager):
    - Adafruit SSD1306 + Adafruit GFX
    - DHT sensor library (Adafruit) + Adafruit Unified Sensor
  Built-in: WiFi, WebServer, esp_now, Wire, Preferences

  SETUP
    1) DASH_MAC me Robot 1 ka MAC daalo (Robot 1 dashboard -> Fleet tab). Robot 1 se jodna na ho to waise hi chhod do.
    2) LOCATION_TEXT me demo ka fixed location label likho (GPS location nahi).
    3) Upload karo. Serial Monitor (115200) / OLED par is robot ka MAC dikhega - use Robot 1 ke Fleet tab me add karo.
    4) Route ke turn time (R700 / L700) ko apne robot ke hisaab se calibrate karo (90 degree ghumne me jitna time lage).

  PIN MAP (default - apni wiring ke hisaab se sirf number badlo)
    L298N : ENA 25, IN1 26, IN2 27 (left)   IN3 14, IN4 13, ENB 32 (right)
    HC-SR04: TRIG 5, ECHO 34 (voltage divider 5V->3.3V zaroori!)
    MQ-2 AO 35 (analog), Fire sensor DO 33, DHT 4
    Buzzer 15, LED 2. GPIO 18, 19, 16, 17 free.
    OLED SSD1306 I2C: SDA 21, SCL 22
*/

#include <WiFi.h>
#include <WebServer.h>
#include <esp_now.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <DHT.h>
#include <Preferences.h>
#include <time.h>
#include <sys/time.h>

// ---------------- PINS ----------------
#define ENA 25
#define IN1 26
#define IN2 27
#define IN3 14
#define IN4 13
#define ENB 32
#define PIN_TRIG 5
#define PIN_ECHO 34
#define PIN_MQ2 35
#define PIN_FIRE 33
#define PIN_DHT 4
#define PIN_BUZZER 15
#define PIN_LED 2
#define PIN_SDA 21
#define PIN_SCL 22

// ---------------- SETTINGS ----------------
#define AP_SSID "SECURITY_AP"
#define AP_PASS "123456789"          // min 8 characters
#define AP_CHANNEL 1                   // Robot 1 ke AP_CHANNEL jaisa hi rakho
#define LOCATION_TEXT "Main Gate, Block A"   // fixed label only; GPS nahi
#define DASH_MAC "AA:BB:CC:DD:EE:FF"   // Robot 1 ka MAC (jodna ho to badlo)
#define DHT_TYPE DHT11                 // DHT22 ho to DHT22 likho
#define FIRE_LEVEL LOW                 // fire sensor aag pe LOW deta hai
#define GAS_ALERT 2000                 // MQ-2 ADC (0-4095) is se upar = gas/dhuan alert
#define GAS_WARMUP_MS 20000            // MQ-2 garam hone ka time
#define TEMP_ALERT 50                  // is se zyada garmi = alert (C)
#define NEAR_CM 30                     // is se paas cheez = "object near" warning
#define STOP_CM 15                     // aage chalte waqt is se paas pe rukk jao

// ---- SOS / DISPATCH ----
#define AUTO_DISPATCH 1                // 1 = fire / gas aate hi apne aap message
#define COOLDOWN_MS 120000UL           // ek hi alert ka message dobara itni der baad

// ---- AUTO PATROL / FIXED ROUTE ----
#define MAX_STEPS 24                   // route me max steps
#define DEFAULT_ROUTE "F3000,R700,F3000,R700,F3000,R700,F3000,R700"   // chhota square loop
#define DEFAULT_PATROL_SPEED 150       // 80..255

// ---------------- PACKETS (Robot 1 ke saath same) ----------------
#define HB_MAGIC 0x52483142UL
#define SEC_MAGIC_T 0x53454354UL
#define SEC_MAGIC_C 0x53454343UL
struct __attribute__((packed)) HB { uint32_t magic; char rid[8]; char st[12]; uint8_t pct; uint8_t cmd; };
struct __attribute__((packed)) SecTelem { uint32_t magic; int16_t dist; int8_t temp; uint8_t hum; uint16_t gas; uint8_t servo; uint8_t flags; };
struct __attribute__((packed)) SecCmd { uint32_t magic; uint8_t type; int16_t a; int16_t b; };
// SecCmd type: 1=drive 2=ignored (no servo) 3=horn 4=clear E-STOP 5=SOS 6=SOS cancel
//              7=AUTO mode + patrol start   8=MANUAL mode (patrol stop)

// ---------------- OBJECTS / STATE ----------------
WebServer server(80);
Adafruit_SSD1306 oled(128, 64, &Wire, -1);
DHT dht(PIN_DHT, DHT_TYPE);
Preferences prefs;

String state = "READY", myMac = "", myRid = "";
volatile bool estop = false;
volatile int manL = 0, manR = 0;
volatile unsigned long lastDrive = 0, hornUntil = 0;
const int servoTarget = 90; // packet compatibility only; no physical servo fitted
volatile bool pendSos = false, pendSosOff = false, pendTest = false;
float distCm = 999, tempC = 0, hum = 0;
int gasVal = 0;
uint8_t flags = 0;                 // bit0 fire, bit1 gas, bit2 temp, bit3 near
int alertLevel = 0;                // 0 clear, 1 warning, 2 critical, 3 SOS
String alertText = "ALL CLEAR", alertShort = "OK";
bool sosActive = false, muted = false;
bool oledOk = false, fleetOk = false;
uint8_t dashMac[6];
unsigned long lastSensor = 0, lastDht = 0, lastGas = 0, lastOled = 0, lastTel = 0, lastHb = 0, lastFleetRx = 0;
unsigned long lastSosDisp = 0, lastFireDisp = 0, lastGasDisp = 0;

// ---- Mode / patrol state ----
struct Step { char d; uint16_t ms; };
Step route[MAX_STEPS];
int routeLen = 0;
String routeStr = DEFAULT_ROUTE;
volatile bool autoMode = false;    // false = MANUAL, true = AUTO PATROL
bool patrolRun = false, routeLoop = true;
int autoSpeed = DEFAULT_PATROL_SPEED;
int stepIdx = 0, autoL = 0, autoR = 0;
unsigned long stepElapsed = 0, laps = 0;
String holdReason = "";

// Local-only dispatch demo records (no phone numbers and no SMS hardware).
struct Svc { const char *name; String st; String when; };
Svc svcs[4] = {
  {"Police", "NOT SENT - local demo only", "-"},
  {"Fire Brigade", "NOT SENT - local demo only", "-"},
  {"Ambulance", "NOT SENT - local demo only", "-"},
  {"Local Security", "NOT SENT - local demo only", "-"}
};
String lastMsg = "-";
String events[12];
int evCount = 0;

void backgroundTasks();

// ---------------- PWM helper (ESP32 core 2.x & 3.x) ----------------
void pwmInit(int pin, int ch) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  ledcAttachChannel(pin, 1000, 8, ch);
#else
  ledcSetup(ch, 1000, 8);
  ledcAttachPin(pin, ch);
#endif
}
void pwmWrite(int pin, int ch, int duty) {
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  ledcWrite(pin, duty);
#else
  ledcWrite(ch, duty);
#endif
}

// ---------------- TIME / LOG ----------------
bool timeIsSet() { return time(nullptr) > 1600000000; }   // phone se dashboard khulte hi set hota hai
String stamp() {
  char b[12];
  if (timeIsSet()) {
    time_t n = time(nullptr); struct tm t; gmtime_r(&n, &t);
    strftime(b, sizeof(b), "%H:%M:%S", &t);
  } else {
    unsigned long s = millis() / 1000;
    sprintf(b, "%02lu:%02lu:%02lu", s / 3600, (s / 60) % 60, s % 60);
  }
  return String(b);
}
String stampFull() {
  if (!timeIsSet()) return "up " + stamp();
  char b[24];
  time_t n = time(nullptr); struct tm t; gmtime_r(&n, &t);
  strftime(b, sizeof(b), "%d-%m-%Y %H:%M", &t);
  return String(b);
}
void logEvent(const String &e) {
  for (int i = 11; i > 0; i--) events[i] = events[i - 1];
  events[0] = stamp() + "  " + e;
  if (evCount < 12) evCount++;
  Serial.println(events[0]);
}

// ---------------- MOTORS ----------------
void motor(int l, int r) {  // -255..255
  digitalWrite(IN1, l > 0); digitalWrite(IN2, l < 0);
  digitalWrite(IN3, r > 0); digitalWrite(IN4, r < 0);
  pwmWrite(ENA, 8, abs(l));
  pwmWrite(ENB, 9, abs(r));
}

// ---------------- SENSORS ----------------
float getDistance() {
  if (digitalRead(PIN_ECHO) == HIGH) return 999;   // echo atka hua = sensor problem, "khula" maano
  digitalWrite(PIN_TRIG, LOW); delayMicroseconds(2);
  digitalWrite(PIN_TRIG, HIGH); delayMicroseconds(10);
  digitalWrite(PIN_TRIG, LOW);
  long d = pulseIn(PIN_ECHO, HIGH, 25000);
  if (d == 0) return 999;
  return d * 0.0343 / 2.0;
}

void readSensors() {
  if (millis() - lastSensor > 150) { lastSensor = millis(); distCm = getDistance(); }
  if (millis() - lastGas > 200) {
    lastGas = millis();
    long s = 0;
    for (int i = 0; i < 8; i++) s += analogRead(PIN_MQ2);
    gasVal = s / 8;
  }
  if (millis() - lastDht > 3000) {
    lastDht = millis();
    float t = dht.readTemperature(), h = dht.readHumidity();   // fail ho to purani value rehti hai
    if (!isnan(t)) tempC = t;
    if (!isnan(h)) hum = h;
  }
  flags = 0;
  if (digitalRead(PIN_FIRE) == FIRE_LEVEL) flags |= 1;
  if (millis() > GAS_WARMUP_MS && gasVal > GAS_ALERT) flags |= 2;
  if (tempC > TEMP_ALERT) flags |= 4;
  if (distCm >= 2 && distCm < NEAR_CM) flags |= 8;
}

// ---------------- ALERT SYSTEM ----------------
void computeAlert() {
  static int prevLevel = 0;
  if (sosActive)        { alertLevel = 3; alertText = "SOS EMERGENCY";          alertShort = "SOS"; }
  else if (flags & 1)   { alertLevel = 2; alertText = "FIRE ALERT";             alertShort = "FIRE"; }
  else if (flags & 2)   { alertLevel = 2; alertText = "GAS / SMOKE ALERT";      alertShort = "GAS"; }
  else if (flags & 4)   { alertLevel = 1; alertText = "HIGH TEMPERATURE";       alertShort = "HOT"; }
  else if (flags & 8)   { alertLevel = 1; alertText = "OBJECT / INTRUDER NEAR"; alertShort = "NEAR"; }
  else                  { alertLevel = 0; alertText = "ALL CLEAR";              alertShort = "OK"; }
  if (alertLevel == 0 || alertLevel > prevLevel) muted = false;   // naya/bada alert aaye to mute hat jaye
  prevLevel = alertLevel;
}

void alarmTick() {
  bool on = false;
  if (millis() < hornUntil) on = true;
  else if (!muted) {
    if (alertLevel >= 2) on = ((millis() / 250) % 2) != 0;      // siren
    else if (alertLevel == 1) on = (millis() % 2000) < 100;     // chhota beep
  }
  digitalWrite(PIN_BUZZER, on);
  digitalWrite(PIN_LED, alertLevel >= 2 ? (((millis() / 250) % 2) != 0) : on);
}

// ---------------- DISPATCH (Police / Fire / Ambulance / Local) ----------------
// Professional incident report format (multi-line).
String buildMsg(const String &reason, const char *prio) {
  String modeTxt = autoMode ? (patrolRun ? "AUTO PATROL" : "AUTO (idle)") : "MANUAL";
  String obj = (distCm >= 400) ? String("None in range") : (String((int)distCm) + " cm");
  bool isTest = (String(prio) == "TEST");
  String m = "SECURITY ALERT NOTIFICATION\n";
  m += "Incident: " + reason + "\n";
  m += "Priority: " + String(prio) + "\n";
  m += "Location: " + String(LOCATION_TEXT) + "\n";
  m += "Robot ID: " + myRid + "\n";
  m += "Time: " + stampFull() + "\n";
  m += "Robot Mode: " + modeTxt + "\n";
  m += "Sensor Readings: Flame=" + String((flags & 1) ? "DETECTED" : "Clear") +
       ", Gas=" + String(gasVal) + " ADC" +
       ", Temp=" + String((int)tempC) + " C" +
       ", Humidity=" + String((int)hum) + " %" +
       ", Nearest object=" + obj + "\n";
  m += isTest ? "Action: This is a test message. No action required."
              : "Action: Immediate response requested. Please verify and respond.";
  return m;
}

void dispatch(const String &reason, uint8_t mask, const char *prio) {
  String msg = buildMsg(reason, prio);
  lastMsg = msg;
  Serial.println(msg);
  logEvent("DISPATCH: " + reason);
  for (int i = 0; i < 4; i++) {
    if (!(mask & (1 << i))) continue;
    String st = "NOT SENT - local demo only";
    svcs[i].st = st;
    svcs[i].when = stamp();
    logEvent(String(svcs[i].name) + ": " + st);
  }
}

void runPending() {
  if (pendSos) {
    pendSos = false;
    if (!sosActive || millis() - lastSosDisp > 15000) {
      sosActive = true; muted = false; lastSosDisp = millis();
      logEvent("SOS TRIGGERED");
      dispatch("SOS EMERGENCY - assistance required", 15, "CRITICAL");   // Police + Fire + Ambulance + Local
    }
  }
  if (pendSosOff) {
    pendSosOff = false;
    if (sosActive) { sosActive = false; logEvent("SOS cancelled"); }
  }
  if (pendTest) {
    pendTest = false;
    lastMsg = buildMsg("TEST ALERT", "TEST");
    for (int i = 0; i < 4; i++) { svcs[i].st = "TEST ONLY - not sent"; svcs[i].when = stamp(); }
    logEvent("TEST alert (nothing sent)");
    hornUntil = millis() + 600;
  }
}

void autoTick() {
  static uint8_t prev = 0;
  uint8_t rise = flags & ~prev;
  prev = flags;
  if (!AUTO_DISPATCH) return;
  if ((rise & 1) && (lastFireDisp == 0 || millis() - lastFireDisp > COOLDOWN_MS)) {
    lastFireDisp = millis();
    dispatch("FIRE DETECTED", 2 | 8, "CRITICAL");     // Fire Brigade + Local
  }
  if ((rise & 2) && (lastGasDisp == 0 || millis() - lastGasDisp > COOLDOWN_MS)) {
    lastGasDisp = millis();
    dispatch("GAS / SMOKE DETECTED", 2 | 8, "HIGH");  // Fire Brigade + Local
  }
}

// ---------------- ROUTE / PATROL ----------------
// Route text: "F3000,R700,S1000" -> direction letter + milliseconds. Valid ho to route me lagta hai.
bool parseRoute(String s, bool apply) {
  s.trim(); s.toUpperCase();
  Step tmp[MAX_STEPS];
  int n = 0, i = 0, len = s.length();
  while (i < len) {
    while (i < len && (s[i] == ',' || s[i] == ' ')) i++;
    if (i >= len) break;
    char d = s[i];
    if (d != 'F' && d != 'B' && d != 'L' && d != 'R' && d != 'S') return false;
    i++;
    long ms = 0; bool dig = false;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
      ms = ms * 10 + (s[i] - '0'); i++; dig = true;
      if (ms > 60000) return false;
    }
    if (!dig || ms < 100) return false;
    if (n >= MAX_STEPS) return false;
    tmp[n].d = d; tmp[n].ms = (uint16_t)ms; n++;
  }
  if (n == 0) return false;
  if (apply) {
    for (int k = 0; k < n; k++) route[k] = tmp[k];
    routeLen = n;
    routeStr = s;
    stepIdx = 0; stepElapsed = 0;
  }
  return true;
}

void saveSettings() {
  prefs.putString("route", routeStr);
  prefs.putInt("asp", autoSpeed);
  prefs.putBool("loop", routeLoop);
}

void setManualMode() {
  autoMode = false; patrolRun = false;
  manL = manR = 0; autoL = autoR = 0;
  logEvent("Mode: MANUAL");
}

void setAutoMode() {
  manL = manR = 0;
  autoMode = true; patrolRun = false;
  logEvent("Mode: AUTO (Start Patrol dabao)");
}

void startPatrol() {
  stepIdx = 0; stepElapsed = 0; laps = 0;
  patrolRun = true;
  logEvent("Patrol START (" + String(routeLen) + " steps)");
}

void stopPatrol() {
  if (patrolRun) logEvent("Patrol STOP");
  patrolRun = false; autoL = autoR = 0;
}

void patrolTick() {
  static unsigned long last = 0;
  unsigned long now = millis();
  unsigned long dt = now - last; last = now;
  if (dt > 500) dt = 500;
  autoL = autoR = 0; holdReason = "";
  if (!autoMode || !patrolRun || routeLen == 0) return;
  if (estop)           { holdReason = "E-STOP"; return; }
  if (alertLevel >= 2) { holdReason = "ALERT";  return; }       // fire / gas / SOS pe patrol hold
  Step s = route[stepIdx];
  if (s.d == 'F' && distCm < STOP_CM) { holdReason = "OBSTACLE"; return; }
  int sp = autoSpeed;
  if (s.d == 'F')      { autoL = sp;  autoR = sp; }
  else if (s.d == 'B') { autoL = -sp; autoR = -sp; }
  else if (s.d == 'L') { autoL = -sp; autoR = sp; }
  else if (s.d == 'R') { autoL = sp;  autoR = -sp; }
  stepElapsed += dt;
  if (stepElapsed >= s.ms) {
    stepElapsed = 0; stepIdx++;
    if (stepIdx >= routeLen) {
      laps++;
      if (routeLoop) stepIdx = 0;
      else { patrolRun = false; autoL = autoR = 0; logEvent("Patrol complete"); }
    }
  }
}

// ---------------- ESP-NOW (Robot 1 se jodna) ----------------
bool parseMac(const char *s, uint8_t *m) {
  unsigned v[6];
  if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; i++) m[i] = (uint8_t)v[i];
  return true;
}

void handleRecv(const uint8_t *mac, const uint8_t *d, int len) {
  if (memcmp(mac, dashMac, 6) != 0) return;     // sirf Robot 1 ki baat suno
  if (len < 4) return;
  lastFleetRx = millis();
  uint32_t mg; memcpy(&mg, d, 4);
  if (mg == SEC_MAGIC_C && len == (int)sizeof(SecCmd)) {
    SecCmd c; memcpy(&c, d, sizeof(c));
    if (c.type == 4) { estop = false; return; }                 // E-STOP clear
    if (c.type == 3) { hornUntil = millis() + 250; return; }    // horn
    if (c.type == 5) { pendSos = true; return; }                // SOS
    if (c.type == 6) { pendSosOff = true; return; }             // SOS cancel
    if (c.type == 7) { autoMode = true; manL = manR = 0; stepIdx = 0; stepElapsed = 0; patrolRun = true; return; }  // AUTO + patrol
    if (c.type == 8) { autoMode = false; patrolRun = false; manL = manR = 0; return; }                              // MANUAL
    if (c.type == 1) {                                          // drive
      if (estop || autoMode) return;                            // AUTO me manual drive band
      char dch = (char)c.a;
      int sp = constrain((int)c.b, 80, 255), l = 0, r = 0;
      if (dch == 'F') { l = sp; r = sp; }
      else if (dch == 'B') { l = -sp; r = -sp; }
      else if (dch == 'L') { l = -sp; r = sp; }
      else if (dch == 'R') { l = sp; r = -sp; }
      manL = l; manR = r; lastDrive = millis();
    }
    return;
  }
  if (len == (int)sizeof(HB)) {
    HB h; memcpy(&h, d, sizeof(h));
    if (h.magic == HB_MAGIC && h.cmd == 1) { estop = true; manL = manR = 0; }   // Robot 1 se E-STOP
  }
}
#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t *info, const uint8_t *d, int len) { handleRecv(info->src_addr, d, len); }
#else
void onRecv(const uint8_t *mac, const uint8_t *d, int len) { handleRecv(mac, d, len); }
#endif

void fleetInit(bool haveDash) {
  if (esp_now_init() != ESP_OK) return;
  esp_now_register_recv_cb(onRecv);
  if (!haveDash) return;
  esp_now_peer_info_t pi; memset(&pi, 0, sizeof(pi));
  memcpy(pi.peer_addr, dashMac, 6);
  pi.channel = 0; pi.ifidx = WIFI_IF_STA; pi.encrypt = false;
  fleetOk = (esp_now_add_peer(&pi) == ESP_OK);
}

void fleetTick() {
  if (!fleetOk) return;
  if (millis() - lastTel > 500) {
    lastTel = millis();
    SecTelem t; memset(&t, 0, sizeof(t));
    t.magic = SEC_MAGIC_T;
    t.dist = (int16_t)min(distCm, 999.0f);
    t.temp = (int8_t)constrain((int)tempC, -50, 120);
    t.hum = (uint8_t)constrain((int)hum, 0, 100);
    t.gas = (uint16_t)gasVal;
    t.servo = (uint8_t)servoTarget;
    t.flags = flags | (sosActive ? 16 : 0);    // bit4 = SOS active
    esp_now_send(dashMac, (uint8_t *)&t, sizeof(t));
  }
  if (millis() - lastHb > 1000) {
    lastHb = millis();
    HB h; memset(&h, 0, sizeof(h));
    h.magic = HB_MAGIC;
    myRid.toCharArray(h.rid, 8);
    state.toCharArray(h.st, 12);
    h.pct = 60;
    h.cmd = 0;
    esp_now_send(dashMac, (uint8_t *)&h, sizeof(h));
  }
}

// ---------------- DRIVE ----------------
void driveTick() {
  int l, r;
  bool blocked = false;
  if (autoMode) { l = autoL; r = autoR; }                              // AUTO: patrol route se
  else {
    l = manL; r = manR;
    if (millis() - lastDrive > 400) { l = 0; r = 0; }                  // dead-man (sirf manual)
  }
  if (estop) { l = 0; r = 0; }
  if (l > 0 && r > 0 && distCm < STOP_CM) { l = r = 0; blocked = true; }
  motor(l, r);
  if (estop) state = "ESTOP";
  else if (l || r) state = autoMode ? "PATROL" : "DRIVING";
  else if (blocked) state = "BLOCKED";
  else if (sosActive) state = "SOS";
  else if (alertLevel >= 1) state = "ALERT";
  else if (autoMode) state = patrolRun ? "PATROL" : "AUTO";
  else state = "READY";
}

void backgroundTasks() {
  server.handleClient();
  readSensors();
  computeAlert();
  patrolTick();
  driveTick();
  alarmTick();
  fleetTick();
}

// ---------------- OLED ----------------
void updateOled() {
  if (!oledOk) return;
  oled.clearDisplay();
  oled.setTextColor(WHITE);
  if (alertLevel >= 2) {                    // bada alert screen
    oled.setTextSize(3); oled.setCursor(0, 0);
    oled.println(alertShort);
    oled.setTextSize(1);
    oled.println(alertLevel == 3 ? "SOS sent / sending..." : "ALERT!");
    oled.println("Gas:" + String(gasVal) + " T:" + String((int)tempC) + "C");
    oled.println(String(LOCATION_TEXT));
    oled.display();
    return;
  }
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.println("SECURITY ROBOT " + state);
  oled.println("AP: " + String(AP_SSID));
  oled.println("Dist: " + String((int)distCm) + " cm");
  oled.println("T:" + String((int)tempC) + "C H:" + String((int)hum) + "%");
  oled.println("Gas: " + String(gasVal));
  oled.println(String("Fire: ") + ((flags & 1) ? "YES!" : "No"));
  oled.println(alertLevel == 1 ? alertText : String("Status: OK"));
  if (autoMode) oled.println("Mode: AUTO " + (patrolRun ? String(stepIdx + 1) + "/" + String(routeLen) : String("idle")));
  else oled.println("Mode: MANUAL");
  oled.display();
}

// ---------------- WEB DASHBOARD ----------------
const char PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>SECURITY ROBOT</title><style>
:root{--bg:#050f1d;--bg2:#081a30;--card:#0c2340;--line:#1b5fa3;--acc:#2fb4ff;--ok:#2ecc71;--warn:#ffb020;--bad:#ff4d4f;--tx:#e8f4ff;--mu:#86a8c7}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#0d2f57 0,var(--bg) 60%) fixed;color:var(--tx);font-family:system-ui,Segoe UI,Arial,sans-serif;min-height:100vh}
header{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:10px;padding:10px 14px;background:rgba(5,15,29,.93);border-bottom:1px solid var(--line)}
.brand{font-weight:900;font-size:19px;letter-spacing:1px}.brand span{color:var(--acc)}
.pill{padding:4px 12px;border-radius:99px;font-size:12px;font-weight:700;background:#16406e}
.pill.bad{background:#a32226}.pill.ok{background:#146c43}.pill.run{background:#8a5a00}
.sp{flex:1}
main{padding:12px;max-width:1100px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
.card{background:linear-gradient(180deg,var(--card),var(--bg2));border:1px solid var(--line);border-radius:14px;padding:12px}
.card h3{margin:0 0 10px;font-size:12px;letter-spacing:.9px;text-transform:uppercase;color:var(--acc)}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 0;font-size:14px;border-bottom:1px solid #123a63}.row:last-child{border:0}
.row small{color:var(--mu);font-size:11px;display:block}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:10px}
.tile{background:#071a31;border:1px solid #14416f;border-radius:10px;padding:8px;text-align:center}.tile b{display:block;font-size:17px}.tile small{color:var(--mu);font-size:11px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.wn{color:var(--warn)}
.sb{padding:14px;border-radius:12px;text-align:center;font-weight:800;font-size:18px;background:#146c43}
.sb.w{background:#8a5a00}.sb.e{background:#a32226;animation:bl 1s infinite}.sb.o{background:#3a4a5c}
@keyframes bl{50%{opacity:.55}}
label{font-size:12px;color:var(--mu)}
input[type=range]{width:100%;padding:0;height:28px;accent-color:var(--acc);margin:3px 0 10px}
input[type=text]{width:100%;padding:10px;border-radius:8px;border:1px solid var(--line);background:#071a31;color:var(--tx);font-size:14px;margin:4px 0 8px}
button{padding:11px 15px;border:0;border-radius:10px;font-weight:700;font-size:14px;cursor:pointer;margin:3px 2px;color:#fff}
.g{background:#19b56f;color:#032}.r{background:#d63c40}.b{background:#2272d6}.y{background:#c98a00}
.btns{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
.sos{width:100%;padding:22px;font-size:26px;letter-spacing:3px;background:#e0262b;border:3px solid #ffb3b5;border-radius:16px;box-shadow:0 0 18px rgba(224,38,43,.6)}
.dpad{display:grid;grid-template-columns:repeat(3,74px);grid-template-rows:repeat(3,74px);gap:8px;justify-content:center;margin:6px 0 12px;touch-action:none;user-select:none;-webkit-user-select:none}
.pad{margin:0;font-size:26px;border-radius:16px;background:#12365f;border:1px solid var(--line);touch-action:none;user-select:none}
.pad.hold{background:var(--acc);color:#02101f}.pad.stop{background:#8a1f23}
.dim{opacity:.4}
.ev{font-size:12px;color:var(--mu);padding:4px 0;border-bottom:1px solid #123a63;word-break:break-word}
.msg{font-size:12px;background:#071a31;border:1px solid #14416f;border-radius:8px;padding:8px;color:#cfe6ff;word-break:break-word;margin-top:8px;white-space:pre-line}
#toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);background:#12365f;border:1px solid var(--acc);padding:10px 16px;border-radius:99px;font-size:13px;opacity:0;pointer-events:none;transition:.25s;z-index:50;max-width:90%}
#toast.on{opacity:1;transform:translateX(-50%)}
</style></head><body>
<header><div class=brand>SECURITY<span>BOT</span></div><div id=pill class=pill>-</div><div class=sp></div><span id=lk class=pill>-</span></header>
<main><div class=grid>

 <div class=card><h3>Security Status</h3>
  <div id=ban class="sb o">-</div>
  <div class=tiles>
   <div class=tile><b id=ds>-</b><small>Distance</small></div>
   <div class=tile><b id=th>-</b><small>Temp / Hum</small></div>
   <div class=tile><b id=gs>-</b><small>Gas (MQ2)</small></div>
   <div class=tile><b id=fr>-</b><small>Fire</small></div>
   <div class=tile><b id=fl>-</b><small>Fleet Link</small></div>
   <div class=tile><b id=st>-</b><small>State</small></div></div>
  <div class=btns><button class=y onclick=mute()>&#128263; Siren Mute / Unmute</button><button class=b onclick="call('/test','Test alert (kuch bheja nahi)')">Test Alert</button></div></div>

 <div class=card><h3>Emergency SOS</h3>
  <button class=sos onclick=sos()>SOS</button>
  <div class=btns><button class=g onclick="call('/sosoff','SOS cancel')">Cancel SOS</button></div>
  <p style="font-size:12px;color:var(--mu);margin:8px 0 0">SOS dabte hi local siren + OLED + dashboard event + Robot 1 ko ESP-NOW alert (agar configured ho). SMS nahi bheja jata.</p></div>

 <div class=card><h3>Message Dispatch</h3>
  <div id=dp></div>
  <div class=msg id=lm>-</div>
  <div class=row style="margin-top:6px"><span>Dispatch</span><b id=gm>LOCAL DEMO ONLY</b></div></div>

 <div class=card><h3>Drive Mode &amp; Patrol Route</h3>
  <div class=row><span>Current Mode</span><b id=md>-</b></div>
  <div class=btns><button class=b id=bM onclick="setMode('M')">MANUAL</button><button class=g id=bA onclick="setMode('A')">AUTO PATROL</button></div>
  <label>Fixed route &mdash; F=aage B=peeche L=left R=right S=ruko (number = ms). Jaise: F3000,R700,F3000,R700</label>
  <input id=rt type=text maxlength=200 placeholder="F3000,R700,F3000,R700" autocomplete=off autocapitalize=characters>
  <div class=btns><button class=y onclick=saveRoute()>Save Route</button></div>
  <label>Patrol speed: <b id=apv>150</b></label><input id=asp type=range min=80 max=255 value=150 oninput="$('apv').innerText=this.value">
  <label><input type=checkbox id=lp checked> Loop (route baar baar chale)</label>
  <div class=btns><button class=g onclick=pstart()>&#9654; Start Patrol</button><button class=r onclick=pstop()>&#9632; Stop Patrol</button></div>
  <div class=row style="margin-top:8px"><span>Patrol</span><b id=pst>-</b></div>
  <p style="font-size:12px;color:var(--mu);margin:8px 0 0">AUTO me manual drive band rehti hai. Obstacle (&lt;15cm) pe aage ruk jata hai; fire / gas / SOS pe patrol hold ho jati hai. E-STOP hamesha kaam karta hai.</p></div>

 <div class=card id=mc><h3>Manual Control</h3>
  <div class=dpad>
   <span></span><button class=pad id=bF>&#9650;</button><span></span>
   <button class=pad id=bL>&#9664;</button><button class="pad stop" id=bS>&#9632;</button><button class=pad id=bR>&#9654;</button>
   <span></span><button class=pad id=bB>&#9660;</button><span></span></div>
  <label>Speed: <b id=spv>170</b></label><input id=spd type=range min=80 max=255 value=170 oninput="$('spv').innerText=this.value">
  <div class=btns><button class=g onclick="call('/horn','Horn')">&#128227; Horn</button><button class=r onclick=estop()>E-STOP</button><button class=b onclick="call('/clear','E-STOP clear')">Clear E-STOP</button></div>
  <p style="font-size:12px;color:var(--mu);margin:8px 0 0">Laptop: W A S D / arrow keys, Space = stop. Button chhodte hi robot ruk jata hai. Aage obstacle (&lt;15cm) pe forward block.</p></div>

 <div class=card><h3>Recent Events</h3><div id=ev></div></div>

 <div class=card><h3>Robot Info</h3>
  <div class=row><span>Wi-Fi AP</span><b id=ssid>-</b></div>
  <div class=row><span>Dashboard IP</span><b>192.168.4.1</b></div>
  <div class=row><span>Robot ID</span><b id=rid>-</b></div>
  <div class=row><span>MAC Address</span><b id=mac>-</b></div>
  <div class=row><span>Demo location label (not GPS)</span><b id=loc>-</b></div>
  <div class=row><span>Time sync</span><b id=ts>-</b></div></div>
</div></main><div id=toast></div>
<script>
const $=id=>document.getElementById(id);
let dir='S',drv=null,lastAlertLevel=-1,curMode='M',rtInit=false;
function toast(m){const t=$('toast');t.innerText=m;t.classList.add('on');clearTimeout(toast.t);toast.t=setTimeout(()=>t.classList.remove('on'),2300)}
async function call(u,ok){try{const t=(await(await fetch(u)).text()).trim();toast(t=='OK'?(ok||'Done'):t);return t}catch(e){toast('Robot se connection nahi');return 'ERR'}}
function sos(){if(confirm('Local SOS alert activate karna hai? Robot 1 ko alert sirf ESP-NOW link configured hone par milega. SMS nahi bheja jayega.'))call('/sos','Local SOS activated')}
function mute(){call('/mute','Siren mute/unmute')}
function estop(){release();call('/stop','E-STOP')}
function setMode(m){call('/mode?m='+m,m=='A'?'AUTO mode ON':'MANUAL mode ON')}
function saveRoute(){call('/route?set='+encodeURIComponent($('rt').value.trim()),'Route saved')}
function pstart(){call('/patrol?a=1&sp='+$('asp').value+'&loop='+($('lp').checked?1:0),'Patrol started')}
function pstop(){call('/patrol?a=0','Patrol stopped')}
const P={F:'bF',B:'bB',L:'bL',R:'bR'};
function mark(d,on){if(P[d])$(P[d]).classList.toggle('hold',on)}
function sendD(){fetch('/drive?d='+dir+'&sp='+$('spd').value).catch(()=>{})}
function press(d){if(curMode=='A'){toast('AUTO mode me manual band hai - MANUAL chuno');return}if(dir!='S')mark(dir,false);dir=d;mark(d,true);sendD();clearInterval(drv);drv=setInterval(sendD,150)}
function release(){clearInterval(drv);if(dir!='S'){mark(dir,false);dir='S';fetch('/drive?d=S').catch(()=>{})}}
Object.keys(P).forEach(d=>{const e=$(P[d]);e.addEventListener('pointerdown',ev=>{ev.preventDefault();press(d)});['pointerup','pointerleave','pointercancel'].forEach(n=>e.addEventListener(n,release));e.addEventListener('contextmenu',ev=>ev.preventDefault())});
$('bS').addEventListener('pointerdown',ev=>{ev.preventDefault();release();fetch('/drive?d=S').catch(()=>{})});
const KM={w:'F',ArrowUp:'F',s:'B',ArrowDown:'B',a:'L',ArrowLeft:'L',d:'R',ArrowRight:'R'};
addEventListener('keydown',e=>{if(e.repeat||/INPUT|SELECT|TEXTAREA/.test(e.target.tagName))return;const d=KM[e.key];if(d){e.preventDefault();press(d)}else if(e.key==' '){e.preventDefault();release()}});
addEventListener('keyup',e=>{if(KM[e.key])release()});
addEventListener('blur',release);
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
async function u(){try{const j=await(await fetch('/status')).json();
 $('pill').innerText=j.state;$('pill').className='pill '+(j.level>=2?'bad':j.level==1?'run':'ok');
 if(lastAlertLevel>=0 && j.level>lastAlertLevel){toast('SECURITY ALERT: '+j.atext);if(navigator.vibrate)navigator.vibrate([250,120,250]);}
 lastAlertLevel=j.level;
 $('lk').innerText=j.link?'Robot 1: linked':'Robot 1: -';$('lk').className='pill '+(j.link?'ok':'');
 const b=$('ban');b.className='sb '+(j.level>=2?'e':j.level==1?'w':'');b.innerText=(j.level==0?'\u2714 ':'\u26A0 ')+j.atext+(j.muted?' (siren muted)':'');
 $('ds').innerText=j.dist+' cm';$('th').innerText=j.temp+'\u00B0 / '+j.hum+'%';$('gs').innerText=j.gas;
 $('fr').innerText=j.fire?'FIRE!':'Safe';$('fr').className=j.fire?'bad':'ok';
 $('fl').innerText=j.link?'LINKED':'LOCAL';$('st').innerText=j.state;
 $('dp').innerHTML=j.disp.map(x=>'<div class=row><span>'+esc(x.n)+'</span><b class="'+(x.st.indexOf('SENT')==0?'ok':x.st.indexOf('FAILED')>=0?'bad':'')+'">'+esc(x.st)+'<small>'+esc(x.w)+'</small></b></div>').join('');
 $('lm').innerText=(j.msg=='-')?'No message yet':j.msg;
 $('gm').innerText='LOCAL DEMO ONLY \u2014 NO SMS';$('gm').className='wn';
 curMode=j.mode=='AUTO'?'A':'M';
 $('md').innerText=j.mode+(j.mode=='AUTO'?(j.patrol?' (patrolling)':' (idle)'):'');$('md').className=curMode=='A'?'ok':'';
 $('bA').classList.toggle('dim',curMode!='A');$('bM').classList.toggle('dim',curMode=='A');$('mc').classList.toggle('dim',curMode=='A');
 $('pst').innerText=j.patrol?('RUNNING '+j.step+'/'+j.steps+' | lap '+j.laps+(j.hold?' | HOLD: '+j.hold:'')):'STOPPED';
 $('pst').className=j.patrol?(j.hold?'wn':'ok'):'';
 if(!rtInit){$('rt').value=j.route;$('asp').value=j.asp;$('apv').innerText=j.asp;$('lp').checked=j.loop;rtInit=true}
 $('ev').innerHTML=j.events.map(e=>'<div class=ev>'+esc(e)+'</div>').join('');
 $('ssid').innerText=j.ssid;$('rid').innerText=j.rid;$('mac').innerText=j.mac;$('loc').innerText=j.loc;$('ts').innerText=j.timeset?'OK':'Nahi (uptime)';
}catch(e){$('pill').innerText='OFFLINE';$('pill').className='pill bad'}}
fetch('/settime?ts='+Math.floor(Date.now()/1000-new Date().getTimezoneOffset()*60));
setInterval(u,1000);u();
</script></body></html>
)rawliteral";

String jesc(String s) { s.replace("\\", "/"); s.replace("\"", "'"); s.replace("\t", " "); s.replace("\n", " "); return s; }
// multi-line message ke liye: new line ko \n (JSON escape) me badalta hai
String jmsg(String s) { s.replace("\\", "/"); s.replace("\"", "'"); s.replace("\t", " "); s.replace("\r", ""); s.replace("\n", "\\n"); return s; }

void setupRoutes() {
  server.on("/", []() { server.send_P(200, "text/html", PAGE); });

  server.on("/status", []() {
    bool link = fleetOk && (millis() - lastFleetRx < 3000);
    String j = "{\"state\":\"" + state + "\",\"level\":" + String(alertLevel) +
               ",\"atext\":\"" + alertText + "\",\"muted\":" + (muted ? "true" : "false") +
               ",\"sos\":" + (sosActive ? "true" : "false") +
               ",\"dist\":" + String((int)distCm) + ",\"temp\":" + String((int)tempC) +
               ",\"hum\":" + String((int)hum) + ",\"gas\":" + String(gasVal) +
               ",\"fire\":" + ((flags & 1) ? "true" : "false") + ",\"servo\":" + String(servoTarget) +
               ",\"link\":" + (link ? "true" : "false") +
               ",\"mode\":\"" + String(autoMode ? "AUTO" : "MANUAL") + "\"" +
               ",\"patrol\":" + (patrolRun ? "true" : "false") +
               ",\"step\":" + String(stepIdx + 1) + ",\"steps\":" + String(routeLen) +
               ",\"laps\":" + String(laps) + ",\"loop\":" + (routeLoop ? "true" : "false") +
               ",\"asp\":" + String(autoSpeed) + ",\"hold\":\"" + holdReason + "\"" +
               ",\"route\":\"" + jesc(routeStr) + "\"" +
               ",\"ssid\":\"" + String(AP_SSID) + "\",\"rid\":\"" + myRid + "\",\"mac\":\"" + myMac +
               "\",\"loc\":\"" + jesc(String(LOCATION_TEXT)) + "\",\"timeset\":" + (timeIsSet() ? "true" : "false") +
               ",\"msg\":\"" + jmsg(lastMsg) + "\",\"disp\":[";
    for (int i = 0; i < 4; i++) {
      if (i) j += ",";
      j += "{\"n\":\"" + String(svcs[i].name) +
           "\",\"st\":\"" + jesc(svcs[i].st) + "\",\"w\":\"" + jesc(svcs[i].when) + "\"}";
    }
    j += "],\"events\":[";
    for (int i = 0; i < evCount; i++) {
      if (i) j += ",";
      j += "\"" + jesc(events[i]) + "\"";
    }
    j += "]}";
    server.send(200, "application/json", j);
  });

  server.on("/drive", []() {
    if (autoMode) { manL = manR = 0; server.send(200, "text/plain", "AUTO mode - pehle MANUAL chuno"); return; }
    if (estop) { manL = manR = 0; server.send(200, "text/plain", "E-STOP active - Clear E-STOP dabao"); return; }
    String d = server.arg("d");
    int sp = server.hasArg("sp") ? constrain(server.arg("sp").toInt(), 80, 255) : 170;
    int l = 0, r = 0;
    if (d == "F") { l = sp; r = sp; }
    else if (d == "B") { l = -sp; r = -sp; }
    else if (d == "L") { l = -sp; r = sp; }
    else if (d == "R") { l = sp; r = -sp; }
    manL = l; manR = r; lastDrive = millis();
    server.send(200, "text/plain", "OK");
  });

  // ---- Mode / route / patrol ----
  server.on("/mode", []() {
    String m = server.arg("m");
    if (m == "A") setAutoMode();
    else if (m == "M") setManualMode();
    else { server.send(200, "text/plain", "Galat mode"); return; }
    server.send(200, "text/plain", "OK");
  });
  server.on("/route", []() {
    String s = server.arg("set");
    if (!parseRoute(s, true)) {
      server.send(200, "text/plain", "Route galat! Format: F3000,R700 (F/B/L/R/S + ms, max " + String(MAX_STEPS) + " steps)");
      return;
    }
    patrolRun = false; autoL = autoR = 0;      // naya route -> patrol rok do
    saveSettings();
    logEvent("Route saved: " + routeStr);
    server.send(200, "text/plain", "OK");
  });
  server.on("/patrol", []() {
    if (server.arg("a") == "1") {
      if (!autoMode) { server.send(200, "text/plain", "Pehle AUTO PATROL mode chuno"); return; }
      if (routeLen == 0) { server.send(200, "text/plain", "Pehle route save karo"); return; }
      if (server.hasArg("sp")) autoSpeed = constrain(server.arg("sp").toInt(), 80, 255);
      if (server.hasArg("loop")) routeLoop = (server.arg("loop") == "1");
      saveSettings();
      startPatrol();
    } else {
      stopPatrol();
    }
    server.send(200, "text/plain", "OK");
  });

  server.on("/horn", []() { hornUntil = millis() + 250; server.send(200, "text/plain", "OK"); });
  server.on("/stop", []() {
    estop = true; manL = manR = 0;
    logEvent("E-STOP");
    server.send(200, "text/plain", "OK");
  });
  server.on("/clear", []() {
    estop = false;
    logEvent("E-STOP cleared");
    server.send(200, "text/plain", "OK");
  });
  server.on("/sos", []() { pendSos = true; server.send(200, "text/plain", "OK"); });
  server.on("/sosoff", []() { pendSosOff = true; server.send(200, "text/plain", "OK"); });
  server.on("/test", []() { pendTest = true; server.send(200, "text/plain", "OK"); });
  server.on("/mute", []() { muted = !muted; server.send(200, "text/plain", "OK"); });
  server.on("/settime", []() {
    if (server.hasArg("ts") && !timeIsSet()) {
      struct timeval tv; tv.tv_sec = server.arg("ts").toInt(); tv.tv_usec = 0;
      settimeofday(&tv, NULL);
    }
    server.send(200, "text/plain", "OK");
  });
  server.begin();
}

// ---------------- SETUP / LOOP ----------------
void setup() {
  Serial.begin(115200);
  pinMode(IN1, OUTPUT); pinMode(IN2, OUTPUT); pinMode(IN3, OUTPUT); pinMode(IN4, OUTPUT);
  pwmInit(ENA, 8); pwmInit(ENB, 9);
  pinMode(PIN_TRIG, OUTPUT); pinMode(PIN_ECHO, INPUT);
  pinMode(PIN_FIRE, INPUT); pinMode(PIN_MQ2, INPUT);
  pinMode(PIN_BUZZER, OUTPUT); pinMode(PIN_LED, OUTPUT);
  motor(0, 0);

  // saved route / settings load karo (na mile ya kharab ho to default route)
  prefs.begin("secbot", false);
  String saved = prefs.getString("route", DEFAULT_ROUTE);
  if (!parseRoute(saved, true)) parseRoute(DEFAULT_ROUTE, true);
  autoSpeed = constrain(prefs.getInt("asp", DEFAULT_PATROL_SPEED), 80, 255);
  routeLoop = prefs.getBool("loop", true);

  dht.begin();
  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.beginTransmission(0x3C);
  oledOk = (Wire.endTransmission() == 0) && oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);

  WiFi.mode(WIFI_AP_STA);                         // AP = dashboard, STA = ESP-NOW (Robot 1)
  WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL);
  myMac = WiFi.macAddress();
  myRid = "SR-" + myMac.substring(12, 14) + myMac.substring(15, 17);
  bool haveDash = parseMac(DASH_MAC, dashMac) && String(DASH_MAC) != "AA:BB:CC:DD:EE:FF";
  fleetInit(haveDash);
  setupRoutes();

  logEvent("Boot - Security robot ready");
  logEvent(String("Wi-Fi AP: ") + AP_SSID + " 192.168.4.1");
  logEvent("Dispatch mode: local demo only - no SMS");
  logEvent("Mode: MANUAL | Route: " + routeStr);
  Serial.println("SECURITY ROBOT MAC: " + myMac);
  if (!haveDash) Serial.println("DASH_MAC set nahi - Robot 1 se jodna ho to uska MAC daalo.");
  if (oledOk) {
    oled.clearDisplay(); oled.setTextColor(WHITE); oled.setTextSize(1); oled.setCursor(0, 0);
    oled.println("SECURITY ROBOT");
    oled.println("AP: " + String(AP_SSID));
    oled.println("IP: 192.168.4.1");
    oled.println("MAC (Robot 1 me add):");
    oled.println(myMac);
    oled.println(haveDash ? "Robot1 link: set" : "Robot1 link: no");
    oled.display();
    delay(4000);
  }
  digitalWrite(PIN_BUZZER, HIGH); delay(120); digitalWrite(PIN_BUZZER, LOW);
}

void loop() {
  backgroundTasks();
  autoTick();
  runPending();
  if (millis() - lastOled > 600) { lastOled = millis(); updateOled(); }
}
