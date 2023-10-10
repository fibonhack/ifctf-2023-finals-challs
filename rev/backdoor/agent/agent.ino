#include <Adafruit_AHT10.h>

Adafruit_AHT10 aht;

uint8_t radio_pin = D0;
#define START_OF_BIT 500 // us
#define BIT_ONE 4000
#define BIT_ZERO 2000

/*
  Temperature packet:
            t0 -------- t8 -------- t15
  preamble:    10101010    10101010
  packet type: 10011001    10011001
  payload:     xxxxxxxx    xxxxxxxx
               xxxxxxxx    xxxxxxxx
  checksum:    yyyyyyyy    yyyyyyyy


  Humidity packet:
            t0 -------- t8 -------- t15
  preamble:    10101010    10101010
  packet type: 11010010    00101101    
  payload:     xxxxxxxx    xxxxxxxx
               xxxxxxxx    xxxxxxxx
  checksum:    yyyyyyyy    yyyyyyyy


  Secret packet:
            t0 -------- t8 -------- t15
  preamble:    10101010    10101010
  packet type: 11001110    11010110   sk
  payload:     10100110    11010110   ek
               11010110    10000110   ka
  checksum:    00101110    11110110   to
*/


uint8_t packet[10] = {0b01010101, 0b01010101, 0, 0, 0, 0, 0, 0, 0, 0};
uint16_t temperature_id = 0b1001100110011001;
uint16_t humidity_id = 0b1011010001001011;

void computeChecksum(){
  packet[8] = packet[0] ^ packet[2] ^ packet[4] ^ packet[6];
  packet[9] = packet[1] ^ packet[3] ^ packet[5] ^ packet[7];
}

inline void sendBit(uint8_t b){
  if(b){
    // bit 1
    digitalWrite(radio_pin, HIGH);
    delayMicroseconds(START_OF_BIT);
    digitalWrite(radio_pin, LOW);
    delayMicroseconds(BIT_ONE);
  }
  else{
    // bit 0
    digitalWrite(radio_pin, HIGH);
    delayMicroseconds(START_OF_BIT);
    digitalWrite(radio_pin, LOW);
    delayMicroseconds(BIT_ZERO);
  }
}

void sendPacket(){
  computeChecksum();

  for(uint8_t x = 0; x < sizeof(packet); x++){
    uint8_t value = packet[x];
    for(uint8_t y = 0; y < 8; y++){
      sendBit(value & 1);
      value = value >> 1;
    }
  }
  digitalWrite(radio_pin, HIGH);
  delayMicroseconds(START_OF_BIT);
  digitalWrite(radio_pin, LOW);
}

void setup() {
  Serial.begin(115200);
  pinMode(radio_pin, OUTPUT);
  digitalWrite(radio_pin, LOW);

  if (!aht.begin()) {
    Serial.println("Could not find AHT10!");
    while (1) delay(10);
  }

  Serial.println("Starting transmitting!");

  for (int i = 0; i < 10; i++){
    packet[i] = 0b01010101;
  }

}

unsigned long long ziopera = 0;

void loop() {
  sensors_event_t humidity, temp;
  aht.getEvent(&humidity, &temp);// populate temp and humidity objects with fresh data
  Serial.print("Temperature: "); Serial.print(temp.temperature); Serial.println(" degrees C");
  Serial.print("Humidity: "); Serial.print(humidity.relative_humidity); Serial.println("% rH");

  if ((ziopera & 1) == 0) {
    // Temperature
    Serial.println("Sending temperature");
    *((uint16_t*) &packet[2]) = temperature_id;
    *((float*) &packet[4]) = temp.temperature;
  }
  else{
    // Humidity
    Serial.println("Sending humidity");
    *((uint16_t*) &packet[2]) = humidity_id;
    *((float*) &packet[4]) = humidity.relative_humidity;
  }

  sendPacket();
  delay(5000);
  ziopera++;
}