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

  for (int i = 0; i < 10; i++){
    packet[i] = 0b01010101;
  }
}

void loop() {
  Serial.println("Gonna send backdoor signal");
  packet[2] = 's';
  packet[3] = 'k';
  packet[4] = 'e';
  packet[5] = 'k';
  packet[6] = 'k';
  packet[7] = 'a';
  packet[8] = 't';
  packet[9] = 'o';

  sendPacket();
  delay(5000);
}