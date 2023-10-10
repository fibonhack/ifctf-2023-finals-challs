#include <LiquidCrystal_I2C.h>

uint8_t radio_pin = D3;
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

uint16_t preamble = 0b0101010101010101;
uint16_t temperature_id = 0b1001100110011001;
uint16_t humidity_id = 0b1011010001001011;

bool verify_checksum(uint8_t * packet) {
  return (packet[8] == packet[0] ^ packet[2] ^ packet[4] ^ packet[6]) && (packet[9] == packet[1] ^ packet[3] ^ packet[5] ^ packet[7]);
}


#define BITS_ARRAY_SIZE 200
#define PACKET_SIZE_BIT 80
#define PACKET_SIZE_BYTE 10

volatile uint8_t bits[BITS_ARRAY_SIZE] = {0};
volatile uint8_t bit_position = 0;

volatile uint64_t isr_last_hit = 0;
volatile bool isr_got_new_packet = false;


void ICACHE_RAM_ATTR RF_ISR() {
  uint64_t now = micros();
  uint64_t delta = now - isr_last_hit;

  // Software debounce for interrupt
  if (delta < 100) {
    return;
  }

  if (delta > (BIT_ONE << 1)) {
    bit_position = 0;
  }
  else if (delta > 3300) {
    bits[bit_position++] = 1;
  }
  else {
    bits[bit_position++] = 0;
  }

  if(bit_position == PACKET_SIZE_BIT) {
    isr_got_new_packet = true;
    bit_position = 0;
  }

  isr_last_hit = now;
}

LiquidCrystal_I2C lcd(0x27, 16, 2);

void setup() {
  lcd.init();
  lcd.backlight();

  pinMode(radio_pin, INPUT);
  attachInterrupt(radio_pin, RF_ISR, FALLING);

  lcd.clear();

  Serial.begin(115200);
}

uint64_t i = 0;
uint8_t tip = 1;

void loop() {
  uint8_t packet[PACKET_SIZE_BIT];

  if (isr_got_new_packet) {
    for(uint8_t i = 0; i < PACKET_SIZE_BIT; i++)
      packet[i] = bits[i];
    isr_got_new_packet = false;

    uint8_t decoded_bytes[PACKET_SIZE_BIT >> 3] = { 0 };

    for(uint8_t i = 0; i < PACKET_SIZE_BIT; i++) {
      decoded_bytes[i >> 3] = decoded_bytes[i >> 3] | (packet[i] << (i & 0b111));
    }

    if (verify_checksum(decoded_bytes)) {
      uint16_t maybe_preamble = ((uint16_t*)decoded_bytes)[0];
      uint16_t packet_type = ((uint16_t*)decoded_bytes)[1];
      float measure = ((float*) &(decoded_bytes[4]))[0];

      if(maybe_preamble == preamble){
        if(packet_type == temperature_id) {
          Serial.println("Temperature");
          lcd.clear();
          lcd.setCursor(0, 0);
          lcd.print("Temperature:");
          lcd.setCursor(0, 1);
          lcd.print(measure);
        }
        else if(packet_type == humidity_id) {
          Serial.println("Humidity");
          lcd.clear();
          lcd.setCursor(0, 0);
          lcd.print("Humidity:");
          lcd.setCursor(0, 1);
          lcd.print(measure);
        }
      }
    }

    if(((uint16_t*)decoded_bytes)[0] == preamble && strncmp((char*)(decoded_bytes+2), "skekkato", 8) == 0){
      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("ifctf{_un_chi1o_");
      lcd.setCursor(0, 1);
      lcd.print("di_schiaccia7a_}");
    }

  }
  else {
    delayMicroseconds(100);
  }

}