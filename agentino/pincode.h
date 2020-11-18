/* -*- c++ -*- */

// pincode handling, only one pin-code supported now

#define PINCODE_MAX_LENGTH 6
#define RELEASED  0
#define PRESSED   1
#define NONE      2

#define NUM_BUTTONS 4
#define DEBOUNCE_TIME 100
#define PINCODE_ENTER_TIME 5000
#define BUZZER_PIN  12

typedef struct
{
    uint8_t len;
    uint8_t* code;
    unsigned long life_time;
    unsigned long unlock_time;
} pincode_t;

uint8_t pin_pos;
uint8_t pin_input[PINCODE_MAX_LENGTH];
int pin_enter;
unsigned long pin_enter_time;

int button_pin[NUM_BUTTONS] = {2, 3, 4, 5};
int button_state[NUM_BUTTONS];
unsigned long button_time[NUM_BUTTONS];

int read_button(int num)
{
    int value = !digitalRead(button_pin[num]);
    if (!value) {
      if (button_state[num] == PRESSED) {
          button_state[num] = RELEASED;
          return RELEASED;
      }
      button_state[num] = RELEASED;
    }
    else {
        switch(button_state[num]) {
        case PRESSED: 
          break;
        case NONE:
          if ((millis()-button_time[num]) >= DEBOUNCE_TIME) {
              button_state[num] = PRESSED;
              return PRESSED;
          }
          break;
        case RELEASED:
          button_state[num] = NONE;
          button_time[num] = millis();
          break;
        default: break;
        }
    }
    return NONE;
}

void beep(int ms)
{
    digitalWrite(BUZZER_PIN, HIGH);
    delay(ms);
    digitalWrite(BUZZER_PIN, LOW);
    delay(ms);
}


void clear_pincode()
{
    int i;
    for (i = 0; i < PINCODE_MAX_LENGTH; i++)
	pin_input[i] = 0xff;
    pin_pos = 0;
    pin_enter = 0;
}

void check_pincode(pincode_t* pin, uint8_t* locked, int num_pins)
{
    int i;
    int check_pin = 0;
        
    for (i = 0; i < NUM_BUTTONS; i++) {
	switch(read_button(i)) {
	case RELEASED:
	    pin_input[pin_pos++] = i+1;
	    pin_pos %= PINCODE_MAX_LENGTH;
	    check_pin = 1;
	    pin_enter = 1;
	    pin_enter_time = millis();
	    break;
	case PRESSED:
	    beep(100);
	    break;
	default:
	    break;
	}
    }
    if (check_pin) {  // new key entered
	int beeped = 0;
	for (i = 0; i < num_pins; i++) {
	    int j;
	    int code_match=0;
	    int p = (pin_pos-pin[i].len+PINCODE_MAX_LENGTH) %
		PINCODE_MAX_LENGTH;
	    for (j = 0; j < pin[i].len; j++) {
		int k = (p + j) % PINCODE_MAX_LENGTH;
		if (pin[i].code[j] == pin_input[k])
		    code_match++;
	    }
	    if (code_match == pin[i].len) {
		locked[i] = 0;
		pin[i].unlock_time = millis();
		if (!beeped) {
		    beep(100); beep(200); beep(400);
		    beeped = 1;
		}
	    }
	}
    }
    else if (pin_enter) { // check input buffer clear time
        if ((millis() - pin_enter_time) >= PINCODE_ENTER_TIME) {          
            clear_pincode();
        }
    }
    else {
	int beeped = 0;
	for (i = 0; i < num_pins; i++) {
	    if (locked[i] == 0) {
		if ((millis() - pin[i].unlock_time) >= pin[i].life_time) {
		    locked[i] = 1;
		    if (!beeped) {
			beeped = 1;
			beep(400); beep(200); beep(100);
		    }
		}
	    }
	}
    }
}

void pincode_init()
{
    int i;
    
    clear_pincode();

    pinMode(BUZZER_PIN, OUTPUT);
    for(i = 0; i < NUM_BUTTONS; i++) {
	button_state[i] = RELEASED;  
	pinMode(button_pin[i], INPUT_PULLUP);
    }
}
